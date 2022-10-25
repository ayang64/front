package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ayang64/front/commonlog"

	"golang.org/x/crypto/acme/autocert"
)

type Handler struct {
	H http.Handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello!")
	h.H.ServeHTTP(w, r)
}

type Target struct {
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

type Targets []Target

func (t Targets) Index() map[string]*Target {
	rc := map[string]*Target{}
	for i := range t {
		rc[t[i].Domain] = &t[i]
	}
	return rc
}

type Proxy struct {
	mu        *sync.RWMutex // mutex to protect members of Proxy
	HTTPPort  int           // Port to listen for certbot requests
	HTTPSPort int           // port to listen for secure traffic
	Config    string        // Path to configuration file
	Dircache  string
	Targets   Targets            // Unmarshaled configuration file
	Index     map[string]*Target // an index into Targets using domain as the key
}

func (p *Proxy) refresh(ctx context.Context, r io.Reader) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var targets Targets
	if err := json.NewDecoder(r).Decode(&targets); err != nil {
		return err
	}
	// rewrite targets member and re-index
	p.Targets = targets
	p.Index = p.Targets.Index()

	return nil
}

func (p *Proxy) Refresh(ctx context.Context) error {
	// TODO: respect passed in context value
	inf, err := os.Open(p.Config)
	if err != nil {
		return err
	}
	defer inf.Close()
	return p.refresh(ctx, inf)
}

func (p *Proxy) lookupTarget(_ context.Context, name string) (*Target, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	target, found := p.Index[name]
	return target, found
}

func (p *Proxy) LookupTarget(ctx context.Context, name string) (*Target, error) {
	target, exists := p.lookupTarget(ctx, name)
	if !exists {
		// if not found, check if the configuration file has been updated.
		p.Refresh(ctx)
		target, exists = p.lookupTarget(ctx, name)
	}
	if !exists {
		return nil, fmt.Errorf("proxy path for target %q not found", name)
	}
	return target, nil
}

func (p *Proxy) HostPolicy(ctx context.Context, host string) error {
	if _, err := p.LookupTarget(ctx, host); err != nil {
		return fmt.Errorf("HostPolicy() failed for host %q: %w", host, err)
	}
	return nil
}

func (p *Proxy) DialContext(ctx context.Context, _ string, addr string) (net.Conn, error) {
	addr = strings.TrimSuffix(addr, ":80")

	// attempt to find target in cache
	target, err := p.LookupTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", target.Path)
}

func (p Proxy) Run(ctx context.Context) error {
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: p.HostPolicy,
		Cache:      autocert.DirCache("/tmp/dircache"),
	}

	config := tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// should we even bother getting the certificate?
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if _, err := p.LookupTarget(ctx, hello.ServerName); err != nil {
				return nil, fmt.Errorf("could not find proxy target for %q: %w", hello.ServerName, err)
			}

			cert, err := m.GetCertificate(hello)
			if err != nil {
				log.Printf("GetCertificate() failed %v", err)
			}
			return cert, err
		},
	}

	server := http.Server{
		TLSConfig: &config,
		// Handler:   &commonlog.Handler{W: os.Stderr, H: &Handler{}},
		Handler: &commonlog.Handler{
			W: os.Stderr,
			H: &httputil.ReverseProxy{
				Director: func(r *http.Request) {
					r.URL.Scheme = "http"
					r.URL.Host = r.Host
				},
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
						addr = strings.TrimSuffix(addr, ":80")
						nodes := strings.Split(addr, ".")
						addr = strings.Join(nodes[len(nodes)-2:], ".")

						target, err := p.LookupTarget(context.TODO(), addr)
						if err != nil {
							return nil, err
						}

						return net.Dial("unix", target.Path)
					},
				},
			},
		},
	}

	l, err := net.Listen("tcp", ":443")
	if err != nil {
		return err
	}

	cr := http.Server{
		Handler: &commonlog.Handler{W: os.Stderr, H: m.HTTPHandler(nil)},
		Addr:    ":80",
	}

	errCh := make(chan error, 2)

	go func() { errCh <- server.ServeTLS(l, "", "") }()
	go func() { errCh <- cr.ListenAndServe() }()

	for i := 0; i < cap(errCh); i++ {
		if svrerr := <-errCh; err != nil {
			sdCh := make(chan error, 2)

			// give our shutdown go-routines 500ms to complete
			ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()

			go func() { sdCh <- server.Shutdown(ctx) }()
			go func() { sdCh <- cr.Shutdown(ctx) }()
			for i := 0; i < cap(sdCh); i++ {
				if sderr := <-sdCh; err != nil {
					return fmt.Errorf("server failed because %v; could not gracefully shutdown becaue %v", svrerr, sderr)
				}
			}
			return fmt.Errorf("server failed: %v; gracefully shutdown", svrerr)
		}
	}

	return nil
}

func main() {
	httpport := flag.Int("httpport", 80, "http port")
	httpsport := flag.Int("httpsport", 443, "https port")
	config := flag.String("config", "./proxy.json", "configuration file")
	dircache := flag.String("dircache", "./dircache", "location of certificate cache")
	flag.Parse()

	proxy := Proxy{
		HTTPPort:  *httpport,
		HTTPSPort: *httpsport,
		mu:        &sync.RWMutex{},
		Config:    *config,
		Dircache:  *dircache,
		Index:     map[string]*Target{},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer stop()

	if err := proxy.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
