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
	"strings"
	"sync"
	"time"

	"front/httpextra"

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
	mu        *sync.RWMutex      // mutex to protect members of Proxy
	HTTPPort  int                // Port to listen for certbot requests
	HTTPSPort int                // port to listen for secure traffic
	Config    string             // Path to configuration file
	Targets   Targets            // Unmarshaled configuration file
	Index     map[string]*Target // an index into Targets using domain as the key
}

func (dc *Proxy) refresh(ctx context.Context, r io.Reader) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	var targets Targets
	if err := json.NewDecoder(r).Decode(&targets); err != nil {
		return err
	}
	// rewrite targets member and re-index
	dc.Targets = targets
	dc.Index = dc.Targets.Index()

	return nil
}

func (dc *Proxy) Refresh(ctx context.Context) error {
	// TODO: respect passed in context value
	inf, err := os.Open(dc.Config)
	if err != nil {
		return err
	}
	defer inf.Close()
	return dc.refresh(ctx, inf)
}

func (dc *Proxy) lookupTarget(_ context.Context, name string) (*Target, bool) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	target, found := dc.Index[name]
	return target, found
}

func (dc *Proxy) LookupTarget(ctx context.Context, name string) (*Target, error) {
	target, exists := dc.lookupTarget(ctx, name)
	if !exists {
		// if not found, check if the configuration file has been updated.
		dc.Refresh(ctx)
		target, exists = dc.lookupTarget(ctx, name)
	}
	if !exists {
		return nil, fmt.Errorf("proxy path for target %q not found", name)
	}
	return target, nil
}

func (dc *Proxy) HostPolicy(ctx context.Context, host string) error {
	if _, err := dc.LookupTarget(ctx, host); err != nil {
		return fmt.Errorf("HostPolicy() failed for host %q: %w", host, err)
	}
	return nil
}

func (dc *Proxy) DialContext(ctx context.Context, _ string, addr string) (net.Conn, error) {
	addr = strings.TrimSuffix(addr, ":80")

	// attempt to find target in cache
	target, err := dc.LookupTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", target.Path)
}

func (p Proxy) Run(ctx context.Context) error {
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: p.HostPolicy,
		Cache:      autocert.DirCache("."),
	}

	config := tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// should we even bother getting the certificate?
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if _, err := p.LookupTarget(ctx, hello.ServerName); err != nil {
				return nil, fmt.Errorf("could not find proxy target for %q: %w", hello.ServerName, err)
			}
			log.Printf("Getting certificate for for %q", hello.ServerName)
			cert, err := m.GetCertificate(hello)
			if err != nil {
				log.Printf("GetCertificate() returned %v", err)
			}
			return cert, err
		},
	}

	server := http.Server{
		TLSConfig: &config,
		// Handler:   &httpextra.CommonLog{W: os.Stderr, H: &Handler{}},
		Handler: &httpextra.CommonLog{
			W: os.Stderr,
			H: &httputil.ReverseProxy{
				Director: func(r *http.Request) {
					r.URL.Scheme = "http"
					r.URL.Host = r.Host
					// log.Printf("mutating request for %q (%q) - %q", r.URL.Path, r.URL, r.URL.Scheme)
					// log.Printf("request: %#v", r)
				},
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
						addr = strings.TrimSuffix(addr, ":80")
						nodes := strings.Split(addr, ".")
						log.Printf("%v", nodes)
						addr = strings.Join(nodes[len(nodes)-2:], ".")
						log.Printf("dialing %q:%q", "unix", addr)

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
		Handler: &httpextra.CommonLog{W: os.Stderr, H: m.HTTPHandler(nil)},
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
	flag.Parse()

	proxy := Proxy{
		HTTPPort:  *httpport,
		HTTPSPort: *httpsport,
		mu:        &sync.RWMutex{},
		Config:    *config,
		Index:     map[string]*Target{},
	}

	if err := proxy.Run(context.TODO()); err != nil {
		log.Fatal(err)
	}
}
