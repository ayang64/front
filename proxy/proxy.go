package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

	"github.com/ayang64/front/commonlog"
	"golang.org/x/crypto/acme/autocert"
)

type Target struct {
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

type Targets []Target

func (t Targets) index() map[string]*Target {
	rc := map[string]*Target{}
	for i := range t {
		rc[t[i].Domain] = &t[i]
	}
	return rc
}

type Server struct {
	mu           *sync.RWMutex      // Mutex to protect members of Proxy
	index        map[string]*Target // Index into Targets using domain as the key
	httpPort     int                // Port to listen for certbot requests
	httpsPort    int                // Port to listen for secure traffic
	configPath   string             // Path to configuration file
	dircachePath string             // Location of autocert dir cache
	targets      Targets            // Unmarshaled configuration file
}

// refresh attempts to re-read the JSON proxy configuraton provided
// by the supplied io.Reader.
//
// If succesful, the new configuration is stored and indexed for
// fast retrieval.
func (s *Server) refresh(ctx context.Context, r io.Reader) (Targets, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var targets Targets
	if err := json.NewDecoder(r).Decode(&targets); err != nil {
		return nil, err
	}
	// rewrite targets member and re-index

	return targets, nil
}

func (s *Server) refreshFromFile(ctx context.Context, p string) (Targets, error) {
	// TODO: respect passed in context value
	inf, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer inf.Close()
	return s.refresh(ctx, inf)
}

// Refresh attempts to re-read the JSON proxy configuraton provided
// by the supplied io.Reader.
//
// If succesful, the new configuration is stored and indexed for
// fast retrieval.
func (s *Server) Refresh(ctx context.Context) error {
	targets, err := s.refreshFromFile(ctx, s.configPath)
	if err != nil {
		return err
	}
	s.targets = targets
	s.index = s.targets.index()
	return nil
}

func (s *Server) lookupTarget(_ context.Context, name string) (*Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	target, found := s.index[name]
	return target, found
}

func (s *Server) LookupTarget(ctx context.Context, name string) (*Target, error) {
	target, exists := s.lookupTarget(ctx, name)
	if !exists {
		// if not found, check if the configuration file has been updated.
		s.Refresh(ctx)
		target, exists = s.lookupTarget(ctx, name)
	}
	if !exists {
		return nil, fmt.Errorf("proxy path for target %q not found", name)
	}
	return target, nil
}

func (s *Server) HostPolicy(ctx context.Context, host string) error {
	if _, err := s.LookupTarget(ctx, host); err != nil {
		return fmt.Errorf("HostPolicy() failed for host %q: %w", host, err)
	}
	return nil
}

func (s *Server) DialContext(ctx context.Context, _ string, addr string) (net.Conn, error) {
	addr = strings.TrimSuffix(addr, ":80")

	// attempt to find target in cache
	target, err := s.LookupTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", target.Path)
}

func WithDircachePath(p string) func(*Server) error {
	return func(s *Server) error {
		s.dircachePath = p
		return nil
	}
}

func WithConfigPath(p string) func(*Server) error {
	return func(s *Server) error {
		s.configPath = p
		return nil
	}
}

func WithHTTPSPort(port int) func(*Server) error {
	return func(s *Server) error {
		s.httpsPort = port
		return nil
	}
}

func WithHTTPPort(port int) func(*Server) error {
	return func(s *Server) error {
		s.httpPort = port
		return nil
	}
}

func New(opts ...func(*Server) error) (*Server, error) {
	s := Server{
		mu:           &sync.RWMutex{},
		index:        map[string]*Target{},
		httpPort:     80,
		httpsPort:    443,
		configPath:   "./proxy.json",
		dircachePath: "./dircache",
	}
	for _, opt := range opts {
		if err := opt(&s); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

func (s Server) Serve(ctx context.Context) error {
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: s.HostPolicy,
		Cache:      autocert.DirCache(s.dircachePath),
	}

	config := tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// should we even bother getting the certificate?
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if _, err := s.LookupTarget(ctx, hello.ServerName); err != nil {
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

						target, err := s.LookupTarget(context.TODO(), addr)
						if err != nil {
							return nil, err
						}

						return net.Dial("unix", target.Path)
					},
				},
			},
		},
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", s.httpsPort))
	if err != nil {
		return err
	}

	cr := http.Server{
		Handler: &commonlog.Handler{W: os.Stderr, H: m.HTTPHandler(nil)},
		Addr:    fmt.Sprintf(":%d", s.httpPort),
	}

	errCh := make(chan error, 2)

	go func() { errCh <- server.ServeTLS(l, "", "") }()
	go func() { errCh <- cr.ListenAndServe() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// TODO: this entire loop needs to be re-visited.
	for i := 0; i < cap(errCh); i++ {
		select {
		case <-ctx.Done():
			ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()

			sdCh := make(chan error, 2)
			go func() { sdCh <- server.Shutdown(ctx) }()
			go func() { sdCh <- cr.Shutdown(ctx) }()
			for i := 0; i < cap(sdCh); i++ {
				if sderr := <-sdCh; err != nil {
					// return fmt.Errorf("server failed because %v; could not gracefully shutdown becaue %v", svrerr, sderr)
					return sderr
				}
			}
			// return fmt.Errorf("server failed: %v; gracefully shutdown", svrerr)
			return fmt.Errorf("server failed: to gracefully shutdown")

		case err := <-errCh:
			if err != nil {
				cancel()
			}
			// give our shutdown go-routines 500ms to complete
		}
	}

	return nil
}
