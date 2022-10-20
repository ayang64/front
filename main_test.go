package main

import (
	"context"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Ensure that proxy.refresh() properly updates the proxy value.
func TestProxyLookup(t *testing.T) {
	tests := map[string]struct {
		shouldErr       bool
		existingTargets Targets
		r               io.Reader
		expected        Targets
	}{
		// The following test ensures that a failed refresh preserves
		// existing proxy mappings.
		"invalid input with existing targets": {
			shouldErr:       true,
			existingTargets: Targets{{Domain: "foo.com", Path: "/tmp/foo.com"}},
			r: strings.NewReader(`
			xxx[
				{ "domain": "google.com", "path": "/tmp/google.com" }
			]`),
			expected: Targets{{Domain: "foo.com", Path: "/tmp/foo.com"}},
		},
		// The following test ensures that a successful refresh clobbers
		// existing proxy mappings.
		"valid input with existing targets": {
			shouldErr: false,
			existingTargets: Targets{
				{Domain: "foo.com", Path: "/tmp/foo.com"},
			},
			r: strings.NewReader(`
			[
				{ "domain": "google.com", "path": "/tmp/google.com" }
			]`),
			expected: Targets{
				{Domain: "google.com", Path: "/tmp/google.com"},
			},
		},
		// ensure that valid input works and updates target list
		"valid input": {
			shouldErr: false,
			r: strings.NewReader(`[	
				{ "domain": "google.com", "path": "/tmp/google.com" },
				{ "domain": "www.google.com", "path": "/tmp/google.com" },
				{ "domain": "netflix.com", "path": "/tmp/netflix.com" },
				{ "domain": "www.netflix.com", "path": "/tmp/netflix.com" },
				{ "domain": "square.com", "path": "/tmp/square.com" },
				{ "domain": "www.square.com", "path": "/tmp/square.com" }
				]`),
			expected: Targets{
				{Domain: "google.com", Path: "/tmp/google.com"},
				{Domain: "www.google.com", Path: "/tmp/google.com"},
				{Domain: "netflix.com", Path: "/tmp/netflix.com"},
				{Domain: "www.netflix.com", Path: "/tmp/netflix.com"},
				{Domain: "square.com", Path: "/tmp/square.com"},
				{Domain: "www.square.com", Path: "/tmp/square.com"},
			},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			p := Proxy{
				mu:      &sync.RWMutex{},
				Targets: test.existingTargets,
				Config:  "",
				Index:   map[string]*Target{},
			}

			if err := p.refresh(context.Background(), test.r); test.shouldErr != (err != nil) {
				t.Fatalf("expected err != nil to be %v; got %v: %v", test.shouldErr, err != nil, err)
			}

			if expected, got := test.expected, p.Targets; !reflect.DeepEqual(got, expected) {
				t.Fatalf("expected target slice to be %#v; got %#v", expected, got)
			}

			if expected, got := test.expected.Index(), p.Index; !test.shouldErr && !reflect.DeepEqual(got, expected) {
				t.Fatalf("index mismatch!")
			}
		})
	}
}
