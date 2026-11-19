package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// caddyEvery is how often Caddy's storage is checked for a renewed certificate.
const caddyEvery = 5 * time.Minute

// caddyCerts mirrors certificates a local Caddy keeps into stable paths the core reads.
type caddyCerts struct {
	dir     string // where the copies live
	restart func(context.Context) error
	report  func()

	mu     sync.Mutex
	wanted map[string]spec.Caddy
	status map[string]link.CertStatus
	kick   chan struct{}
}

func newCaddyCerts(dir string, restart func(context.Context) error) *caddyCerts {
	return &caddyCerts{dir: dir, restart: restart, wanted: map[string]spec.Caddy{}, status: map[string]link.CertStatus{}, kick: make(chan struct{}, 1)}
}

// Want replaces the set of domains to mirror and copies what is already there, or a stand-in, before the core starts.
func (c *caddyCerts) Want(d spec.Daemon) {
	want := map[string]spec.Caddy{}
	for _, in := range d.Inbounds {
		if cd := in.Security.Caddy; cd != nil && in.Security.Type == spec.SecurityTLS && cd.Domain != "" {
			want[cd.Domain] = *cd
		}
	}
	c.mu.Lock()
	c.wanted = want
	for dom := range c.status {
		if _, ok := want[dom]; !ok {
			delete(c.status, dom)
		}
	}
	c.mu.Unlock()

	for _, cd := range want {
		c.set(c.sync(cd))
	}
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Statuses returns the state of every mirrored certificate.
func (c *caddyCerts) Statuses() []link.CertStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]link.CertStatus, 0, len(c.status))
	for _, s := range c.status {
		out = append(out, s)
	}
	return out
}

func (c *caddyCerts) set(s link.CertStatus) {
	c.mu.Lock()
	c.status[s.Domain] = s
	c.mu.Unlock()
}

// Run picks up renewals until ctx ends.
func (c *caddyCerts) Run(ctx context.Context) {
	tick := time.NewTicker(caddyEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-tick.C:
		}
		c.mu.Lock()
		var todo []spec.Caddy
		for _, cd := range c.wanted {
			todo = append(todo, cd)
		}
		c.mu.Unlock()

		changed := false
		for _, cd := range todo {
			before := c.fingerprint(cd)
			c.set(c.sync(cd))
			if !bytes.Equal(before, c.fingerprint(cd)) {
				changed = true
				slog.Info("picked up a new certificate from Caddy", "domain", cd.Domain)
			}
		}
		if changed && c.restart != nil {
			if err := c.restart(ctx); err != nil {
				slog.Warn("reloading after a new certificate failed", "err", err)
			}
		}
		if c.report != nil {
			c.report()
		}
	}
}

// fingerprint identifies the copy currently in place.
func (c *caddyCerts) fingerprint(cd spec.Caddy) []byte {
	cert, _ := cd.Paths(c.dir)
	raw, _ := os.ReadFile(cert)
	return raw
}

// sync copies Caddy's newest certificate for a domain, or puts a stand-in in place when Caddy has none yet.
func (c *caddyCerts) sync(cd spec.Caddy) link.CertStatus {
	st := link.CertStatus{Domain: cd.Domain}
	certPath, keyPath := cd.Paths(c.dir)
	marker := filepath.Join(filepath.Dir(certPath), ".placeholder")

	src := cd.Dir
	if src == "" {
		src = spec.CaddyDir
	}
	found, err := findCaddyCert(src, cd.Domain)
	if err != nil {
		st.Error = err.Error()
		if !fileExists(certPath) || !fileExists(keyPath) {
			if err := selfSigned(certPath, keyPath, strings.TrimPrefix(cd.Domain, "*.")); err == nil {
				_ = os.WriteFile(marker, nil, 0o600)
			}
		}
		st.Placeholder = fileExists(marker)
		return st
	}

	st.Expires = found.expires
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		st.Error = err.Error()
		return st
	}
	old, _ := os.ReadFile(certPath)
	if !bytes.Equal(old, found.cert) {
		if err := writeAtomic(keyPath, found.key); err != nil {
			st.Error = err.Error()
			return st
		}
		if err := writeAtomic(certPath, found.cert); err != nil {
			st.Error = err.Error()
			return st
		}
		_ = os.Chmod(certPath, 0o644)
	}
	_ = os.Remove(marker)
	st.OK = time.Now().Before(found.expires)
	if !st.OK {
		st.Error = "Caddy's certificate has expired"
	}
	return st
}

// caddyFound is one certificate and key read from Caddy's storage.
type caddyFound struct {
	cert, key []byte
	expires   time.Time
}

// findCaddyCert looks through every issuer in Caddy's storage for the freshest certificate covering domain,
// including a wildcard for its parent.
func findCaddyCert(dir, domain string) (caddyFound, error) {
	names := []string{spec.Caddy{Domain: domain}.StorageName()}
	if !strings.HasPrefix(domain, "*.") {
		if _, parent, ok := strings.Cut(domain, "."); ok && strings.Contains(parent, ".") {
			names = append(names, "wildcard_."+parent)
		}
	}
	// a wildcard certificate only verifies against a name under it
	host := domain
	if rest, ok := strings.CutPrefix(domain, "*."); ok {
		host = "frostbite-check." + rest
	}

	var best caddyFound
	seen := false
	for _, name := range names {
		matches, _ := filepath.Glob(filepath.Join(dir, "certificates", "*", name, name+".crt"))
		for _, certPath := range matches {
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}
			keyPEM, err := os.ReadFile(strings.TrimSuffix(certPath, ".crt") + ".key")
			if err != nil {
				continue
			}
			if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
				continue
			}
			block, _ := pem.Decode(certPEM)
			if block == nil {
				continue
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil || leaf.VerifyHostname(host) != nil {
				continue
			}
			if !seen || leaf.NotAfter.After(best.expires) {
				best, seen = caddyFound{cert: certPEM, key: keyPEM, expires: leaf.NotAfter}, true
			}
		}
	}
	if !seen {
		if _, err := os.Stat(filepath.Join(dir, "certificates")); errors.Is(err, os.ErrNotExist) {
			return best, fmt.Errorf("no Caddy storage at %s, mount Caddy's data folder there", dir)
		}
		return best, fmt.Errorf("Caddy has no certificate for %s yet", domain)
	}
	return best, nil
}
