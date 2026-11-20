package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// existingEvery is how often the other tool's storage is checked for a renewed certificate.
const existingEvery = 5 * time.Minute

// existingCerts mirrors certificates another tool on the node keeps, such as Caddy or certbot, into stable paths the
// core reads.
type existingCerts struct {
	dir     string // where the copies live
	restart func(context.Context) error
	report  func()

	mu     sync.Mutex
	wanted map[string]spec.Existing
	status map[string]link.CertStatus
	kick   chan struct{}
}

func newExistingCerts(dir string, restart func(context.Context) error) *existingCerts {
	return &existingCerts{dir: dir, restart: restart, wanted: map[string]spec.Existing{}, status: map[string]link.CertStatus{}, kick: make(chan struct{}, 1)}
}

// Want replaces the set of domains to mirror and copies what is already there, or a stand-in, before the core starts.
func (c *existingCerts) Want(d spec.Daemon) {
	want := map[string]spec.Existing{}
	for _, in := range d.Inbounds {
		if cd := in.Security.Existing; cd != nil && in.Security.Type == spec.SecurityTLS && cd.Domain != "" {
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
func (c *existingCerts) Statuses() []link.CertStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]link.CertStatus, 0, len(c.status))
	for _, s := range c.status {
		out = append(out, s)
	}
	return out
}

func (c *existingCerts) set(s link.CertStatus) {
	c.mu.Lock()
	c.status[s.Domain] = s
	c.mu.Unlock()
}

// Run picks up renewals until ctx ends.
func (c *existingCerts) Run(ctx context.Context) {
	tick := time.NewTicker(existingEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-tick.C:
		}
		c.mu.Lock()
		var todo []spec.Existing
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
				slog.Info("picked up a renewed certificate", "domain", cd.Domain)
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
func (c *existingCerts) fingerprint(cd spec.Existing) []byte {
	cert, _ := cd.Paths(c.dir)
	raw, _ := os.ReadFile(cert)
	return raw
}

// sync copies the newest certificate covering a domain, or puts a stand-in in place while there is none.
func (c *existingCerts) sync(cd spec.Existing) link.CertStatus {
	st := link.CertStatus{Domain: cd.Domain}
	certPath, keyPath := cd.Paths(c.dir)
	marker := filepath.Join(filepath.Dir(certPath), ".placeholder")

	dirs := spec.ExistingDirs
	if cd.Dir != "" {
		dirs = []string{cd.Dir}
	}
	found, err := findCert(dirs, cd.Domain)
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
		st.Error = "the certificate has expired"
	}
	return st
}

// foundCert is one certificate and its key.
type foundCert struct {
	cert, key []byte
	expires   time.Time
}

// findCert searches dirs for the freshest certificate covering domain, including a wildcard for its parent. It knows
// Caddy's storage (NAME.crt next to NAME.key) and certbot's (fullchain.pem next to privkey.pem), and matches by the
// names in the certificate rather than by folder names.
func findCert(dirs []string, domain string) (foundCert, error) {
	// a wildcard certificate only verifies against a name under it
	host := domain
	if rest, ok := strings.CutPrefix(domain, "*."); ok {
		host = "frostbite-check." + rest
	}

	var best foundCert
	seen, searched := false, []string{}
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		searched = append(searched, dir)
		for _, pair := range certPairs(dir) {
			certPEM, err := os.ReadFile(pair[0])
			if err != nil {
				continue
			}
			keyPEM, err := os.ReadFile(pair[1])
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
				best, seen = foundCert{cert: certPEM, key: keyPEM, expires: leaf.NotAfter}, true
			}
		}
	}
	switch {
	case seen:
		return best, nil
	case len(searched) == 0:
		return best, fmt.Errorf("found no certificate storage in %s. Mount Caddy's data folder or certbot's /etc/letsencrypt there", strings.Join(dirs, ", "))
	default:
		return best, fmt.Errorf("no certificate for %s in %s yet", domain, strings.Join(searched, ", "))
	}
}

// existingDepth bounds how deep findCert looks, enough for Caddy's certificates/ISSUER/NAME/NAME.crt.
const existingDepth = 4

// certPairs lists certificate and key files that sit next to each other under dir. certbot's archive/ is skipped
// because live/ links to its current files.
func certPairs(dir string) [][2]string {
	var out [][2]string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if d.IsDir() {
			if rel != "." && (d.Name() == "archive" || strings.Count(rel, string(filepath.Separator)) >= existingDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		var key string
		switch {
		case name == "fullchain.pem":
			key = filepath.Join(filepath.Dir(path), "privkey.pem")
		case strings.HasSuffix(name, ".crt"):
			key = strings.TrimSuffix(path, ".crt") + ".key"
		default:
			return nil
		}
		out = append(out, [2]string{path, key})
		return nil
	})
	return out
}
