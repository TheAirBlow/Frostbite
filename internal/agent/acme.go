package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// renewBefore is how long before expiry a certificate gets replaced.
const renewBefore = 30 * 24 * time.Hour

// retryEvery is how often a failed or pending certificate is tried again.
const retryEvery = 15 * time.Minute

// certs keeps certificates for ACME inbounds fresh in the background.
type certs struct {
	dir       string
	directory string // ACME directory url, Let's Encrypt when empty
	httpPort  int
	restart   func(context.Context) error
	report    func([]link.CertStatus)

	mu      sync.Mutex
	wanted  map[string]spec.ACME
	status  map[string]link.CertStatus
	kick    chan struct{}
	started bool
}

// newCerts creates the manager. restart reloads the core after a new certificate lands.
func newCerts(dir, directory string, httpPort int, restart func(context.Context) error) *certs {
	if httpPort == 0 {
		httpPort = 80
	}
	return &certs{
		dir: dir, directory: directory, httpPort: httpPort, restart: restart,
		wanted: map[string]spec.ACME{}, status: map[string]link.CertStatus{}, kick: make(chan struct{}, 1),
	}
}

// certPaths gives the files for a domain.
func (c *certs) certPaths(domain string) (cert, key, marker string) {
	base := filepath.Join(c.dir, domain)
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem"), filepath.Join(base, ".placeholder")
}

// Want replaces the set of domains to look after and puts a stand-in in place for those without a certificate.
func (c *certs) Want(d spec.Daemon) {
	want := map[string]spec.ACME{}
	for _, in := range d.Inbounds {
		if a := in.Security.ACME; a != nil && in.Security.Type == spec.SecurityTLS && a.Domain != "" {
			want[a.Domain] = *a
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

	for dom := range want {
		cert, key, marker := c.certPaths(dom)
		if fileExists(cert) && fileExists(key) {
			continue
		}
		if err := selfSigned(cert, key, dom); err != nil {
			slog.Warn("could not create a stand-in certificate", "domain", dom, "err", err)
			continue
		}
		_ = os.WriteFile(marker, nil, 0o600)
		slog.Warn("no certificate yet, serving a self signed stand-in", "domain", dom)
	}
	c.nudge()
}

// nudge wakes the worker.
func (c *certs) nudge() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Statuses returns the current state of every wanted certificate.
func (c *certs) Statuses() []link.CertStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]link.CertStatus, 0, len(c.wanted))
	for dom := range c.wanted {
		if s, ok := c.status[dom]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Run works through wanted certificates until ctx ends.
func (c *certs) Run(ctx context.Context) {
	tick := time.NewTicker(retryEvery)
	defer tick.Stop()
	for {
		c.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-tick.C:
		}
	}
}

// pass checks every wanted domain once.
func (c *certs) pass(ctx context.Context) {
	c.mu.Lock()
	var todo []spec.ACME
	for _, a := range c.wanted {
		todo = append(todo, a)
	}
	c.mu.Unlock()

	renewed := false
	for _, a := range todo {
		st := c.inspect(a.Domain)
		if st.OK && !st.Placeholder && time.Until(st.Expires) > renewBefore {
			c.set(st)
			continue
		}

		slog.Info("getting a certificate", "domain", a.Domain)
		if err := c.obtain(ctx, a); err != nil {
			slog.Warn("certificate request failed", "domain", a.Domain, "err", err)
			st = c.inspect(a.Domain)
			st.Error = err.Error()
			c.set(st)
			continue
		}
		c.set(c.inspect(a.Domain))
		renewed = true
		slog.Info("certificate ready", "domain", a.Domain)
	}

	if renewed && c.restart != nil {
		if err := c.restart(ctx); err != nil {
			slog.Warn("reloading after a new certificate failed", "err", err)
		}
	}
	if c.report != nil {
		c.report(c.Statuses())
	}
}

// set stores a status.
func (c *certs) set(s link.CertStatus) {
	c.mu.Lock()
	c.status[s.Domain] = s
	c.mu.Unlock()
}

// inspect reads what is on disk for a domain.
func (c *certs) inspect(domain string) link.CertStatus {
	cert, _, marker := c.certPaths(domain)
	st := link.CertStatus{Domain: domain}
	raw, err := os.ReadFile(cert)
	if err != nil {
		st.Error = "no certificate yet"
		return st
	}
	if block, _ := pem.Decode(raw); block != nil {
		if x, err := x509.ParseCertificate(block.Bytes); err == nil {
			st.Expires = x.NotAfter
		}
	}
	_, perr := os.Stat(marker)
	st.Placeholder = perr == nil
	st.OK = !st.Placeholder && time.Now().Before(st.Expires)
	return st
}

// user is the ACME account.
type user struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *registration.Resource { return u.reg }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

// account loads or creates the ACME account for an email.
func (c *certs) account(email string) (*user, error) {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(c.dir, "account.key")
	u := &user{email: email}

	if raw, err := os.ReadFile(keyPath); err == nil {
		if block, _ := pem.Decode(raw); block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				u.key = k
			}
		}
	}
	if u.key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
		u.key = k
	}
	if raw, err := os.ReadFile(filepath.Join(c.dir, "account.json")); err == nil {
		var reg registration.Resource
		if json.Unmarshal(raw, &reg) == nil {
			u.reg = &reg
		}
	}
	return u, nil
}

// obtain asks the CA for a certificate and writes it where the core expects it.
func (c *certs) obtain(ctx context.Context, a spec.ACME) error {
	u, err := c.account(a.Email)
	if err != nil {
		return err
	}

	cfg := lego.NewConfig(u)
	if c.directory != "" {
		cfg.CADirURL = c.directory
	}
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("talking to the CA: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", strconv.Itoa(c.httpPort))); err != nil {
		return err
	}

	if u.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("registering an account: %w", err)
		}
		u.reg = reg
		if raw, err := json.Marshal(reg); err == nil {
			_ = writeAtomic(filepath.Join(c.dir, "account.json"), raw)
		}
	}

	res, err := obtainWithContext(ctx, client, a.Domain)
	if err != nil {
		return explain(err, a.Domain, c.httpPort)
	}

	certPath, keyPath, marker := c.certPaths(a.Domain)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(keyPath, res.PrivateKey); err != nil {
		return err
	}
	if err := writeAtomic(certPath, res.Certificate); err != nil {
		return err
	}
	_ = os.Chmod(certPath, 0o644)
	_ = os.Remove(marker)
	return nil
}

// obtainWithContext runs a request that lego itself cannot cancel, so a shutdown does not wait for it.
func obtainWithContext(ctx context.Context, client *lego.Client, domain string) (*certificate.Resource, error) {
	type out struct {
		res *certificate.Resource
		err error
	}
	ch := make(chan out, 1)
	go func() {
		res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{domain}, Bundle: true})
		ch <- out{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// explain turns the usual failure into something actionable.
func explain(err error, domain string, port int) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("%w (the CA must reach http://%s:%d from the internet, so the domain has to point at this node and the port must be free)", err, domain, port)
}
