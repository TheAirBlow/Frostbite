// Package agent is the daemon side of the panel link, shared by every core's binary.
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"frostbite/internal/core"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// Version is the agent build version, set at link time.
var Version = "dev"

// Config tells an agent who it is and where the panel lives.
type Config struct {
	PanelURL string
	Token    string
	DataDir  string
	Insecure bool // skip TLS verification of the panel, for self-signed setups

	ACMEDirectory string // certificate authority, Let's Encrypt when empty
	ACMEHTTPPort  int    // where the HTTP-01 challenge listens, 80 when zero
}

// Runtime drives one core. Implementations live next to their binary.
type Runtime interface {
	Kind() string
	CoreVersion() string
	// Apply makes the core run d. rendered is the native config for it.
	Apply(ctx context.Context, d spec.Daemon, rendered []byte) error
	// Stats returns usage since the previous call and who is connected right now.
	Stats(ctx context.Context) (link.Stats, error)
	Restart(ctx context.Context) error
	Logs(lines int) string
	Close() error
}

// Reloader is a runtime that can pick up new certificate files without dropping its users, which beats a restart.
type Reloader interface {
	Reload(ctx context.Context) error
}

// RealityServer is a runtime whose core serves REALITY inbounds, so it answers probes of REALITY targets.
type RealityServer interface {
	ServesReality()
}

// Agent keeps a runtime in sync with the panel.
type Agent struct {
	cfg Config
	rt  Runtime

	mu      sync.Mutex
	applied int64
	lastErr string

	certs    *certs
	existing *existingCerts
	guards   *guards
	last     *link.Spec // the spec as the panel sent it, for applying again
	waits    []string   // inbounds serving a stand-in until their own certificate files appear
	sendMu   sync.Mutex
	send     func(typ string, body any) error // the live session's writer, nil while offline
}

// New creates an agent.
func New(cfg Config, rt Runtime) *Agent {
	a := &Agent{cfg: cfg, rt: rt}
	reload := rt.Restart
	if r, ok := rt.(Reloader); ok {
		reload = r.Reload
	}
	a.certs = newCerts(filepath.Join(cfg.DataDir, "acme"), cfg.ACMEDirectory, cfg.ACMEHTTPPort, reload)
	a.certs.report = func([]link.CertStatus) { a.reportCerts() }
	a.existing = newExistingCerts(filepath.Join(cfg.DataDir, "existing-certs"), reload)
	a.existing.report = a.reportCerts
	a.guards = newGuards(rt)
	return a
}

// certStatuses lists every certificate the agent looks after.
func (a *Agent) certStatuses() []link.CertStatus {
	return append(a.certs.Statuses(), a.existing.Statuses()...)
}

// reportCerts tells the panel how certificates are doing, if a session is open.
func (a *Agent) reportCerts() {
	a.sendMu.Lock()
	send := a.send
	a.sendMu.Unlock()
	if send != nil {
		_ = send(link.TypeCerts, a.certStatuses())
	}
}

// localize points spec paths that assume the container layout at this agent's data directory.
func (a *Agent) localize(d *spec.Daemon) {
	if filepath.Clean(a.cfg.DataDir) == "/data" {
		return
	}
	acme, existing := filepath.Join(a.cfg.DataDir, "acme"), filepath.Join(a.cfg.DataDir, "existing-certs")
	for i := range d.Inbounds {
		s := &d.Inbounds[i].Security
		if s.Type != spec.SecurityTLS {
			continue
		}
		if s.ACME != nil {
			s.CertPath, s.KeyPath = s.ACME.Paths(acme)
		} else if s.Existing != nil {
			s.CertPath, s.KeyPath = s.Existing.Paths(existing)
		}
	}
}

// Run connects to the panel and stays connected until ctx ends, resuming from the last good spec if the panel is away.
func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	a.resume(ctx)
	go a.certs.Run(ctx)
	go a.existing.Run(ctx)
	go a.guards.Run(ctx)
	go a.watchStandins(ctx)

	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			break
		}
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		slog.Warn("lost the panel, retrying", "err", err, "in", backoff.Round(time.Millisecond))

		select {
		case <-ctx.Done():
		case <-time.After(backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return a.rt.Close()
}

// specPath is where the last good spec is kept.
func (a *Agent) specPath() string { return filepath.Join(a.cfg.DataDir, "spec.json") }

// resume applies the saved spec so users keep their connection while the panel is unreachable.
func (a *Agent) resume(ctx context.Context) {
	raw, err := os.ReadFile(a.specPath())
	if err != nil {
		return
	}
	var sp link.Spec
	if err := json.Unmarshal(raw, &sp); err != nil {
		slog.Warn("saved spec is unreadable, ignoring it", "err", err)
		return
	}
	if err := a.apply(ctx, sp, false); err != nil {
		slog.Warn("saved spec did not apply", "err", err)
		return
	}
	slog.Info("resumed from the saved spec", "revision", sp.Revision)
}

// dial opens the websocket to the panel.
func (a *Agent) dial(ctx context.Context) (*websocket.Conn, error) {
	u, err := url.Parse(strings.TrimRight(a.cfg.PanelURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("bad panel url: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	u.Path = strings.TrimRight(u.Path, "/") + link.Path

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: a.cfg.Insecure}, Proxy: http.ProxyFromEnvironment}}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + a.cfg.Token}},
	})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(16 << 20)
	return conn, nil
}

// session is one connection to the panel, from hello to disconnect.
func (a *Agent) session(ctx context.Context) error {
	conn, err := a.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	send := func(typ string, body any) error {
		b, err := link.Encode(typ, body)
		if err != nil {
			return err
		}
		wctx, wcancel := context.WithTimeout(sctx, 10*time.Second)
		defer wcancel()
		return conn.Write(wctx, websocket.MessageText, b)
	}

	a.mu.Lock()
	applied := a.applied
	a.mu.Unlock()
	hello := link.Hello{Kind: a.rt.Kind(), AgentVer: Version, CoreVer: a.rt.CoreVersion(), AppliedRev: applied, Host: hostInfo()}
	if err := send(link.TypeHello, hello); err != nil {
		return err
	}
	slog.Info("connected to the panel", "core", hello.CoreVer)

	a.sendMu.Lock()
	a.send = send
	a.sendMu.Unlock()
	defer func() {
		a.sendMu.Lock()
		a.send = nil
		a.sendMu.Unlock()
	}()
	if st := a.certStatuses(); len(st) > 0 {
		_ = send(link.TypeCerts, st)
	}

	go a.report(sctx, cancel, send)

	for {
		_, data, err := conn.Read(sctx)
		if err != nil {
			return err
		}
		m, err := link.Decode(data)
		if err != nil {
			slog.Warn("bad frame from the panel", "err", err)
			continue
		}
		switch m.Type {
		case link.TypeSpec:
			var sp link.Spec
			if err := json.Unmarshal(m.Body, &sp); err != nil {
				slog.Warn("bad spec from the panel", "err", err)
				continue
			}
			ack := link.Ack{Revision: sp.Revision}
			if err := a.apply(sctx, sp, true); err != nil {
				slog.Error("applying spec failed", "revision", sp.Revision, "err", err)
				ack.Error = err.Error()
			}
			if err := send(link.TypeAck, ack); err != nil {
				return err
			}
		case link.TypeCmd:
			var cmd link.Cmd
			if err := json.Unmarshal(m.Body, &cmd); err != nil {
				continue
			}
			go func() {
				if err := send(link.TypeResult, a.command(sctx, cmd)); err != nil {
					cancel()
				}
			}()
		}
	}
}

// apply renders a spec, hands it to the runtime and remembers it.
func (a *Agent) apply(ctx context.Context, sp link.Spec, save bool) error {
	desc := core.Get(a.rt.Kind())
	if desc == nil {
		return fmt.Errorf("this binary has no renderer for %q", a.rt.Kind())
	}
	if sp.Daemon.Kind != a.rt.Kind() {
		return fmt.Errorf("spec is for a %s daemon, this one runs %s", sp.Daemon.Kind, a.rt.Kind())
	}

	d := sp.Daemon
	d.Inbounds = slices.Clone(d.Inbounds)
	a.localize(&d)
	a.certs.Want(d)
	a.existing.Want(d)
	waits := ensureCerts(&d, filepath.Join(a.cfg.DataDir, "standin"))
	rendered, err := desc.Render(d)
	if err != nil {
		return a.fail(fmt.Errorf("render: %w", err))
	}
	a.guards.Pause()
	err = a.rt.Apply(ctx, d, rendered)
	a.guards.Want(d)
	if err != nil {
		return a.fail(err)
	}

	a.mu.Lock()
	a.applied, a.lastErr = sp.Revision, ""
	a.last, a.waits = &sp, waits
	a.mu.Unlock()
	if save {
		if raw, err := json.Marshal(sp); err == nil {
			if err := writeAtomic(a.specPath(), raw); err != nil {
				slog.Warn("could not save the spec", "err", err)
			}
		}
	}
	return nil
}

// watchStandins applies the spec again once the certificate files of an inbound serving a stand-in appear.
func (a *Agent) watchStandins(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		a.mu.Lock()
		last, waits := a.last, a.waits
		a.mu.Unlock()
		if last == nil || len(waits) == 0 || !certsAppeared(last.Daemon, waits) {
			continue
		}
		slog.Info("certificate files appeared, applying the spec again")
		if err := a.apply(ctx, *last, false); err != nil {
			slog.Warn("applying with the new certificate failed", "err", err)
		}
	}
}

// certsAppeared reports whether any of the named inbounds now has its own certificate files.
func certsAppeared(d spec.Daemon, tags []string) bool {
	for _, in := range d.Inbounds {
		if slices.Contains(tags, in.Tag) && fileExists(in.Security.CertPath) && fileExists(in.Security.KeyPath) {
			return true
		}
	}
	return false
}

// fail remembers the last error.
func (a *Agent) fail(err error) error {
	a.mu.Lock()
	a.lastErr = err.Error()
	a.mu.Unlock()
	return err
}

// writeAtomic replaces a file without ever leaving a half written one behind.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// hostInfo describes the machine.
func hostInfo() link.HostInfo {
	name, _ := os.Hostname()
	return link.HostInfo{Hostname: name, OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), MemTotal: readMemTotal(), Kernel: readKernel()}
}

// report sends usage and health on a timer until the session ends.
func (a *Agent) report(ctx context.Context, cancel context.CancelFunc, send func(string, any) error) {
	stats := time.NewTicker(10 * time.Second)
	defer stats.Stop()
	metrics := time.NewTicker(15 * time.Second)
	defer metrics.Stop()
	sampler := newSampler()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stats.C:
			s, err := a.rt.Stats(ctx)
			if err != nil {
				slog.Debug("stats unavailable", "err", err)
				continue
			}
			if len(s.Users) == 0 && len(s.Online) == 0 {
				continue
			}
			if err := send(link.TypeStats, s); err != nil {
				cancel()
				return
			}
		case <-metrics.C:
			if err := send(link.TypeMetrics, sampler.sample()); err != nil {
				cancel()
				return
			}
		}
	}
}

// command runs a panel command.
func (a *Agent) command(ctx context.Context, c link.Cmd) link.Result {
	res := link.Result{ID: c.ID, OK: true}
	switch c.Name {
	case link.CmdRestart:
		if err := a.rt.Restart(ctx); err != nil {
			res.OK, res.Error = false, err.Error()
		}
	case link.CmdLogs:
		n := 200
		fmt.Sscanf(c.Args["lines"], "%d", &n)
		res.Output = a.rt.Logs(max(1, min(n, 5000)))
	case link.CmdTestReality, link.CmdTestHost:
		if _, serves := a.rt.(RealityServer); c.Name == link.CmdTestReality && !serves {
			res.OK, res.Error = false, a.rt.Kind()+" does not serve REALITY"
			break
		}
		xver, _ := strconv.Atoi(c.Args["xver"])
		out, err := testTLS(ctx, c.Args["dest"], c.Args["sni"], xver)
		res.Output = out
		if err != nil {
			res.OK, res.Error = false, err.Error()
		}
	default:
		res.OK, res.Error = false, "unknown command "+c.Name
	}
	return res
}

// errNotRunning is returned by runtimes that were asked for something before they were started.
var errNotRunning = errors.New("the core is not running yet")

// ConfigFromEnv reads the agent configuration from FROSTBITE_* variables.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		PanelURL: os.Getenv("FROSTBITE_PANEL_URL"),
		Token:    os.Getenv("FROSTBITE_TOKEN"),
		DataDir:  os.Getenv("FROSTBITE_DATA_DIR"),
		Insecure: os.Getenv("FROSTBITE_INSECURE") == "true",

		ACMEDirectory: os.Getenv("FROSTBITE_ACME_DIRECTORY"),
	}
	if n, err := strconv.Atoi(os.Getenv("FROSTBITE_ACME_HTTP_PORT")); err == nil {
		cfg.ACMEHTTPPort = n
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/data"
	}
	switch {
	case cfg.PanelURL == "":
		return cfg, errors.New("FROSTBITE_PANEL_URL is not set")
	case cfg.Token == "":
		return cfg, errors.New("FROSTBITE_TOKEN is not set")
	}
	return cfg, nil
}
