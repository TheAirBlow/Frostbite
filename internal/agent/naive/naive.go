// Package naive runs the naive daemon: Caddy with the NaiveProxy fork of forwardproxy, supervised as a subprocess. The
// Caddy build carries the Frostbite gate, which keeps the users, counts their traffic and cuts them off, all through
// Caddy's admin api, so changing users never reloads the config and never drops anyone who stays.
package naive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"frostbite/internal/agent/logs"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// credential is a proxy user as the gate knows it.
type credential struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// usage is what the gate reports.
type usage struct {
	Users  map[string]link.Usage `json:"users"`
	Online map[string][]string   `json:"online"`
}

// Runtime runs Caddy.
type Runtime struct {
	bin     string
	dataDir string
	logs    *logs.Ring
	admin   *http.Client

	mu       sync.Mutex
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	exited   chan struct{}
	stopping bool
	failures int // unexpected exits in a row, for backoff

	cfg    []byte                  // the config that should be running
	loaded []byte                  // the config the running process has
	users  map[string][]credential // the users that should be known, by inbound
	pushed map[string][]credential // the users the running process knows
}

// New creates a runtime. bin is the Caddy executable, dataDir holds its config and admin socket.
func New(bin, dataDir string) *Runtime {
	r := &Runtime{bin: bin, dataDir: dataDir, logs: logs.NewRing(2000)}
	r.admin = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", r.socket())
		}},
	}
	return r
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "naive" }

// CoreVersion asks the binary which version it is.
func (r *Runtime) CoreVersion() string {
	out, err := exec.Command(r.bin, "version").Output()
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "unknown"
	}
	return "caddy " + strings.TrimPrefix(fields[0], "v")
}

func (r *Runtime) socket() string { return filepath.Join(r.dataDir, "caddy.sock") }

// withAdmin points the config at the agent's admin socket, which every loaded config must name or Caddy falls back to
// its default address.
func (r *Runtime) withAdmin(rendered []byte) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(rendered, &cfg); err != nil {
		return nil, err
	}
	cfg["admin"] = map[string]any{"listen": "unix/" + r.socket(), "config": map[string]any{"persist": false}}
	return json.Marshal(cfg)
}

// usersOf lists who may use each inbound.
func usersOf(d spec.Daemon) map[string][]credential {
	out := map[string][]credential{}
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoNaive {
			continue
		}
		list := []credential{}
		for _, u := range in.Users {
			list = append(list, credential{Name: u.Name, Password: u.Password})
		}
		slices.SortFunc(list, func(a, b credential) int { return strings.Compare(a.Name, b.Name) })
		out[in.Tag] = list
	}
	return out
}

// Apply brings Caddy in line with d. Users change through the gate, and the config is only reloaded when it differs.
func (r *Runtime) Apply(ctx context.Context, d spec.Daemon, rendered []byte) error {
	cfg, err := r.withAdmin(rendered)
	if err != nil {
		return err
	}
	users := usersOf(d)

	r.mu.Lock()
	defer r.mu.Unlock()

	if !bytes.Equal(cfg, r.loaded) {
		if err := r.validate(ctx, cfg); err != nil {
			return err
		}
	}
	r.cfg, r.users = cfg, users
	if r.cmd == nil {
		return r.startLocked(ctx)
	}
	return r.syncLocked(ctx)
}

// syncLocked makes the running process match the wanted users and config. Users go first, so a user added together
// with a new inbound can connect the moment it opens, and a removed one is already gone when it closes.
func (r *Runtime) syncLocked(ctx context.Context) error {
	for tag, list := range r.users {
		if reflect.DeepEqual(r.pushed[tag], list) {
			continue
		}
		if err := r.setUsers(ctx, tag, list); err != nil {
			return err
		}
	}
	for tag := range r.pushed {
		if _, ok := r.users[tag]; !ok {
			// an inbound that is gone must not keep its tunnels
			if err := r.setUsers(ctx, tag, nil); err != nil {
				return err
			}
			delete(r.pushed, tag)
		}
	}
	if !bytes.Equal(r.cfg, r.loaded) {
		if err := r.load(ctx, r.cfg); err != nil {
			return err
		}
		r.loaded = r.cfg
	}
	return nil
}

// setUsers replaces the users of one inbound.
func (r *Runtime) setUsers(ctx context.Context, tag string, list []credential) error {
	if list == nil {
		list = []credential{}
	}
	body, _ := json.Marshal(map[string]any{"users": list})
	out, err := r.call(ctx, http.MethodPut, "/frostbite/users/"+tag, body, nil)
	if err != nil {
		return fmt.Errorf("users of %s: %w", tag, err)
	}
	var res struct{ Cut int }
	if json.Unmarshal(out, &res) == nil && res.Cut > 0 {
		slog.Info("naive: cut tunnels of users that are gone", "inbound", tag, "tunnels", res.Cut)
	}
	r.pushed[tag] = list
	return nil
}

// load has Caddy switch to a config without dropping the connections it already serves.
func (r *Runtime) load(ctx context.Context, cfg []byte) error {
	// without this Caddy skips a config that looks unchanged, which would also skip new certificate files
	_, err := r.call(ctx, http.MethodPost, "/load", cfg, http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"must-revalidate"}})
	if err != nil {
		return fmt.Errorf("caddy rejected the config: %w", err)
	}
	return nil
}

// call sends a request to Caddy's admin api.
func (r *Runtime) call(ctx context.Context, method, path string, body []byte, hdr http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://caddy"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := r.admin.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// validate has Caddy check a config before it replaces the running one.
func (r *Runtime) validate(ctx context.Context, cfg []byte) error {
	tmp := filepath.Join(r.dataDir, "naive.next.json")
	if err := os.WriteFile(tmp, cfg, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, "validate", "--config", tmp)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Env = r.env()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("caddy rejected the config: %s", lastLines(out.String(), 6))
	}
	return nil
}

// env keeps everything Caddy writes under the data directory.
func (r *Runtime) env() []string {
	return append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(r.dataDir, "caddy-config"),
		"XDG_DATA_HOME="+filepath.Join(r.dataDir, "caddy-data"),
	)
}

// startLocked starts Caddy with nothing to serve, hands it the users, and only then loads the config, so nobody
// reaches a listener that does not know them yet.
func (r *Runtime) startLocked(ctx context.Context) error {
	r.stopping = false
	_ = os.Remove(r.socket())

	boot, err := r.withAdmin([]byte(`{"logging":{"logs":{"default":{"level":"INFO","encoder":{"format":"console"}}}}}`))
	if err != nil {
		return err
	}
	bootPath := filepath.Join(r.dataDir, "naive.boot.json")
	if err := os.WriteFile(bootPath, boot, 0o600); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runCtx, r.bin, "run", "--config", bootPath)
	cmd.Stdout, cmd.Stderr = r.logs, r.logs
	cmd.Env = r.env()
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("starting caddy: %w", err)
	}
	exited := make(chan struct{})
	r.cmd, r.cancel, r.exited = cmd, cancel, exited
	r.loaded, r.pushed = nil, map[string][]credential{}
	slog.Info("caddy started", "pid", cmd.Process.Pid)
	go r.watch(cmd, cancel, time.Now(), exited)

	if err := r.waitReady(ctx, exited); err != nil {
		r.stopLocked()
		return err
	}
	if err := r.syncLocked(ctx); err != nil {
		r.stopLocked()
		return err
	}
	return nil
}

// waitReady waits for the admin api to answer.
func (r *Runtime) waitReady(ctx context.Context, exited chan struct{}) error {
	deadline := time.After(15 * time.Second)
	for {
		if _, err := r.call(ctx, http.MethodGet, "/config/", nil, nil); err == nil {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("caddy exited while starting: %s", lastLines(r.logs.Tail(20), 4))
		case <-deadline:
			return errors.New("caddy did not come up")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// watch brings Caddy back if it dies on its own.
func (r *Runtime) watch(cmd *exec.Cmd, cancel context.CancelFunc, started time.Time, exited chan struct{}) {
	err := cmd.Wait()
	cancel()
	close(exited)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != cmd || r.stopping {
		return
	}
	slog.Error("caddy exited unexpectedly", "err", err)
	r.cmd = nil
	if time.Since(started) > time.Minute {
		r.failures = 0
	}
	r.failures++
	delay := min(3*time.Second<<min(r.failures-1, 4), time.Minute)
	go func() {
		time.Sleep(delay)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.cmd != nil || r.stopping || r.cfg == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := r.startLocked(ctx); err != nil {
			slog.Error("restarting caddy failed", "err", err, "attempt", r.failures)
		}
	}()
}

// stopLocked stops the running process and waits for it. The caller holds the lock.
func (r *Runtime) stopLocked() {
	if r.cmd == nil {
		return
	}
	done := r.exited
	r.cmd = nil
	// Caddy waits for open connections before it exits, so the context also kills it after the wait delay
	r.cancel()
	<-done
}

// Restart stops Caddy and starts it again, which drops every tunnel.
func (r *Runtime) Restart(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg == nil {
		return errors.New("there is no config to run yet")
	}
	r.stopLocked()
	return r.startLocked(ctx)
}

// Reload has Caddy read its config and certificate files again without dropping anyone.
func (r *Runtime) Reload(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg == nil {
		return errors.New("there is no config to run yet")
	}
	if r.cmd == nil {
		return r.startLocked(ctx)
	}
	return r.load(ctx, r.cfg)
}

// Close stops Caddy for good.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopping = true
	r.stopLocked()
	return nil
}

// Logs returns the tail of Caddy's output.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }

// Stats returns the traffic since the last call and who is connected now.
func (r *Runtime) Stats(ctx context.Context) (link.Stats, error) {
	r.mu.Lock()
	running := r.cmd != nil
	r.mu.Unlock()
	if !running {
		return link.Stats{}, errors.New("caddy is not running")
	}
	out, err := r.call(ctx, http.MethodPost, "/frostbite/usage", nil, nil)
	if err != nil {
		return link.Stats{}, err
	}
	var u usage
	if err := json.Unmarshal(out, &u); err != nil {
		return link.Stats{}, fmt.Errorf("unreadable usage: %w", err)
	}
	st := link.Stats{Users: u.Users, Online: map[string][]string{}}
	for name, ips := range u.Online {
		st.Online[name] = ips
	}
	if st.Users == nil {
		st.Users = map[string]link.Usage{}
	}
	return st, nil
}

// lastLines keeps the tail of some output for an error message.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
