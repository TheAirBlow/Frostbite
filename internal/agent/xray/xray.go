// Package xray runs xray-core as a supervised subprocess and talks to it over its API.
package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"frostbite/internal/agent/logs"
	corex "frostbite/internal/core/xray"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// apiAddr is where xray's api inbound listens, see the renderer.
var apiAddr = fmt.Sprintf("127.0.0.1:%d", corex.APIPort)

// Runtime runs xray-core.
type Runtime struct {
	bin     string
	dataDir string

	mu       sync.Mutex
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	current  *spec.Daemon
	logs     *logs.Ring
	stopping bool
}

// New creates a runtime. bin is the xray executable, dataDir holds its config.
func New(bin, dataDir string) *Runtime {
	return &Runtime{bin: bin, dataDir: dataDir, logs: logs.NewRing(2000)}
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "xray" }

// CoreVersion asks the binary which version it is.
func (r *Runtime) CoreVersion() string {
	out, err := exec.Command(r.bin, "version").Output()
	if err != nil {
		return "unknown"
	}
	first, _, _ := strings.Cut(string(out), "\n")
	if i := strings.Index(first, "("); i > 0 {
		first = first[:i]
	}
	return strings.TrimSpace(first)
}

// configPath is where the rendered config is written.
func (r *Runtime) configPath() string { return filepath.Join(r.dataDir, "xray.json") }

// Apply brings xray in line with d, touching only the users when only the users changed.
func (r *Runtime) Apply(ctx context.Context, d spec.Daemon, rendered []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cmd != nil && r.current != nil && spec.SameShape(*r.current, d) {
		if err := r.syncUsers(*r.current, d); err == nil {
			if err := os.WriteFile(r.configPath(), rendered, 0o600); err != nil {
				slog.Warn("could not save the config", "err", err)
			}
			cp := d
			r.current = &cp
			return nil
		} else {
			slog.Warn("hot user update failed, restarting xray instead", "err", err)
		}
	}

	if err := r.check(ctx, rendered); err != nil {
		return err
	}
	if err := os.WriteFile(r.configPath(), rendered, 0o600); err != nil {
		return err
	}
	if err := r.restartLocked(); err != nil {
		return err
	}
	cp := d
	r.current = &cp
	return nil
}

// check has xray validate a config before it replaces the running one.
func (r *Runtime) check(ctx context.Context, rendered []byte) error {
	tmp := filepath.Join(r.dataDir, "xray.next.json")
	if err := os.WriteFile(tmp, rendered, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, "run", "-test", "-c", tmp)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("xray rejected the config: %s", lastLines(out.String(), 6))
	}
	return nil
}

// syncUsers adds and removes users through the api, inbound by inbound.
func (r *Runtime) syncUsers(old, next spec.Daemon) error {
	oldUsers := map[string]map[string]spec.User{}
	for _, in := range old.Inbounds {
		m := map[string]spec.User{}
		for _, u := range in.Users {
			m[u.Name] = u
		}
		oldUsers[in.Tag] = m
	}

	for _, in := range next.Inbounds {
		have := oldUsers[in.Tag]
		want := map[string]bool{}
		var add []spec.User
		for _, u := range in.Users {
			want[u.Name] = true
			if prev, ok := have[u.Name]; !ok {
				add = append(add, u)
			} else if prev != u {
				// credentials changed: drop the old one first, then add the new
				if err := r.api("rmu", "-tag="+in.Tag, u.Name); err != nil {
					return err
				}
				add = append(add, u)
			}
		}

		var gone []string
		for name := range have {
			if !want[name] {
				gone = append(gone, name)
			}
		}
		if len(gone) > 0 {
			if err := r.api(append([]string{"rmu", "-tag=" + in.Tag}, gone...)...); err != nil {
				return err
			}
		}
		if len(add) > 0 {
			if err := r.addUsers(in, add); err != nil {
				return err
			}
		}
	}
	return nil
}

// addUsers pushes users into a running inbound.
func (r *Runtime) addUsers(in spec.Inbound, users []spec.User) error {
	in.Users = users
	full, err := corex.Inbound(in)
	if err != nil {
		return err
	}
	// xray's config parser insists on a port even though the inbound already exists
	doc := map[string]any{"inbounds": []any{map[string]any{
		"tag": full["tag"], "protocol": full["protocol"], "port": full["port"], "listen": full["listen"], "settings": full["settings"],
	}}}
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(r.dataDir, "adu-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	tmp.Close()

	// adu exits 0 even when it added nobody, so the summary line is the only honest answer
	out, err := r.apiOut("adu", tmp.Name())
	if err != nil {
		return err
	}
	var added int
	if i := strings.LastIndex(string(out), "Added "); i >= 0 {
		fmt.Sscanf(string(out)[i:], "Added %d user(s)", &added)
	}
	if added != len(users) {
		return fmt.Errorf("xray added %d of %d users: %s", added, len(users), lastLines(string(out), 3))
	}
	return nil
}

// api runs an `xray api` subcommand against the running core.
func (r *Runtime) api(args ...string) error {
	_, err := r.apiOut(args...)
	return err
}

// apiOut runs an `xray api` subcommand and returns what it printed.
func (r *Runtime) apiOut(args ...string) ([]byte, error) {
	full := append([]string{"api", args[0], "-s", apiAddr}, args[1:]...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, full...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("xray api %s: %v: %s", args[0], err, lastLines(errOut.String()+out.String(), 4))
	}
	return out.Bytes(), nil
}

// restartLocked starts xray from the saved config, replacing any running instance. The caller holds the lock.
func (r *Runtime) restartLocked() error {
	r.stopLocked()
	r.stopping = false

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, r.bin, "run", "-c", r.configPath())
	cmd.Stdout, cmd.Stderr = r.logs, r.logs
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("starting xray: %w", err)
	}
	r.cmd, r.cancel = cmd, cancel
	slog.Info("xray started", "pid", cmd.Process.Pid)

	go r.watch(cmd)
	return nil
}

// watch restarts xray if it dies on its own.
func (r *Runtime) watch(cmd *exec.Cmd) {
	err := cmd.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != cmd || r.stopping {
		return
	}
	slog.Error("xray exited unexpectedly", "err", err)
	r.cmd = nil
	go func() {
		time.Sleep(3 * time.Second)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.cmd == nil && !r.stopping {
			if err := r.restartLocked(); err != nil {
				slog.Error("restarting xray failed", "err", err)
			}
		}
	}()
}

// stopLocked stops the running instance. The caller holds the lock.
func (r *Runtime) stopLocked() {
	if r.cmd == nil {
		return
	}
	cmd := r.cmd
	r.cmd = nil
	r.cancel()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	}
}

// Restart restarts the core with the current config.
func (r *Runtime) Restart(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := os.Stat(r.configPath()); err != nil {
		return errors.New("there is no config to run yet")
	}
	return r.restartLocked()
}

// Close stops xray for good.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopping = true
	r.stopLocked()
	return nil
}

// Logs returns the tail of xray's output.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }

// statsDoc is what `xray api statsquery` prints.
type statsDoc struct {
	Stat []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"stat"`
}

// Stats reads and resets per user counters, and lists who is online.
func (r *Runtime) Stats(ctx context.Context) (link.Stats, error) {
	r.mu.Lock()
	running := r.cmd != nil
	r.mu.Unlock()
	if !running {
		return link.Stats{}, errors.New("xray is not running")
	}

	out, err := r.apiOut("statsquery", "-pattern", "user>>>", "-reset=true")
	if err != nil {
		return link.Stats{}, err
	}
	var doc statsDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return link.Stats{}, fmt.Errorf("unreadable stats: %w", err)
	}

	st := link.Stats{Users: map[string]link.Usage{}}
	for _, s := range doc.Stat {
		// user>>>NAME>>>traffic>>>uplink
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			continue
		}
		n := toInt(s.Value)
		if n == 0 {
			continue
		}
		u := st.Users[parts[1]]
		if parts[3] == "uplink" {
			u.Up += n
		} else {
			u.Down += n
		}
		st.Users[parts[1]] = u
	}

	st.Online = r.online()
	return st, nil
}

// online lists the source addresses of connected users.
func (r *Runtime) online() map[string][]string {
	out, err := r.apiOut("statsgetallonlineusers")
	if err != nil {
		return nil
	}
	var doc struct {
		Users []string `json:"users"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return nil
	}

	res := map[string][]string{}
	for _, full := range doc.Users {
		parts := strings.Split(full, ">>>")
		if len(parts) < 2 {
			continue
		}
		ipsOut, err := r.apiOut("statsonlineiplist", "-email", parts[1])
		if err != nil {
			continue
		}
		var ips struct {
			IPs map[string]any `json:"ips"`
		}
		if json.Unmarshal(ipsOut, &ips) != nil {
			continue
		}
		for ip := range ips.IPs {
			res[parts[1]] = append(res[parts[1]], ip)
		}
		if len(res[parts[1]]) == 0 {
			res[parts[1]] = []string{}
		}
	}
	return res
}

// toInt reads a counter that xray prints as either a number or a string.
func toInt(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		var n int64
		fmt.Sscanf(t, "%d", &n)
		return n
	}
	return 0
}

// lastLines keeps the tail of command output for error messages.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
