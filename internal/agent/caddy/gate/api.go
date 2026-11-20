package gate

import (
	"io"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

func init() { caddy.RegisterModule(LogWriter{}) }

// Replace makes the users of an inbound exactly creds and cuts every tunnel of a user that is gone or whose password
// changed. It returns how many tunnels it cut.
func Replace(inbound string, creds []Credential) int { return registry.replace(inbound, creds) }

// CutAll ends every tunnel, keeping the users.
func CutAll() {
	registry.mu.Lock()
	all := make([]*session, 0, len(registry.sessions))
	for s := range registry.sessions {
		all = append(all, s)
	}
	registry.mu.Unlock()
	for _, s := range all {
		s.kick()
	}
}

// Drain returns the traffic since the previous call and lists who is connected.
func Drain() Report { return registry.drain() }

var (
	sinkMu sync.Mutex
	sink   io.Writer
)

// SetLogSink sends what Caddy logs to w, which lets the agent keep it for the panel.
func SetLogSink(w io.Writer) {
	sinkMu.Lock()
	sink = w
	sinkMu.Unlock()
}

// LogWriter is the log output that feeds the sink.
type LogWriter struct{}

// CaddyModule returns the module information.
func (LogWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.logging.writers.frostbite", New: func() caddy.Module { return new(LogWriter) }}
}

// String names the output.
func (LogWriter) String() string { return "frostbite" }

// WriterKey identifies the output, so a reload keeps it.
func (LogWriter) WriterKey() string { return "frostbite" }

// OpenWriter returns the writer Caddy logs to.
func (LogWriter) OpenWriter() (io.WriteCloser, error) { return sinkWriter{}, nil }

type sinkWriter struct{}

func (sinkWriter) Write(p []byte) (int, error) {
	sinkMu.Lock()
	w := sink
	sinkMu.Unlock()
	if w == nil {
		return len(p), nil
	}
	return w.Write(p)
}

func (sinkWriter) Close() error { return nil }
