package gate

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"

	"frostbite/internal/agent/egress"
)

func init() { caddy.RegisterModule(&Egress{}) }

var (
	egressOnce sync.Once
	egressOut  *egress.Egress
)

// shared is the egress every gate tunnels through. It outlives config reloads, so one that keeps the egress config
// keeps every tunnel too.
func shared() *egress.Egress {
	egressOnce.Do(func() {
		egressOut = egress.New(func(level, msg string) {
			_, _ = fmt.Fprintf(sinkWriter{}, "%s\t%s\tegress\t%s\n", time.Now().Format("2006/01/02 15:04:05.000"), level, msg)
		})
	})
	return egressOut
}

// CloseEgress stops the egress for good.
func CloseEgress() { _ = shared().Close() }

// EgressError says why the egress config Caddy runs has not started, nil once it has.
func EgressError() error { return shared().Err() }

// Egress is the Caddy app that holds the egress config, a sing-box config with no inbounds.
type Egress struct{ raw []byte }

// CaddyModule returns the module information.
func (*Egress) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "frostbite_egress", New: func() caddy.Module { return new(Egress) }}
}

// UnmarshalJSON keeps the config as it is, for sing-box to read.
func (e *Egress) UnmarshalJSON(b []byte) error {
	e.raw = bytes.Clone(b)
	return nil
}

// Start runs the config, which changes nothing when it is the one running already. A config that fails to start does
// not fail Caddy, so the site stays up while the egress retries; EgressError reports it.
func (e *Egress) Start() error {
	_ = shared().Apply(e.raw)
	return nil
}

// Stop leaves the egress running: the config that replaces this one has started by now, and Close ends it for good.
func (e *Egress) Stop() error { return nil }

var _ caddy.App = (*Egress)(nil)
