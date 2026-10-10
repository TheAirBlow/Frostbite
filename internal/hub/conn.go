package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"frostbite/internal/db"
	"frostbite/internal/link"
	"frostbite/internal/metrics"
)

// writeTimeout is how long one write to a daemon may take.
const writeTimeout = 10 * time.Second

// outQueueSize bounds how far behind a daemon may fall before we drop it.
const outQueueSize = 64

// maxFrame caps what a daemon may send in one message.
const maxFrame = 8 << 20

// conn is one connected daemon.
type conn struct {
	daemon db.Daemon
	ws     *websocket.Conn
	out    chan []byte
	since  time.Time
	hello  link.Hello
}

// HashToken hashes a daemon token for storage and lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Handler accepts daemon connections.
func (h *Hub) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			metrics.LinkRejected.WithLabelValues("missing_token").Inc()
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		d, err := h.q.GetDaemonByToken(r.Context(), HashToken(token))
		if err != nil {
			metrics.LinkRejected.WithLabelValues("unknown_token").Inc()
			http.Error(w, "unknown token", http.StatusUnauthorized)
			return
		}

		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			metrics.LinkRejected.WithLabelValues("upgrade_failed").Inc()
			slog.Warn("hub: websocket upgrade failed", "daemon", d.ID, "err", err)
			return
		}
		ws.SetReadLimit(maxFrame)
		h.serve(d, ws)
	})
}

// serve runs one daemon connection until it drops.
func (h *Hub) serve(d db.Daemon, ws *websocket.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &conn{daemon: d, ws: ws, out: make(chan []byte, outQueueSize), since: time.Now()}
	go c.writeLoop(ctx, cancel, h.cfg.PingInterval)

	if err := h.handshake(ctx, c); err != nil {
		metrics.LinkRejected.WithLabelValues("handshake_failed").Inc()
		slog.Warn("hub: handshake failed", "daemon", d.ID, "err", err)
		ws.Close(websocket.StatusPolicyViolation, "handshake failed")
		return
	}

	h.mu.Lock()
	if old := h.conns[d.ID]; old != nil {
		old.ws.Close(websocket.StatusGoingAway, "replaced by a newer connection")
	}
	h.conns[d.ID] = c
	h.mu.Unlock()
	slog.Info("hub: daemon connected", "daemon", d.ID, "kind", d.Kind, "core", c.hello.CoreVer)
	metrics.LinkConnections.WithLabelValues(d.Kind).Inc()

	if err := h.Rebuild(ctx, d.ID); err != nil {
		slog.Error("hub: initial push failed", "daemon", d.ID, "err", err)
	}

	err := h.readLoop(ctx, c)
	if !errors.Is(err, context.Canceled) {
		slog.Info("hub: daemon disconnected", "daemon", d.ID, "err", err)
	}

	metrics.LinkDisconnections.WithLabelValues(d.Kind).Inc()
	metrics.LinkSessionSeconds.WithLabelValues(d.Kind).Observe(time.Since(c.since).Seconds())
	h.mu.Lock()
	if h.conns[d.ID] == c {
		delete(h.conns, d.ID)
		delete(h.metrics, d.ID)
		delete(h.certs, d.ID)
		h.dropOnline(d.ID)
	}
	h.mu.Unlock()
	ws.CloseNow()
}

// handshake waits for the hello and records what the daemon told us.
func (h *Hub) handshake(ctx context.Context, c *conn) error {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, data, err := c.ws.Read(rctx)
	if err != nil {
		return err
	}
	m, err := link.Decode(data)
	if err != nil {
		return err
	}
	if m.Type != link.TypeHello {
		return errors.New("first message was not hello")
	}
	if err := decodeBody(m, &c.hello); err != nil {
		return err
	}
	if c.hello.Kind != c.daemon.Kind {
		return errors.New("daemon kind does not match: token belongs to " + c.daemon.Kind)
	}

	info, _ := encodeJSON(c.hello.Host)
	return h.q.SetDaemonHello(ctx, db.SetDaemonHelloParams{
		ID: c.daemon.ID, CoreVersion: c.hello.CoreVer, AgentVersion: c.hello.AgentVer, HostInfo: info,
	})
}

// writeLoop drains the outgoing queue and keeps the link alive with pings.
func (c *conn) writeLoop(ctx context.Context, cancel context.CancelFunc, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case b := <-c.out:
			wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Write(wctx, websocket.MessageText, b)
			wcancel()
			if err != nil {
				cancel()
				c.ws.CloseNow()
				return
			}
		case <-tick.C:
			pctx, pcancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Ping(pctx)
			pcancel()
			if err != nil {
				cancel()
				c.ws.CloseNow()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// send queues a frame, dropping the connection if the daemon cannot keep up.
func (c *conn) send(typ string, body any) {
	b, err := link.Encode(typ, body)
	if err != nil {
		slog.Error("hub: encode failed", "type", typ, "err", err)
		return
	}
	select {
	case c.out <- b:
		metrics.LinkMessagesOut.WithLabelValues(c.daemon.Kind, typ).Inc()
		metrics.LinkBytesOut.WithLabelValues(c.daemon.Kind).Add(float64(len(b)))
	default:
		metrics.LinkDropped.WithLabelValues(c.daemon.Kind).Inc()
		slog.Warn("hub: daemon is not keeping up, dropping link", "daemon", c.daemon.ID)
		c.ws.CloseNow()
	}
}

// readLoop handles everything a daemon sends after the hello.
func (h *Hub) readLoop(ctx context.Context, c *conn) error {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return err
		}
		metrics.LinkBytesIn.WithLabelValues(c.daemon.Kind).Add(float64(len(data)))
		m, err := link.Decode(data)
		if err != nil {
			metrics.LinkBadFrames.WithLabelValues(c.daemon.Kind).Inc()
			slog.Warn("hub: bad frame", "daemon", c.daemon.ID, "err", err)
			continue
		}
		metrics.LinkMessagesIn.WithLabelValues(c.daemon.Kind, m.Type).Inc()
		h.handle(ctx, c, m)
	}
}

// handle dispatches one message from a daemon.
func (h *Hub) handle(ctx context.Context, c *conn, m link.Message) {
	switch m.Type {
	case link.TypeAck:
		var a link.Ack
		if decodeBody(m, &a) != nil {
			return
		}
		if err := h.q.SetDaemonApplied(ctx, db.SetDaemonAppliedParams{ID: c.daemon.ID, AppliedRev: a.Revision, LastError: a.Error}); err != nil {
			slog.Error("hub: saving ack failed", "daemon", c.daemon.ID, "err", err)
		}
		result := "applied"
		if a.Error != "" {
			result = "rejected"
		}
		metrics.SpecAcks.WithLabelValues(c.daemon.Kind, result).Inc()
		if a.Error != "" {
			slog.Warn("hub: daemon rejected spec", "daemon", c.daemon.ID, "rev", a.Revision, "err", a.Error)
		}
	case link.TypeStats:
		var s link.Stats
		if decodeBody(m, &s) == nil {
			metrics.DaemonReports.WithLabelValues(c.daemon.Kind, "stats").Inc()
			h.ingest(ctx, c.daemon, s)
		}
	case link.TypeMetrics:
		var mt link.Metrics
		if decodeBody(m, &mt) == nil {
			metrics.DaemonReports.WithLabelValues(c.daemon.Kind, "metrics").Inc()
			h.mu.Lock()
			h.metrics[c.daemon.ID] = sample{Metrics: mt, At: time.Now()}
			h.mu.Unlock()
			_ = h.q.TouchDaemon(ctx, c.daemon.ID)
		}
	case link.TypeCerts:
		var list []link.CertStatus
		if decodeBody(m, &list) == nil {
			h.mu.Lock()
			h.certs[c.daemon.ID] = list
			h.mu.Unlock()
		}
	case link.TypeResult:
		var r link.Result
		if decodeBody(m, &r) != nil {
			return
		}
		h.mu.Lock()
		ch := h.waiters[r.ID]
		delete(h.waiters, r.ID)
		h.mu.Unlock()
		if ch != nil {
			ch <- r
		}
	}
}

// push sends a spec to a daemon if it is connected.
func (h *Hub) push(daemonID int64, sp link.Spec) {
	h.mu.RLock()
	c := h.conns[daemonID]
	h.mu.RUnlock()
	if c != nil {
		metrics.SpecPushes.WithLabelValues(c.daemon.Kind).Inc()
		c.send(link.TypeSpec, sp)
	}
}

// Kick drops a daemon's connection, for example after it was disabled or its token rotated.
func (h *Hub) Kick(daemonID int64) {
	h.mu.RLock()
	c := h.conns[daemonID]
	h.mu.RUnlock()
	if c != nil {
		c.ws.Close(websocket.StatusPolicyViolation, "kicked")
	}
}
