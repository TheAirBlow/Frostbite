package gate

import (
	"bytes"
	"context"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"frostbite/internal/agent/egress"
)

// paddingFrames is how many frames of a NaiveProxy tunnel carry padding in each direction.
const paddingFrames = 8

// serveConnect answers a CONNECT and hands the tunnel to the egress, which routes it to the target. A target that
// names the UDP over TCP address gets its packets sent on by the egress too.
func serveConnect(w http.ResponseWriter, r *http.Request, t *tunnel, m egress.Meta) error {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	m.Destination = M.ParseSocksaddr(host)
	w.Header().Set("Padding", paddingHeader())
	w.WriteHeader(http.StatusOK)

	s := &stream{local: t.localAddr(), remote: m.Source}
	if r.ProtoMajor >= 2 {
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			return err
		}
		s.r, s.pad, s.soft = r.Body, r.Header.Get("Padding") != "", true
		s.write = func(p []byte) error {
			if _, err := w.Write(p); err != nil {
				return err
			}
			return rc.Flush()
		}
		// an HTTP/2 stream ends for good when a deadline passes, so the tunnel keeps its own instead
		s.close, s.readDeadline, s.writeDeadline = t.end, s.setSoftDeadline, func(time.Time) error { return nil }
	} else {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := rw.Flush(); err != nil {
			return err
		}
		var cached []byte
		if n := rw.Reader.Buffered(); n > 0 {
			cached, _ = rw.Peek(n)
			cached = bytes.Clone(cached)
		}
		s.r = io.MultiReader(bytes.NewReader(cached), conn)
		s.write = func(p []byte) error {
			_, err := conn.Write(p)
			return err
		}
		s.close, s.readDeadline, s.writeDeadline = func() { _ = conn.Close() }, conn.SetReadDeadline, conn.SetWriteDeadline
	}
	_ = shared().RouteConn(r.Context(), s, m)
	return nil
}

var discardLog = log.New(io.Discard, "", 0)

// serveForward passes a request for an absolute URL on to its server through the egress, as a plain HTTP proxy does.
func serveForward(w http.ResponseWriter, r *http.Request, m egress.Meta) error {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			m := m
			m.Destination = M.ParseSocksaddr(address)
			return shared().Dial(ctx, m)
		},
		DisableCompression: true,
	}
	defer tr.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      discardLog,
	}
	proxy.ServeHTTP(w, r)
	return nil
}

// stream is a CONNECT tunnel as a connection, with the padding NaiveProxy puts on the first frames of each direction.
type stream struct {
	r       io.Reader
	write   func([]byte) error
	pad     bool
	mu      sync.Mutex
	wframes int

	frames int // frames read so far
	remain int // payload bytes left in the current frame
	skip   int // padding bytes left after it

	local, remote               net.Addr
	close                       func()
	readDeadline, writeDeadline func(time.Time) error

	// soft deadlines let a read give up without ending the tunnel. The read goes on, and what it brings is handed out
	// by the next one.
	soft     bool
	deadline atomic.Pointer[time.Time]
	inflight chan readResult
	held     []byte
	heldErr  error
}

type readResult struct {
	b   []byte
	err error
}

func (s *stream) setSoftDeadline(t time.Time) error {
	if t.IsZero() {
		s.deadline.Store(nil)
	} else {
		s.deadline.Store(&t)
	}
	return nil
}

func (s *stream) Read(p []byte) (int, error) {
	if !s.soft {
		return s.readFrames(p)
	}
	for {
		if len(s.held) > 0 || s.heldErr != nil {
			n := copy(p, s.held)
			s.held = s.held[n:]
			if n > 0 {
				return n, nil
			}
			err := s.heldErr
			s.heldErr = nil
			return 0, err
		}
		d := s.deadline.Load()
		if s.inflight == nil {
			if d == nil {
				return s.readFrames(p)
			}
			ch, buf := make(chan readResult, 1), make([]byte, len(p))
			go func() {
				n, err := s.readFrames(buf)
				ch <- readResult{buf[:n], err}
			}()
			s.inflight = ch
		}
		var expired <-chan time.Time
		var timer *time.Timer
		if d != nil {
			timer = time.NewTimer(time.Until(*d))
			expired = timer.C
		}
		select {
		case r := <-s.inflight:
			s.inflight, s.held, s.heldErr = nil, r.b, r.err
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// readFrames reads the payload, dropping the padding of the first frames.
func (s *stream) readFrames(p []byte) (int, error) {
	for {
		if s.remain > 0 {
			n, err := s.r.Read(p[:min(len(p), s.remain)])
			s.remain -= n
			return n, err
		}
		if s.skip > 0 {
			if _, err := io.CopyN(io.Discard, s.r, int64(s.skip)); err != nil {
				return 0, err
			}
			s.skip = 0
		}
		if !s.pad || s.frames >= paddingFrames {
			return s.r.Read(p)
		}
		var head [3]byte
		if _, err := io.ReadFull(s.r, head[:]); err != nil {
			return 0, err
		}
		s.frames++
		s.remain, s.skip = int(head[0])<<8|int(head[1]), int(head[2])
	}
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk, out := p, p
		if s.pad && s.wframes < paddingFrames {
			chunk = p[:min(len(p), 65535)]
			padding := rand.Intn(256)
			out = make([]byte, 3+len(chunk)+padding)
			out[0], out[1], out[2] = byte(len(chunk)>>8), byte(len(chunk)), byte(padding)
			copy(out[3:], chunk)
			s.wframes++
		}
		if err := s.write(out); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (s *stream) Close() error {
	s.close()
	return nil
}

func (s *stream) LocalAddr() net.Addr  { return orNone(s.local) }
func (s *stream) RemoteAddr() net.Addr { return orNone(s.remote) }

func (s *stream) SetDeadline(t time.Time) error {
	_ = s.writeDeadline(t)
	return s.readDeadline(t)
}

func (s *stream) SetReadDeadline(t time.Time) error  { return s.readDeadline(t) }
func (s *stream) SetWriteDeadline(t time.Time) error { return s.writeDeadline(t) }

func orNone(a net.Addr) net.Addr {
	if a == nil {
		return &net.TCPAddr{}
	}
	return a
}

// paddingHeader is the random filler a NaiveProxy server answers with.
func paddingHeader() string {
	n := rand.Intn(32) + 30
	padding := make([]byte, n)
	bits := rand.Uint64()
	for i := range 16 {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < n; i++ {
		padding[i] = '~'
	}
	return string(padding)
}
