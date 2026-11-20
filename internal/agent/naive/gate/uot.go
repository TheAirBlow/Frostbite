package gate

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/uot"
)

// paddingFrames is how many frames of a NaiveProxy tunnel carry padding in each direction.
const paddingFrames = 8

// ACLRule decides whether a destination is allowed. Rules are checked in order and the first match wins.
type ACLRule struct {
	Subjects []string `json:"subjects,omitempty"`
	Allow    bool     `json:"allow,omitempty"`
}

// acl decides which addresses UDP packets may be sent to. forwardproxy applies the same rules to TCP.
type acl []aclEntry

type aclEntry struct {
	all    bool
	prefix netip.Prefix
	allow  bool
}

func newACL(rules []ACLRule) acl {
	var out acl
	for _, r := range rules {
		for _, s := range r.Subjects {
			switch {
			case s == "all":
				out = append(out, aclEntry{all: true, allow: r.Allow})
			default:
				if p, err := netip.ParsePrefix(s); err == nil {
					out = append(out, aclEntry{prefix: p, allow: r.Allow})
				} else if a, err := netip.ParseAddr(s); err == nil {
					out = append(out, aclEntry{prefix: netip.PrefixFrom(a, a.BitLen()), allow: r.Allow})
				}
				// names cannot be matched here, a packet only carries an address
			}
		}
	}
	return out
}

// allowed reports whether packets may go to ip. Without a matching rule, only public addresses are allowed.
func (a acl) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, e := range a {
		if e.all || e.prefix.Contains(ip) {
			return e.allow
		}
	}
	return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified())
}

// filteredConn drops packets to addresses the rules refuse.
type filteredConn struct {
	net.PacketConn
	rules acl
}

func (c filteredConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if u, ok := addr.(*net.UDPAddr); ok {
		if ip, ok := netip.AddrFromSlice(u.IP); !ok || !c.rules.allowed(ip) {
			return len(b), nil
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

// uotVersion says which UDP over TCP protocol a CONNECT target asks for, 0 when it is an ordinary target.
func uotVersion(r *http.Request) int {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch strings.ToLower(host) {
	case uot.MagicAddress:
		return uot.Version
	case uot.LegacyMagicAddress:
		return uot.LegacyVersion
	}
	return 0
}

// serveUoT answers a CONNECT to the UDP over TCP address: the tunnel carries UDP packets, which are sent from here.
func (g *Gate) serveUoT(w http.ResponseWriter, r *http.Request, version int) error {
	w.Header().Set("Padding", paddingHeader())
	w.WriteHeader(http.StatusOK)

	var s *stream
	if r.ProtoMajor >= 2 {
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			return err
		}
		s = &stream{r: r.Body, write: func(p []byte) error {
			if _, err := w.Write(p); err != nil {
				return err
			}
			return rc.Flush()
		}, pad: r.Header.Get("Padding") != ""}
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
		s = &stream{r: io.MultiReader(bytes.NewReader(cached), conn), write: func(p []byte) error {
			_, err := conn.Write(p)
			return err
		}}
	}

	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	packets := uot.NewServerConn(filteredConn{pc, g.udpRules}, version)
	defer packets.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(packets, s); done <- struct{}{} }()
	go func() { _, _ = io.Copy(s, packets); done <- struct{}{} }()
	<-done
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
}

func (s *stream) Read(p []byte) (int, error) {
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
