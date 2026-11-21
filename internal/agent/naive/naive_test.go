package naive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"golang.org/x/net/http2"

	"frostbite/internal/agent/naive/gate"
	corenaive "frostbite/internal/core/naive"
	"frostbite/internal/spec"
)

func writeCert(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kder, _ := x509.MarshalECPrivateKey(k)
	cert, key = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	return cert, key
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// site records what the proxy sends it.
type site struct {
	*httptest.Server
	mu   sync.Mutex
	seen []http.Header
}

func newSite(t *testing.T) *site {
	s := &site{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Header.Clone())
		s.mu.Unlock()
		fmt.Fprint(w, "the real site")
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *site) last() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[len(s.seen)-1]
}

func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

type fixture struct {
	rt   *Runtime
	d    spec.Daemon
	addr string
	echo string
}

func newFixture(t *testing.T, tune func(*spec.Inbound)) *fixture {
	t.Helper()
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	f := &fixture{rt: New(), echo: echoServer(t)}
	t.Cleanup(func() { f.rt.Close() })

	f.addr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	host, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	in := spec.Inbound{
		Tag: "naive", Protocol: spec.ProtoNaive, Listen: host, Port: p,
		Security: spec.Security{Type: spec.SecurityTLS, CertPath: cert, KeyPath: key},
		Options:  spec.Options{NaiveDest: "127.0.0.1:1"},
		Users:    []spec.User{{Name: "u1", Password: "pw1"}},
	}
	if tune != nil {
		tune(&in)
	}
	f.d = spec.Daemon{
		Kind: "naive", Inbounds: []spec.Inbound{in}, Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}}, Final: "direct",
		// the echo server is on loopback, which the daemon refuses unless a rule says otherwise
		Rules: []spec.Rule{{IPCIDR: []string{"127.0.0.1/32"}, Outbound: "direct"}},
	}
	f.apply(t)
	return f
}

func (f *fixture) apply(t *testing.T) {
	t.Helper()
	if err := f.d.Validate(); err != nil {
		t.Fatal(err)
	}
	rendered, err := corenaive.Render(f.d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.rt.Apply(ctx, f.d, rendered); err != nil {
		t.Fatalf("apply: %v\n%s", err, f.rt.Logs(20))
	}
}

func (f *fixture) setUsers(t *testing.T, users ...spec.User) {
	f.d.Inbounds[0].Users = users
	f.apply(t)
}

func basic(name, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+pass))
}

func (f *fixture) get(t *testing.T) string {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Get("https://" + f.addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// tunnel opens a CONNECT to the echo server.
func (f *fixture) tunnel(t *testing.T, name, pass string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", f.echo, f.echo, basic(name, pass))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("connect as %s: %s", name, resp.Status)
	}
	return c, br
}

func echoOnce(c net.Conn, br *bufio.Reader, msg string) error {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(c, msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		return err
	}
	if string(got) != msg {
		return fmt.Errorf("got %q", got)
	}
	return nil
}

func TestHotUsersAndKick(t *testing.T) {
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })

	if got := f.get(t); got != "the real site" {
		t.Fatalf("a visitor got %q", got)
	}
	c1, br1 := f.tunnel(t, "u1", "pw1")
	if err := echoOnce(c1, br1, "hello"); err != nil {
		t.Fatal(err)
	}

	// a user added later does not disturb the one connected
	f.setUsers(t, spec.User{Name: "u1", Password: "pw1"}, spec.User{Name: "u2", Password: "pw2"})
	if err := echoOnce(c1, br1, "still"); err != nil {
		t.Fatalf("adding a user dropped u1: %v", err)
	}
	c2, br2 := f.tunnel(t, "u2", "pw2")
	if err := echoOnce(c2, br2, "new"); err != nil {
		t.Fatal(err)
	}

	st, err := f.rt.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u := st.Users["u1"]; u.Up < 10 || u.Down < 10 {
		t.Errorf("u1 usage %+v", u)
	}
	if len(st.Online["u1"]) != 1 || len(st.Online["u2"]) != 1 {
		t.Errorf("online %v", st.Online)
	}

	// deleting u1 cuts u1 and nobody else, after u1 sent a last bit that nobody has collected yet
	if err := echoOnce(c1, br1, "last"); err != nil {
		t.Fatal(err)
	}
	f.setUsers(t, spec.User{Name: "u2", Password: "pw2"})
	if err := echoOnce(c1, br1, "gone"); err == nil {
		t.Error("u1 stayed connected after being deleted")
	}
	if err := echoOnce(c2, br2, "fine"); err != nil {
		t.Errorf("deleting u1 dropped u2: %v", err)
	}
	st, _ = f.rt.Stats(context.Background())
	if st.Users["u1"].Up == 0 {
		t.Errorf("the last traffic of the deleted user was lost: %v", st.Users)
	}
	if len(st.Online["u1"]) != 0 {
		t.Errorf("u1 is still online: %v", st.Online)
	}
}

func TestChangingTheConfigKeepsTunnels(t *testing.T) {
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })
	c, br := f.tunnel(t, "u1", "pw1")
	if err := echoOnce(c, br, "a"); err != nil {
		t.Fatal(err)
	}

	f.d.Inbounds[0].Options.NaiveHeader = "X-Real-IP"
	f.apply(t)
	if err := echoOnce(c, br, "b"); err != nil {
		t.Fatalf("a config change dropped a tunnel: %v", err)
	}
	f.get(t)
	if got := s.last().Get("X-Real-IP"); got != "127.0.0.1" {
		t.Errorf("X-Real-IP = %q", got)
	}
	if got := s.last().Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For = %q, the site reads another header", got)
	}

	f.d.Inbounds[0].Options.NaiveHeader = spec.NaiveNoHeader
	f.apply(t)
	f.get(t)
	h := s.last()
	if h.Get("X-Real-IP") != "" || h.Get("X-Forwarded-For") != "" {
		t.Errorf("an address header was sent: %v", h)
	}
	if err := f.rt.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(c, br, "c"); err != nil {
		t.Fatalf("a reload dropped a tunnel: %v", err)
	}
}

func TestStrangersAndProbes(t *testing.T) {
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })

	c, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", f.echo, f.echo, basic("u1", "wrong"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 407 || resp.Header.Get("Proxy-Authenticate") != "" {
		t.Errorf("a wrong password revealed a proxy: %s %v", resp.Status, resp.Header)
	}
	if resp.Header.Get("Via") != "" {
		t.Errorf("Via gave the reverse proxy away: %v", resp.Header)
	}
	if got := s.last().Get("Proxy-Authorization"); got != "" {
		t.Errorf("the site saw proxy credentials: %q", got)
	}
}

// proxyV2 builds a PROXY protocol v2 header for a TCP connection.
func proxyV2(src, dst string) []byte {
	sa, da := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	var b bytes.Buffer
	b.Write([]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C})
	b.Write(sa)
	b.Write(da)
	_ = binary.Write(&b, binary.BigEndian, [2]uint16{40000, 443})
	return b.Bytes()
}

func TestRealAddressFromTheEdgeAndToTheSite(t *testing.T) {
	// a site that insists on a PROXY v2 header and says what address it carried
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				head := make([]byte, 16)
				if _, err := io.ReadFull(br, head); err != nil || !bytes.HasPrefix(head, []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51}) {
					got <- "no header"
					return
				}
				addr := make([]byte, 12)
				io.ReadFull(br, addr)
				got <- net.IP(addr[:4]).String()
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				got <- "xff=" + req.Header.Get("X-Forwarded-For")
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsite")
			}()
		}
	}()

	f := newFixture(t, func(in *spec.Inbound) {
		in.Options.NaiveDest = l.Addr().String()
		in.Options.NaiveProxy = "v2"
		in.Options.AcceptProxy = true
	})

	// the edge in front sends a header naming the visitor
	raw, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.Write(proxyV2("203.0.113.7", "127.0.0.1"))
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "site" {
		t.Fatalf("body %q", body)
	}
	select {
	case a := <-got:
		if a != "203.0.113.7" {
			t.Errorf("the site's PROXY header carried %q", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the site saw nothing")
	}
	if a := <-got; a != "xff=203.0.113.7" {
		t.Errorf("the site read %q", a)
	}
}

// tunnelH2 opens a CONNECT over HTTP/2, the way NaiveProxy does.
func (f *fixture) tunnelH2(t *testing.T, name, pass string) (*io.PipeWriter, io.ReadCloser) {
	t.Helper()
	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		return tls.Dial(n, a, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}}
	pr, pw := io.Pipe()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: f.addr}, Host: f.echo, Body: pr, Header: http.Header{"Proxy-Authorization": {basic(name, pass)}}}
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("h2 connect as %s: %v %v", name, resp, err)
	}
	return pw, resp.Body
}

func echoH2(w io.Writer, r io.Reader, msg string) error {
	if _, err := io.WriteString(w, msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(r, got); err != nil {
		return err
	}
	if string(got) != msg {
		return fmt.Errorf("got %q", got)
	}
	return nil
}

func TestH2UsersAndKick(t *testing.T) {
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })
	w1, r1 := f.tunnelH2(t, "u1", "pw1")
	if err := echoH2(w1, r1, "hello"); err != nil {
		t.Fatal(err)
	}

	f.setUsers(t, spec.User{Name: "u1", Password: "pw1"}, spec.User{Name: "u2", Password: "pw2"})
	if err := echoH2(w1, r1, "still"); err != nil {
		t.Fatalf("adding a user dropped u1: %v", err)
	}
	w2, r2 := f.tunnelH2(t, "u2", "pw2")
	if err := echoH2(w2, r2, "new"); err != nil {
		t.Fatal(err)
	}

	f.setUsers(t, spec.User{Name: "u2", Password: "pw2"})
	done := make(chan error, 1)
	go func() {
		for {
			if err := echoH2(w1, r1, "x"); err != nil {
				done <- err
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("u1 stayed connected after being deleted")
	}
	if err := echoH2(w2, r2, "fine"); err != nil {
		t.Errorf("deleting u1 dropped u2: %v", err)
	}

	st, _ := f.rt.Stats(context.Background())
	if st.Users["u1"].Up == 0 || st.Users["u2"].Down == 0 {
		t.Errorf("usage %v", st.Users)
	}
}

// proxyListener consumes the PROXY v2 header in front of each connection and reports the address it names.
type proxyListener struct {
	net.Listener
	from chan string
}

func (l proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	head := make([]byte, 16)
	if _, err := io.ReadFull(c, head); err != nil || !bytes.HasPrefix(head, []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51}) {
		l.from <- "no header"
		return c, nil
	}
	body := make([]byte, binary.BigEndian.Uint16(head[14:]))
	io.ReadFull(c, body)
	l.from <- net.IP(body[:4]).String()
	return c, nil
}

// A site behind HTTPS gets the visitor's host as server name, and the visitor's address in a PROXY header when asked.
func TestHTTPSSite(t *testing.T) {
	for _, proxy := range []string{"", "v2"} {
		t.Run("proxy="+proxy, func(t *testing.T) {
			sni, from := make(chan string, 4), make(chan string, 4)
			dir := t.TempDir()
			cert, key := writeCert(t, dir)
			pair, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var ln net.Listener = raw
			if proxy != "" {
				ln = proxyListener{raw, from}
			}
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "secure site "+r.Host+" xff="+r.Header.Get("X-Forwarded-For"))
			})}
			go srv.Serve(tls.NewListener(ln, &tls.Config{
				Certificates: []tls.Certificate{pair},
				GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
					sni <- h.ServerName
					return nil, nil
				},
			}))
			defer srv.Close()

			f := newFixture(t, func(in *spec.Inbound) {
				in.Options.NaiveDest = raw.Addr().String()
				in.Options.NaiveTLS = true
				in.Options.NaiveSkip = true
				in.Options.NaiveProxy = proxy
				in.Options.AcceptProxy = true
			})
			conn, err := net.Dial("tcp", f.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write(proxyV2("203.0.113.7", "127.0.0.1"))
			tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "vpn.example.test", NextProtos: []string{"http/1.1"}})
			fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: vpn.example.test\r\nConnection: close\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || string(body) != "secure site vpn.example.test xff=203.0.113.7" {
				t.Fatalf("got %d %q\n%s", resp.StatusCode, body, f.rt.Logs(20))
			}
			if got := <-sni; got != "vpn.example.test" {
				t.Errorf("the site saw server name %q", got)
			}
			if proxy != "" {
				if got := <-from; got != "203.0.113.7" {
					t.Errorf("the site's PROXY header named %q", got)
				}
			}
		})
	}
}

// udpEcho answers every packet with the same bytes.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// padded is the client end of a NaiveProxy tunnel, which pads the first frames in both directions.
type padded struct {
	net.Conn
	r             io.Reader
	reads, writes int
	remain, skip  int
}

func (p *padded) Read(b []byte) (int, error) {
	for {
		if p.remain > 0 {
			n, err := p.r.Read(b[:min(len(b), p.remain)])
			p.remain -= n
			return n, err
		}
		if p.skip > 0 {
			if _, err := io.CopyN(io.Discard, p.r, int64(p.skip)); err != nil {
				return 0, err
			}
			p.skip = 0
		}
		if p.reads >= 8 {
			return p.r.Read(b)
		}
		var h [3]byte
		if _, err := io.ReadFull(p.r, h[:]); err != nil {
			return 0, err
		}
		p.reads++
		p.remain, p.skip = int(h[0])<<8|int(h[1]), int(h[2])
	}
}

func (p *padded) Write(b []byte) (int, error) {
	if p.writes >= 8 {
		return p.Conn.Write(b)
	}
	p.writes++
	out := make([]byte, 3+len(b)+7)
	out[0], out[1], out[2] = byte(len(b)>>8), byte(len(b)), 7
	copy(out[3:], b)
	if _, err := p.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// uotDialer reaches the proxy's UDP over TCP address the way a NaiveProxy client does.
type uotDialer struct {
	f      *fixture
	t      *testing.T
	user   string
	pass   string
	legacy bool
}

func (d uotDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	conn, err := tls.Dial("tcp", d.f.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(conn, "CONNECT %s:0 HTTP/1.1\r\nHost: %s:0\r\nProxy-Authorization: %s\r\n\r\n", dest.Fqdn, dest.Fqdn, basic(d.user, d.pass))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("connect: %s", resp.Status)
	}
	return &bufConn{Conn: conn, r: br}, nil
}

func (d uotDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func TestUDPOverTCP(t *testing.T) {
	echo := udpEcho(t)
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })
	dest := M.SocksaddrFromNetIP(echo.AddrPort())

	for _, version := range []uint8{uot.Version, uot.LegacyVersion} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			client := &uot.Client{Dialer: uotDialer{f: f, t: t, user: "u1", pass: "pw1"}, Version: version}
			conn, err := client.DialContext(context.Background(), "udp", dest)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 16)
			n, err := conn.Read(got)
			if err != nil || string(got[:n]) != "ping" {
				t.Fatalf("got %q, %v\n%s", got[:n], err, f.rt.Logs(10))
			}
		})
	}

	st, _ := f.rt.Stats(context.Background())
	if st.Users["u1"].Up == 0 || st.Users["u1"].Down == 0 {
		t.Errorf("the packets were not counted: %v", st.Users)
	}
}

func TestUDPOverTCPPaddedH2(t *testing.T) {
	echo := udpEcho(t)
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })

	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		return tls.Dial(n, a, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}}
	pr, pw := io.Pipe()
	authority := uot.MagicAddress + ":0"
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: f.addr}, Host: authority, Body: pr,
		Header: http.Header{"Proxy-Authorization": {basic("u1", "pw1")}, "Padding": {"!#$()+<>?@[]^`{}~~~~~~~~~~~~~~~~~~~~~~~~~~"}}}
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", resp, err)
	}
	if resp.Header.Get("Padding") == "" {
		t.Error("the answer has no Padding header")
	}
	conn := &padded{Conn: pipeConn{pw, resp.Body}, r: resp.Body}
	client := uot.NewLazyConn(conn, uot.Request{IsConnect: true, Destination: M.SocksaddrFromNetIP(echo.AddrPort())})
	defer client.Close()

	// more than the padded frames, so the switch to plain data is covered
	for i := 0; i < 12; i++ {
		msg := fmt.Sprintf("packet %d", i)
		if _, err := client.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		n, err := client.Read(got)
		if err != nil || string(got[:n]) != msg {
			t.Fatalf("packet %d: got %q, %v", i, got[:n], err)
		}
	}
}

// pipeConn joins a request pipe and a response body into one connection.
type pipeConn struct {
	w *io.PipeWriter
	r io.ReadCloser
}

func (c pipeConn) Read(b []byte) (int, error)     { return c.r.Read(b) }
func (c pipeConn) Write(b []byte) (int, error)    { return c.w.Write(b) }
func (c pipeConn) Close() error                   { c.w.Close(); return c.r.Close() }
func (pipeConn) LocalAddr() net.Addr              { return nil }
func (pipeConn) RemoteAddr() net.Addr             { return nil }
func (pipeConn) SetDeadline(time.Time) error      { return nil }
func (pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (pipeConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPToPrivateAddressesIsDropped(t *testing.T) {
	// the rule that lets loopback through is the fixture's, so ask for an address no rule mentions
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })
	client := &uot.Client{Dialer: uotDialer{f: f, t: t, user: "u1", pass: "pw1"}, Version: uot.Version}
	conn, err := client.DialContext(context.Background(), "udp", M.ParseSocksaddr("192.168.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte("x"))
	if n, err := conn.Read(make([]byte, 8)); err == nil {
		t.Errorf("got an answer of %d bytes from a private address", n)
	}
}

func TestPlainHTTPProxy(t *testing.T) {
	f := newFixture(t, nil)
	target := newSite(t)
	proxyURL, _ := url.Parse("https://u1:pw1@" + f.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Get(target.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "the real site" {
		t.Fatalf("got %q", b)
	}
	if h := target.last(); h.Get("Proxy-Authorization") != "" {
		t.Fatalf("credentials reached the target: %v", h)
	}
}

// A target that speaks first makes sniffing wait out its timeout, which must leave an HTTP/2 tunnel working.
func TestH2SniffingServerFirst(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); fmt.Fprint(c, "banner\n"); io.Copy(c, c) }()
		}
	}()
	f := newFixture(t, func(in *spec.Inbound) { in.Sniffing.Enabled = true })
	f.echo = l.Addr().String()
	w, r := f.tunnelH2(t, "u1", "pw1")
	got := make([]byte, len("banner\n"))
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "banner\n" {
		t.Fatalf("banner: %q %v", got, err)
	}
	if err := echoH2(w, r, "after the sniff"); err != nil {
		t.Fatalf("the tunnel broke when sniffing gave up: %v\n%s", err, f.rt.Logs(10))
	}

	c, br := f.tunnel(t, "u1", "pw1")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if line, err := br.ReadString('\n'); err != nil || line != "banner\n" {
		t.Fatalf("http/1.1 banner: %q %v", line, err)
	}
	if err := echoOnce(c, br, "after the sniff"); err != nil {
		t.Fatalf("the http/1.1 tunnel broke when sniffing gave up: %v", err)
	}
}

func TestConnectWithoutCredentialsSeesTheSite(t *testing.T) {
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })
	c, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", f.echo, f.echo)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "the real site" || resp.Header.Get("Proxy-Authenticate") != "" {
		t.Errorf("a CONNECT without credentials met a proxy: %s %v %q", resp.Status, resp.Header, body)
	}
}

func TestSiteStaysUpWithoutTheEgress(t *testing.T) {
	s := newSite(t)
	f := newFixture(t, func(in *spec.Inbound) { in.Options.NaiveDest = strings.TrimPrefix(s.URL, "http://") })
	// a rule set nobody serves keeps the egress from starting
	f.d.Rules = append(f.d.Rules, spec.Rule{GeoSite: []string{"x"}, Outbound: "direct"})
	rendered, err := corenaive.Render(f.d)
	if err != nil {
		t.Fatal(err)
	}
	rendered = bytes.ReplaceAll(rendered, []byte("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-x.srs"), []byte("http://127.0.0.1:1/x.srs"))
	if err := f.rt.Apply(context.Background(), f.d, rendered); err == nil {
		t.Fatal("a daemon whose egress can't start reported nothing")
	}
	if got := f.get(t); got != "the real site" {
		t.Fatalf("the site went down with the egress: %q", got)
	}
	gate.CloseEgress()
}
