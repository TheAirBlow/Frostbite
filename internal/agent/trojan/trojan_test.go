package trojan

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
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	sbtls "github.com/sagernet/sing-box/common/tls"
	sbtrojan "github.com/sagernet/sing-box/transport/trojan"
	smux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	coretrojan "frostbite/internal/core/trojan"
	"frostbite/internal/spec"
)

func writeCert(t testing.TB, dir, name string) (cert, key string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kder, _ := x509.MarshalECPrivateKey(k)
	cert, key = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	return cert, key
}

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func echoServer(t testing.TB) string {
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
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func udpEcho(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().String()
}

// site records the requests the daemon passes on.
type site struct {
	*httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func newSite(t *testing.T, body string) *site {
	s := &site{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Clone(context.Background()))
		s.mu.Unlock()
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *site) addr() string { return strings.TrimPrefix(s.URL, "http://") }

func (s *site) last() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[len(s.seen)-1]
}

type fixture struct {
	rt   *Runtime
	d    spec.Daemon
	addr string
	echo string
	dir  string
}

func newFixture(t testing.TB, tune func(*spec.Inbound)) *fixture {
	t.Helper()
	f := &fixture{rt: New(), echo: echoServer(t), dir: t.TempDir()}
	t.Cleanup(func() { f.rt.Close() })
	cert, key := writeCert(t, f.dir, "localhost")
	p := freePort(t)
	f.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
	in := spec.Inbound{
		Tag: "tj", Protocol: spec.ProtoTrojan, Listen: "127.0.0.1", Port: p,
		Transport: spec.Transport{Type: spec.TransportTCP},
		Security:  spec.Security{Type: spec.SecurityTLS, CertPath: cert, KeyPath: key},
		Options:   spec.Options{TJDest: "127.0.0.1:1"},
		Users:     []spec.User{{Name: "u1", Password: "pw1"}},
	}
	if tune != nil {
		tune(&in)
	}
	f.d = spec.Daemon{Kind: "trojan", Inbounds: []spec.Inbound{in}, Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}, {Tag: "block", Kind: spec.OutBlock}}, Final: "direct"}
	f.apply(t)
	return f
}

func (f *fixture) apply(t testing.TB) {
	t.Helper()
	if err := f.d.Validate(); err != nil {
		t.Fatal(err)
	}
	rendered, err := coretrojan.Render(f.d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rt.Apply(context.Background(), f.d, rendered); err != nil {
		t.Fatalf("apply: %v\n%s", err, f.rt.Logs(20))
	}
}

func (f *fixture) setUsers(t *testing.T, users ...spec.User) {
	f.d.Inbounds[0].Users = users
	f.apply(t)
}

// header is a trojan request.
func header(password string, cmd byte, dst string) []byte {
	host, port, _ := net.SplitHostPort(dst)
	p, _ := strconv.Atoi(port)
	a := addr{host: host, port: uint16(p)}
	if ip, err := netip.ParseAddr(host); err == nil {
		a = addr{ip: ip, port: uint16(p)}
	}
	b := append([]byte(passwordHash(password)), '\r', '\n', cmd)
	b = appendAddr(b, a)
	return append(b, '\r', '\n')
}

func (f *fixture) dialTLS(t testing.TB, cfg *tls.Config) *tls.Conn {
	t.Helper()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg.InsecureSkipVerify = true
	c, err := tls.Dial("tcp", f.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// connect opens a trojan tunnel to dst, sending payload together with the request as real clients do.
func (f *fixture) connect(t testing.TB, password, dst string, payload []byte) *tls.Conn {
	t.Helper()
	c := f.dialTLS(t, nil)
	if _, err := c.Write(append(header(password, cmdConnect, dst), payload...)); err != nil {
		t.Fatal(err)
	}
	return c
}

func expectEcho(t *testing.T, c net.Conn, want string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 64)); err == nil || isTimeout(err) {
		t.Fatalf("connection still open (read %d, %v)", n, err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestTunnelCountsTraffic(t *testing.T) {
	f := newFixture(t, nil)
	c := f.connect(t, "pw1", f.echo, []byte("hello"))
	expectEcho(t, c, "hello")
	fmt.Fprint(c, "again")
	expectEcho(t, c, "again")

	// the last write is booked just after the client could read it
	time.Sleep(50 * time.Millisecond)
	st, _ := f.rt.Stats(context.Background())
	if ips := st.Online["u1"]; len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("online: %v", st.Online)
	}
	if u := st.Users["u1"]; u.Up < 10 || u.Down < 10 {
		t.Fatalf("usage: %+v", st.Users)
	}
	c.Close()
	time.Sleep(100 * time.Millisecond)
	st, _ = f.rt.Stats(context.Background())
	if len(st.Online) != 0 || st.Users["u1"].Up != 0 {
		t.Fatalf("after close: %+v", st)
	}
}

func TestStrangersReachTheSite(t *testing.T) {
	s := newSite(t, "the real site")
	f := newFixture(t, func(in *spec.Inbound) { in.Options.TJDest = s.addr() })

	// a browser, a wrong password and a short probe all see the site
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + f.addr + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "the real site" || s.last().URL.Path != "/page" {
		t.Fatalf("browser got %q", body)
	}

	c := f.connect(t, "wrong", f.echo, []byte("GET /x HTTP/1.1\r\nHost: a\r\n\r\n"))
	resp, err = http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("wrong password got no answer from the site: %v", err)
	}
	resp.Body.Close()

	c = f.dialTLS(t, nil)
	fmt.Fprint(c, "GET / HTTP/1.0\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !bytes.Contains(b, []byte("the real site")) {
		t.Fatalf("short probe got %q", b)
	}
}

func TestRemovedUserIsCutOff(t *testing.T) {
	f := newFixture(t, nil)
	c := f.connect(t, "pw1", f.echo, []byte("x"))
	expectEcho(t, c, "x")

	f.setUsers(t, spec.User{Name: "u1", Password: "pw1"}, spec.User{Name: "u2", Password: "pw2"})
	fmt.Fprint(c, "y")
	expectEcho(t, c, "y") // a user who stays keeps their tunnel
	c2 := f.connect(t, "pw2", f.echo, []byte("z"))
	expectEcho(t, c2, "z")

	f.setUsers(t, spec.User{Name: "u2", Password: "new"})
	expectClosed(t, c)
	expectClosed(t, c2) // a new password cuts the old one off
	c3 := f.connect(t, "new", f.echo, []byte("w"))
	expectEcho(t, c3, "w")
}

func TestUDPAssociate(t *testing.T) {
	f := newFixture(t, nil)
	echo := udpEcho(t)
	c := f.dialTLS(t, nil)
	pk := &trojanPackets{r: c, w: c}
	head := header("pw1", cmdUDP, "0.0.0.0:0")
	if _, err := c.Write(head); err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(echo)
	for i := range 3 {
		msg := []byte("packet " + strconv.Itoa(i))
		if err := pk.writePacket(msg, addrOf(ap)); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 100)
		n, from, err := pk.readPacket(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != string(msg) || from.String() != echo {
			t.Fatalf("got %q from %s", buf[:n], from)
		}
	}
}

func TestRulesBlock(t *testing.T) {
	f := newFixture(t, nil)
	f.d.Rules = []spec.Rule{{IPCIDR: []string{"127.0.0.0/8"}, Port: []string{strings.Split(f.echo, ":")[1]}, Outbound: "block"}}
	f.apply(t)
	c := f.connect(t, "pw1", f.echo, []byte("x"))
	expectClosed(t, c)

	f.d.Rules = []spec.Rule{{Domain: []string{"localhost"}, Outbound: "block"}}
	f.apply(t)
	c = f.connect(t, "pw1", f.echo, []byte("x"))
	expectEcho(t, c, "x")
	_, port, _ := net.SplitHostPort(f.echo)
	c = f.connect(t, "pw1", "localhost:"+port, []byte("x"))
	expectClosed(t, c)
}

func TestSniffingRoutesByServerName(t *testing.T) {
	f := newFixture(t, func(in *spec.Inbound) { in.Sniffing = spec.Sniffing{Enabled: true, RouteOnly: true} })
	f.d.Rules = []spec.Rule{{DomainSuffix: []string{"blocked.example"}, Outbound: "block"}}
	f.apply(t)
	c := f.connect(t, "pw1", f.echo, []byte("GET / HTTP/1.1\r\nHost: www.blocked.example\r\n\r\n"))
	expectClosed(t, c)
	c = f.connect(t, "pw1", f.echo, []byte("GET / HTTP/1.1\r\nHost: fine.example\r\n\r\n"))
	expectEcho(t, c, "GET / HTTP/1.1\r\n")
}

func TestClientIPHeader(t *testing.T) {
	s := newSite(t, "ok")
	f := newFixture(t, func(in *spec.Inbound) {
		in.Options.TJDest = s.addr()
		in.Options.TJIPHeader = "X-Real-IP"
		in.Options.TJHeaders = map[string]string{"X-From": "trojan"}
	})
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: h2}
		if h2 {
			if err := http2.ConfigureTransport(tr); err != nil {
				t.Fatal(err)
			}
		}
		req, _ := http.NewRequest("GET", "https://"+f.addr+"/a", nil)
		req.Host = "site.example"
		req.Header.Set("X-Real-IP", "1.2.3.4")
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if h2 != (resp.ProtoMajor == 2) {
			t.Fatalf("visitor spoke %s", resp.Proto)
		}
		got := s.last()
		if got.Header.Get("X-Real-IP") != "127.0.0.1" || got.Header.Get("X-From") != "trojan" || got.Header.Get("X-Forwarded-For") != "" || got.Host != "site.example" {
			t.Fatalf("site saw host %q and %v", got.Host, got.Header)
		}
	}
}

// proxySite is a site that reads a PROXY header and answers with the source it names.
func proxySite(t *testing.T) string {
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
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				h, err := proxyproto.Read(br)
				if err != nil {
					fmt.Fprintf(c, "no header: %v", err)
					return
				}
				line, _ := br.ReadString('\n')
				fmt.Fprintf(c, "v%d %s %s", h.Version, h.SourceAddr, line)
			}()
		}
	}()
	return l.Addr().String()
}

func TestProxyProtocolToSite(t *testing.T) {
	dest := proxySite(t)
	for _, v := range []string{"v1", "v2"} {
		f := newFixture(t, func(in *spec.Inbound) { in.Options.TJDest, in.Options.TJProxy = dest, v })
		c := f.dialTLS(t, nil)
		fmt.Fprint(c, "hello site\n")
		b, _ := io.ReadAll(c)
		if !strings.HasPrefix(string(b), v+" 127.0.0.1:") || !strings.HasSuffix(string(b), "hello site\n") {
			t.Fatalf("%s: site said %q", v, b)
		}
	}
}

func TestSiteBySNIALPNAndPath(t *testing.T) {
	main, byName, byALPN, byPath := newSite(t, "main"), newSite(t, "name"), newSite(t, "alpn"), newSite(t, "path")
	f := newFixture(t, func(in *spec.Inbound) {
		in.Security.ALPN = []string{"h2", "http/1.1"}
		in.Options.TJDest = main.addr()
		in.Options.TJBySNI = map[string]string{"*.blog.example": byName.addr()}
		in.Options.TJByALPN = map[string]string{"h2": byALPN.addr()}
		in.Options.TJByPath = map[string]string{"/api": byPath.addr()}
	})
	get := func(sni string, alpn []string, path string) string {
		c := f.dialTLS(t, &tls.Config{ServerName: sni, NextProtos: alpn})
		if c.ConnectionState().NegotiatedProtocol == "h2" {
			// the h2 site is a plain HTTP/1.1 test server, which is enough to see where the bytes went
			fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		} else {
			fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	for _, c := range []struct {
		sni  string
		alpn []string
		path string
		want string
	}{
		{"www.blog.example", []string{"h2"}, "/api", "name"},
		{"other.example", []string{"h2"}, "/api", "alpn"},
		{"other.example", []string{"http/1.1"}, "/api/v1", "path"},
		{"other.example", []string{"http/1.1"}, "/", "main"},
	} {
		if got := get(c.sni, c.alpn, c.path); got != c.want {
			t.Errorf("%s %v %s went to %q, want %q", c.sni, c.alpn, c.path, got, c.want)
		}
	}
}

func TestPlainHTTP(t *testing.T) {
	s := newSite(t, "plain site")
	for _, c := range []struct{ mode, want string }{
		{spec.TrojanPlainRedirect, "301 Moved Permanently"},
		{spec.TrojanPlainNginx, "The plain HTTP request was sent to HTTPS port"},
		{spec.TrojanPlainSite, "plain site"},
		{"", ""},
	} {
		f := newFixture(t, func(in *spec.Inbound) { in.Options.TJDest, in.Options.TJPlain = s.addr(), c.mode })
		conn, err := net.Dial("tcp", f.addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(conn, "GET /x?y=1 HTTP/1.1\r\nHost: site.example\r\nConnection: close\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(conn)
		conn.Close()
		if c.want == "" && len(b) != 0 || !strings.Contains(string(b), c.want) {
			t.Errorf("%q: got %q", c.mode, b)
		}
		if c.mode == spec.TrojanPlainRedirect && !strings.Contains(string(b), "Location: https://site.example/x?y=1\r\n") {
			t.Errorf("redirect: %q", b)
		}
	}
}

func TestSingMux(t *testing.T) {
	f := newFixture(t, nil)
	echo := udpEcho(t)
	for _, proto := range []string{"smux", "yamux", "h2mux"} {
		for _, padding := range []bool{false, true} {
			client, err := smux.NewClient(smux.Options{Dialer: trojanDialer{f: f, t: t}, Protocol: proto, Padding: padding, MaxConnections: 1, Logger: logger.NOP()})
			if err != nil {
				t.Fatal(err)
			}
			for i := range 3 {
				c, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr(f.echo))
				if err != nil {
					t.Fatalf("%s: %v", proto, err)
				}
				msg := fmt.Sprintf("%s %d", proto, i)
				fmt.Fprint(c, msg)
				expectEcho(t, c, msg)
				c.Close()
			}
			pc, err := client.ListenPacket(context.Background(), M.ParseSocksaddr(echo))
			if err != nil {
				t.Fatal(err)
			}
			ua, _ := net.ResolveUDPAddr("udp", echo)
			if _, err := pc.WriteTo([]byte("dgram"), ua); err != nil {
				t.Fatal(err)
			}
			_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 64)
			n, _, err := pc.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "dgram" {
				t.Fatalf("%s udp: %q %v", proto, buf[:n], err)
			}
			pc.Close()
			client.Close()
		}
	}
}

// trojanDialer is what sing-box puts under a multiplexed trojan outbound.
type trojanDialer struct {
	f *fixture
	t *testing.T
}

func (d trojanDialer) DialContext(_ context.Context, _ string, dst M.Socksaddr) (net.Conn, error) {
	c, err := tls.Dial("tcp", d.f.addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	return sbtrojan.NewClientConn(c, sbtrojan.Key("pw1"), dst), nil
}

func (d trojanDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("not used")
}

// coolFrame builds a Mux.Cool frame.
func coolFrame(id uint16, status, opt byte, target []byte, data []byte) []byte {
	meta := binary.BigEndian.AppendUint16(nil, id)
	meta = append(meta, status, opt)
	meta = append(meta, target...)
	b := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	b = append(b, meta...)
	if opt&coolOptData != 0 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		b = append(b, data...)
	}
	return b
}

// readCool reads one frame.
func readCool(t *testing.T, r io.Reader) (id uint16, status byte, meta, data []byte) {
	t.Helper()
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		t.Fatal(err)
	}
	meta = make([]byte, binary.BigEndian.Uint16(head[:]))
	if _, err := io.ReadFull(r, meta); err != nil {
		t.Fatal(err)
	}
	if meta[3]&coolOptData != 0 {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			t.Fatal(err)
		}
		data = make([]byte, binary.BigEndian.Uint16(head[:]))
		if _, err := io.ReadFull(r, data); err != nil {
			t.Fatal(err)
		}
	}
	return binary.BigEndian.Uint16(meta), meta[2], meta, data
}

func TestMuxCool(t *testing.T) {
	f := newFixture(t, nil)
	c := f.connect(t, "pw1", muxCoolHost+":9527", nil)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	ap := netip.MustParseAddrPort(f.echo)
	ip := ap.Addr().As4()
	tcp := append(binary.BigEndian.AppendUint16([]byte{coolTCP}, ap.Port()), 0x01)
	tcp = append(tcp, ip[:]...)
	// two streams at once, the second opened without data
	if _, err := c.Write(append(coolFrame(1, coolNew, coolOptData, tcp, []byte("one")), coolFrame(2, coolNew, 0, tcp, nil)...)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(coolFrame(2, coolKeep, coolOptData, nil, []byte("two"))); err != nil {
		t.Fatal(err)
	}
	got := map[uint16]string{}
	for len(got) < 2 {
		id, status, _, data := readCool(t, c)
		if status != coolKeep {
			t.Fatalf("stream %d: status %d", id, status)
		}
		got[id] += string(data)
		if got[id] != "one" && got[id] != "two" && len(got[id]) >= 3 {
			t.Fatalf("stream %d got %q", id, got[id])
		}
	}
	if got[1] != "one" || got[2] != "two" {
		t.Fatalf("got %v", got)
	}

	// XUDP: packets name their destination, and answers name where they came from
	echo := netip.MustParseAddrPort(udpEcho(t))
	eip := echo.Addr().As4()
	udp := append(binary.BigEndian.AppendUint16([]byte{coolUDP}, echo.Port()), 0x01)
	udp = append(udp, eip[:]...)
	global := append(slicesClone(udp), 1, 2, 3, 4, 5, 6, 7, 8)
	if _, err := c.Write(coolFrame(3, coolNew, coolOptData, global, []byte("dgram"))); err != nil {
		t.Fatal(err)
	}
	for {
		id, status, meta, data := readCool(t, c)
		if id != 3 {
			continue
		}
		if status != coolKeep || string(data) != "dgram" || !bytes.Equal(meta[4:], udp) {
			t.Fatalf("udp answer: status %d meta %x data %q", status, meta, data)
		}
		break
	}

	// a large answer comes back split into frames Xray accepts
	big := bytes.Repeat([]byte("0123456789"), 3000)
	frames := coolFrame(4, coolNew, coolOptData, tcp, big[:coolChunk])
	frames = append(frames, coolFrame(4, coolKeep, coolOptData, nil, big[coolChunk:2*coolChunk])...)
	frames = append(frames, coolFrame(4, coolKeep, coolOptData, nil, big[2*coolChunk:])...)
	if _, err := c.Write(frames); err != nil {
		t.Fatal(err)
	}
	var back []byte
	for len(back) < len(big) {
		id, status, _, data := readCool(t, c)
		if id != 4 {
			continue
		}
		if status != coolKeep || len(data) > coolChunk {
			t.Fatalf("big answer: status %d, %d bytes in a frame", status, len(data))
		}
		back = append(back, data...)
	}
	if !bytes.Equal(back, big) {
		t.Fatal("big answer differs")
	}

	if _, err := c.Write(coolFrame(1, coolEnd, 0, nil, nil)); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "")
}

func slicesClone(b []byte) []byte { return append([]byte(nil), b...) }

func TestECH(t *testing.T) {
	configPem, keyPem, err := sbtls.ECHKeygenDefault("public.example")
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(in *spec.Inbound) { in.Security.ECHKey = keyPem })
	block, _ := pem.Decode([]byte(configPem))
	c := f.dialTLS(t, &tls.Config{ServerName: "localhost", EncryptedClientHelloConfigList: block.Bytes, MinVersion: tls.VersionTLS13})
	if !c.ConnectionState().ECHAccepted {
		t.Fatal("ECH was not accepted")
	}
	if _, err := c.Write(append(header("pw1", cmdConnect, f.echo), "ech"...)); err != nil {
		t.Fatal(err)
	}
	expectEcho(t, c, "ech")
}

func TestTLSKnobs(t *testing.T) {
	f := newFixture(t, func(in *spec.Inbound) {
		in.Options.TJMinTLS = "1.2"
		in.Options.TJCiphers = []string{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"}
		in.Options.TJCurves = []string{"P-384"}
		in.Options.TJNoTicket = true
	})
	c := f.dialTLS(t, &tls.Config{MaxVersion: tls.VersionTLS12})
	cs := c.ConnectionState()
	if cs.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 || cs.CurveID != tls.CurveP384 {
		t.Fatalf("suite %s curve %s", tls.CipherSuiteName(cs.CipherSuite), cs.CurveID)
	}

	f.d.Inbounds[0].Options.TJMinTLS = "1.3"
	f.apply(t)
	if _, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS 1.2 was accepted")
	}
}

func TestNewCertificateKeepsConnections(t *testing.T) {
	f := newFixture(t, nil)
	c := f.connect(t, "pw1", f.echo, []byte("a"))
	expectEcho(t, c, "a")

	cert, key := writeCert(t, f.dir, "renewed.example")
	f.d.Inbounds[0].Security.CertPath, f.d.Inbounds[0].Security.KeyPath = cert, key
	f.apply(t)
	fmt.Fprint(c, "b")
	expectEcho(t, c, "b")
	c2 := f.dialTLS(t, nil)
	if cn := c2.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "renewed.example" {
		t.Fatalf("still serving %s", cn)
	}
}

func TestAcceptProxyFromLoopbackOnly(t *testing.T) {
	f := newFixture(t, func(in *spec.Inbound) { in.Options.AcceptProxy = true })
	raw, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}
	if _, err := proxyproto.HeaderProxyFromAddrs(2, src, raw.RemoteAddr()).WriteTo(raw); err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write(append(header("pw1", cmdConnect, f.echo), "p"...)); err != nil {
		t.Fatal(err)
	}
	expectEcho(t, c, "p")
	st, _ := f.rt.Stats(context.Background())
	if ips := st.Online["u1"]; len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("online: %v", st.Online)
	}
}

func TestRenderedConfigTakesPatches(t *testing.T) {
	f := newFixture(t, nil)
	f.d.Inbounds[0].RawPatch = json.RawMessage(`{"plain":"nginx"}`)
	f.apply(t)
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	b, _ := io.ReadAll(conn)
	if !strings.Contains(string(b), "nginx") {
		t.Fatalf("patch ignored: %q", b)
	}
}

// TestUpstreamClients runs upstream trojan and trojan-go as clients in front of the daemon.
func TestUpstreamClients(t *testing.T) {
	for _, name := range []string{"trojan", "trojan-go"} {
		t.Run(name, func(t *testing.T) { upstreamClient(t, name) })
	}
}

func upstreamClient(t *testing.T, name string) {
	bin, err := exec.LookPath(name)
	if err != nil {
		t.Skip(name + " is not installed")
	}
	s := newSite(t, "site")
	f := newFixture(t, func(in *spec.Inbound) { in.Options.TJDest = s.addr() })
	echo := udpEcho(t)
	socks := freePort(t)
	cfg := map[string]any{
		"run_type": "client", "local_addr": "127.0.0.1", "local_port": socks,
		"remote_addr": "127.0.0.1", "remote_port": f.d.Inbounds[0].Port, "password": []string{"pw1"}, "log_level": 1,
		"ssl": map[string]any{"verify": false, "verify_hostname": false, "sni": "localhost", "alpn": []string{"h2", "http/1.1"}},
	}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(f.dir, "client.json")
	_ = os.WriteFile(path, raw, 0o600)
	cmd := exec.Command(bin, "-config", path)
	if name == "trojan" {
		cmd = exec.Command(bin, "-c", path)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	var dialer proxy.Dialer
	for range 50 {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socks)); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	dialer, err = proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socks), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dialer.Dial("tcp", f.echo)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	defer c.Close()
	fmt.Fprint(c, "through upstream trojan")
	expectEcho(t, c, "through upstream trojan")

	st, _ := f.rt.Stats(context.Background())
	if st.Users["u1"].Up == 0 {
		t.Fatalf("no traffic counted: %+v\n%s", st, out.String())
	}

	// UDP through the client's SOCKS5 UDP ASSOCIATE
	ctl, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socks))
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	_, _ = ctl.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(ctl, resp)
	_, _ = ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctl, rep); err != nil || rep[1] != 0 {
		t.Fatalf("udp associate: %x %v", rep, err)
	}
	relayAddr := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	uc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	ap := netip.MustParseAddrPort(echo)
	ip := ap.Addr().As4()
	pkt := append([]byte{0, 0, 0, 1}, ip[:]...)
	pkt = binary.BigEndian.AppendUint16(pkt, ap.Port())
	pkt = append(pkt, "udp via upstream"...)
	_, _ = uc.Write(pkt)
	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 200)
	n, err := uc.Read(buf)
	if err != nil || !bytes.HasSuffix(buf[:n], []byte("udp via upstream")) {
		t.Fatalf("udp: %q %v\n%s", buf[:n], err, out.String())
	}
}

func TestRenamedInboundKeepsItsPort(t *testing.T) {
	f := newFixture(t, nil)
	f.d.Inbounds[0].Tag = "tj-renamed"
	f.apply(t)
	expectEcho(t, f.connect(t, "pw1", f.echo, []byte("hello")), "hello")
}

func TestProxyOutbound(t *testing.T) {
	exit := newFixture(t, nil)
	host, port, _ := net.SplitHostPort(exit.addr)
	p, _ := strconv.Atoi(port)
	f := newFixture(t, nil)
	f.d.Outbounds = append(f.d.Outbounds, spec.Outbound{Tag: "chain", Kind: spec.OutProxy, Upstream: &spec.Upstream{
		Protocol: spec.ProtoTrojan, Address: host, Port: p, Password: "pw1",
		Security: spec.Security{Type: spec.SecurityTLS, SNI: "localhost", Insecure: true},
	}})
	f.d.Final = "chain"
	f.apply(t)

	c := f.connect(t, "pw1", f.echo, []byte("through the chain"))
	expectEcho(t, c, "through the chain")
	time.Sleep(50 * time.Millisecond)
	if st, _ := exit.rt.Stats(context.Background()); st.Users["u1"].Up == 0 {
		t.Fatalf("the exit saw nothing: %+v", st)
	}
}

// bannerServer greets every connection before it echoes, as SSH and SMTP servers speak first.
func bannerServer(t testing.TB) string {
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
			go func() { defer c.Close(); fmt.Fprint(c, "banner\n"); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// Sniffing waits out its timeout when the target speaks first, and the tunnel must carry on after it.
func TestSniffingServerFirst(t *testing.T) {
	f := newFixture(t, func(in *spec.Inbound) { in.Sniffing.Enabled = true })
	banner := bannerServer(t)

	c := f.connect(t, "pw1", banner, nil)
	expectEcho(t, c, "banner\n")
	fmt.Fprint(c, "plain")
	expectEcho(t, c, "plain")

	m := f.connect(t, "pw1", muxCoolHost+":9527", nil)
	_ = m.SetDeadline(time.Now().Add(10 * time.Second))
	ap := netip.MustParseAddrPort(banner)
	ip := ap.Addr().As4()
	tcp := append(binary.BigEndian.AppendUint16([]byte{coolTCP}, ap.Port()), 0x01)
	tcp = append(tcp, ip[:]...)
	if _, err := m.Write(coolFrame(1, coolNew, 0, tcp, nil)); err != nil {
		t.Fatal(err)
	}
	var got string
	for got != "banner\n" {
		_, status, _, data := readCool(t, m)
		if status != coolKeep {
			t.Fatalf("status %d before the banner", status)
		}
		got += string(data)
	}
	if _, err := m.Write(coolFrame(1, coolKeep, coolOptData, nil, []byte("muxed"))); err != nil {
		t.Fatal(err)
	}
	if _, status, _, data := readCool(t, m); status != coolKeep || string(data) != "muxed" {
		t.Fatalf("after the sniff: status %d, %q", status, data)
	}
}

// brokenEgress needs a rule set nobody serves, so it can't start.
const brokenEgress = `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{
	"rule_set":[{"type":"remote","tag":"x","format":"source","url":"http://127.0.0.1:1/x.json"}],
	"rules":[{"rule_set":["x"],"action":"reject"}]}}`

func TestSiteStaysUpWithoutTheEgress(t *testing.T) {
	s := newSite(t, "the real site")
	f := &fixture{rt: New(), echo: echoServer(t), dir: t.TempDir()}
	t.Cleanup(func() { f.rt.Close() })
	cert, key := writeCert(t, f.dir, "localhost")
	p := freePort(t)
	f.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
	f.d = spec.Daemon{Kind: "trojan", Final: "direct", Inbounds: []spec.Inbound{{
		Tag: "tj", Protocol: spec.ProtoTrojan, Listen: "127.0.0.1", Port: p,
		Security: spec.Security{Type: spec.SecurityTLS, CertPath: cert, KeyPath: key},
		Options:  spec.Options{TJDest: s.addr()}, Users: []spec.User{{Name: "u1", Password: "pw1"}},
	}}}
	rendered, err := coretrojan.Render(f.d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg coretrojan.Config
	_ = json.Unmarshal(rendered, &cfg)
	cfg.Egress = json.RawMessage(brokenEgress)
	rendered, _ = json.Marshal(cfg)
	if err := f.rt.Apply(context.Background(), f.d, rendered); err == nil {
		t.Fatal("a daemon whose egress can't start reported nothing")
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + f.addr + "/")
	if err != nil {
		t.Fatalf("the site went down with the egress: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "the real site" {
		t.Fatalf("got %q", body)
	}
	expectClosed(t, f.connect(t, "pw1", f.echo, []byte("hello")))
}
