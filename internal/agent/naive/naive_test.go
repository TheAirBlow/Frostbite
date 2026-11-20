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

	"golang.org/x/net/http2"

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
		// the echo server is on loopback, which forwardproxy refuses unless a rule says otherwise
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
