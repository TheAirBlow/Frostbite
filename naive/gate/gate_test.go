package gate

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/caddyserver/forwardproxy"
	"golang.org/x/net/http2"
)

// rig is a running Caddy with one naive server in front of a site and an echo target.
type rig struct {
	addr  string // the proxy
	admin *http.Client
	site  *httptest.Server
	echo  string
	mu    sync.Mutex
	seen  []http.Header
}

func selfSigned(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newRig(t *testing.T) *rig {
	t.Helper()
	registry.mu.Lock()
	registry.users, registry.usage, registry.sessions = map[string]map[string][32]byte{}, map[string]*counter{}, map[*session]struct{}{}
	registry.mu.Unlock()
	r := &rig{}
	r.site = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Header.Clone())
		r.mu.Unlock()
		fmt.Fprint(w, "the real site")
	}))
	t.Cleanup(r.site.Close)

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	r.echo = echo.Addr().String()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	cert, key := selfSigned(t)
	sock := filepath.Join(t.TempDir(), "admin.sock")
	r.addr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := map[string]any{
		"admin":   map[string]any{"listen": "unix/" + sock, "config": map[string]any{"persist": false}},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"tls": map[string]any{"certificates": map[string]any{"load_pem": []any{map[string]any{"certificate": cert, "key": key}}}},
			"http": map[string]any{"servers": map[string]any{"naive": map[string]any{
				"listen":                  []string{r.addr},
				"protocols":               []string{"h1", "h2"},
				"automatic_https":         map[string]any{"disable": true},
				"tls_connection_policies": []any{map[string]any{}},
				"routes": []any{
					map[string]any{"handle": []any{map[string]any{
						"handler": "frostbite_gate", "inbound": "naive",
						"proxy": map[string]any{"handler": "forward_proxy", "hide_ip": true, "hide_via": true,
							"acl": []any{map[string]any{"subjects": []string{"127.0.0.1"}, "allow": true}}},
					}}},
					map[string]any{"handle": []any{map[string]any{
						"handler":   "reverse_proxy",
						"upstreams": []any{map[string]any{"dial": strings.TrimPrefix(r.site.URL, "http://")}},
						"headers": map[string]any{"request": map[string]any{
							"set":    map[string]any{"X-Forwarded-For": []string{"{http.request.remote.host}"}},
							"delete": []string{"Proxy-Authorization"},
						}},
					}}},
				},
			}}},
		},
	}
	raw, _ := json.Marshal(cfg)
	if err := caddy.Load(raw, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	r.admin = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	return r
}

func (r *rig) setUsers(t *testing.T, users ...Credential) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"users": users})
	req, _ := http.NewRequest(http.MethodPut, "http://admin/frostbite/users/naive", strings.NewReader(string(body)))
	resp, err := r.admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ Cut int }
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("set users: %d %s", resp.StatusCode, raw)
	}
	_ = json.Unmarshal(raw, &out)
	return out.Cut
}

func (r *rig) usage(t *testing.T) Report {
	t.Helper()
	resp, err := r.admin.Post("http://admin/frostbite/usage", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func basic(name, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+pass))
}

// tunnelH1 opens a CONNECT over HTTP/1.1 to the echo target.
func (r *rig) tunnelH1(t *testing.T, name, pass string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", r.echo, r.echo, basic(name, pass))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("h1 connect: %v %v", resp, err)
	}
	return c, br
}

type h2Tunnel struct {
	w    *io.PipeWriter
	body io.ReadCloser
	tr   *http2.Transport
}

// tunnelH2 opens a CONNECT over HTTP/2, the way NaiveProxy does.
func (r *rig) tunnelH2(t *testing.T, name, pass string) *h2Tunnel {
	t.Helper()
	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		return tls.Dial(n, a, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}}
	pr, pw := io.Pipe()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: r.addr}, Host: r.echo, Body: pr, Header: http.Header{"Proxy-Authorization": {basic(name, pass)}}}
	req.URL.Host = r.addr
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("h2 connect: %v %v", resp, err)
	}
	return &h2Tunnel{w: pw, body: resp.Body, tr: tr}
}

func (h *h2Tunnel) echo(t *testing.T, msg string) {
	t.Helper()
	if _, err := h.w.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(h.body, got); err != nil || string(got) != msg {
		t.Fatalf("echo %q: got %q, %v", msg, got, err)
	}
}

// dead reports whether the tunnel stops carrying data within a few seconds.
func (h *h2Tunnel) dead() bool {
	done := make(chan bool, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := h.w.Write([]byte("x")); err != nil {
				done <- true
				return
			}
			buf := make([]byte, 1)
			h.body.Read(buf)
			time.Sleep(50 * time.Millisecond)
		}
		done <- false
	}()
	select {
	case v := <-done:
		return v
	case <-time.After(5 * time.Second):
		return false
	}
}

func get(t *testing.T, addr, path string, hdr http.Header) (int, string) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("GET", "https://"+addr+path, nil)
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestStrangersSeeTheSite(t *testing.T) {
	r := newRig(t)
	r.setUsers(t, Credential{Name: "u1", Password: "pw"})

	code, body := get(t, r.addr, "/", http.Header{"Proxy-Authorization": {basic("u1", "wrong")}, "X-Forwarded-For": {"6.6.6.6"}})
	if code != 200 || body != "the real site" {
		t.Fatalf("got %d %q", code, body)
	}
	h := r.seen[len(r.seen)-1]
	if h.Get("Proxy-Authorization") != "" {
		t.Error("proxy credentials reached the site")
	}
	if xff := h.Get("X-Forwarded-For"); xff != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want the connecting address only", xff)
	}

	// valid credentials on a plain request must not leak either
	get(t, r.addr, "/", http.Header{"Proxy-Authorization": {basic("u1", "pw")}})
	if r.seen[len(r.seen)-1].Get("Proxy-Authorization") != "" {
		t.Error("valid proxy credentials reached the site")
	}
}

func TestWrongPasswordIsNotAProxy(t *testing.T) {
	r := newRig(t)
	r.setUsers(t, Credential{Name: "u1", Password: "pw"})
	c, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", r.echo, r.echo, basic("u1", "nope"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 407 || resp.Header.Get("Proxy-Authenticate") != "" {
		t.Fatalf("a prober learned something: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestH2CountsAndKeepsTunnelsWhenUsersChange(t *testing.T) {
	r := newRig(t)
	r.setUsers(t, Credential{Name: "u1", Password: "pw"})
	tun := r.tunnelH2(t, "u1", "pw")
	tun.echo(t, "hello")

	if cut := r.setUsers(t, Credential{Name: "u1", Password: "pw"}, Credential{Name: "u2", Password: "pw2"}); cut != 0 {
		t.Fatalf("adding a user cut %d tunnels", cut)
	}
	tun.echo(t, "still here")

	rep := r.usage(t)
	u := rep.Users["u1"]
	if u.Up < int64(len("hello")+len("still here")) || u.Down < int64(len("hello")+len("still here")) {
		t.Errorf("usage %+v is too low", u)
	}
	if ips := rep.Online["u1"]; len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Errorf("online = %v", rep.Online)
	}
	if again := r.usage(t); len(again.Users) != 0 {
		t.Errorf("counters were not reset: %v", again.Users)
	}
}

func TestH2DeletedUserIsCut(t *testing.T) {
	r := newRig(t)
	r.setUsers(t, Credential{Name: "u1", Password: "pw"}, Credential{Name: "u2", Password: "pw2"})
	a := r.tunnelH2(t, "u1", "pw")
	b := r.tunnelH2(t, "u2", "pw2")
	a.echo(t, "a")
	b.echo(t, "b")

	if cut := r.setUsers(t, Credential{Name: "u2", Password: "pw2"}); cut != 1 {
		t.Fatalf("cut %d tunnels, want 1", cut)
	}
	if !a.dead() {
		t.Error("the deleted user's tunnel is still open")
	}
	b.echo(t, "b again")

	// the last bytes of the deleted user are still reported
	if rep := r.usage(t); rep.Users["u1"].Up == 0 {
		t.Errorf("lost the usage of the deleted user: %v", rep.Users)
	}

	// and they cannot come back
	code, _ := get(t, r.addr, "/", http.Header{"Proxy-Authorization": {basic("u1", "pw")}})
	if code != 200 {
		t.Errorf("site status %d", code)
	}
}

func TestH2ChangedPasswordCutsTheOldOne(t *testing.T) {
	r := newRig(t)
	r.setUsers(t, Credential{Name: "u1", Password: "old"})
	a := r.tunnelH2(t, "u1", "old")
	a.echo(t, "a")
	if cut := r.setUsers(t, Credential{Name: "u1", Password: "new"}); cut != 1 {
		t.Fatalf("cut %d", cut)
	}
	if !a.dead() {
		t.Error("tunnel with the old password survived")
	}
	r.tunnelH2(t, "u1", "new").echo(t, "fresh")
}

func TestH1CountsAndIsCut(t *testing.T) {
	r := newRig(t)
	r.setUsers(t, Credential{Name: "u1", Password: "pw"})
	c, br := r.tunnelH1(t, "u1", "pw")
	defer c.Close()
	fmt.Fprint(c, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if u := r.usage(t).Users["u1"]; u.Up < 4 || u.Down < 4 {
		t.Errorf("usage %+v", u)
	}

	r.setUsers(t)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "x")
	if _, err := br.ReadByte(); err == nil {
		t.Error("the tunnel survived deleting the user")
	}
}
