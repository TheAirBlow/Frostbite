package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"frostbite/internal/spec"
)

func TestProxyHeaderRoundTrip(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51000}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}
	src6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}
	for _, tc := range []struct {
		ver      int
		src, dst net.Addr
	}{{1, src, dst}, {2, src, dst}, {1, src6, dst}, {2, src6, dst}, {1, nil, nil}, {2, nil, nil}} {
		r := bufio.NewReader(bytes.NewReader(append(proxyHeader(tc.ver, tc.src, tc.dst), "rest"...)))
		s, d, err := readProxyHeader(r)
		if err != nil {
			t.Fatalf("v%d: %v", tc.ver, err)
		}
		if tc.src == nil {
			if s != nil || d != nil {
				t.Fatalf("v%d LOCAL carried addresses", tc.ver)
			}
		} else if !s.(*net.TCPAddr).IP.Equal(tc.src.(*net.TCPAddr).IP) || s.(*net.TCPAddr).Port != tc.src.(*net.TCPAddr).Port || d.(*net.TCPAddr).Port != 443 {
			t.Fatalf("v%d: got %v %v", tc.ver, s, d)
		}
		if rest, _ := r.ReadString(0); rest != "rest" {
			t.Fatalf("v%d: payload became %q", tc.ver, rest)
		}
	}
}

func TestFindCaddyCert(t *testing.T) {
	dir := t.TempDir()
	put := func(issuer, name, host string) {
		base := filepath.Join(dir, "certificates", issuer, name)
		if err := selfSigned(filepath.Join(base, name+".crt"), filepath.Join(base, name+".key"), host); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := findCaddyCert(dir, "vpn.example.com"); err == nil {
		t.Fatal("found a certificate in empty storage")
	}
	put("acme.zerossl.com-v2-dv90", "wildcard_.example.com", "*.example.com")
	if _, err := findCaddyCert(dir, "vpn.example.com"); err != nil {
		t.Fatalf("wildcard of the parent not used: %v", err)
	}
	put("acme-v02.api.letsencrypt.org-directory", "vpn.example.com", "vpn.example.com")
	if _, err := findCaddyCert(dir, "vpn.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := findCaddyCert(dir, "*.example.com"); err != nil {
		t.Fatalf("wildcard domain: %v", err)
	}
	if _, err := findCaddyCert(dir, "other.org"); err == nil {
		t.Fatal("found a certificate for an unrelated domain")
	}
}

func TestCaddySyncStandInThenReal(t *testing.T) {
	storage, copies := t.TempDir(), t.TempDir()
	c := newCaddyCerts(copies, nil)
	cd := spec.Caddy{Domain: "vpn.example.com", Dir: storage}
	if st := c.sync(cd); !st.Placeholder || st.OK {
		t.Fatalf("expected a stand-in, got %+v", st)
	}
	if _, err := os.Stat(filepath.Join(storage, "certificates")); err == nil {
		t.Fatal("wrote into Caddy's storage")
	}
	base := filepath.Join(storage, "certificates", "local", cd.Domain)
	if err := selfSigned(filepath.Join(base, cd.Domain+".crt"), filepath.Join(base, cd.Domain+".key"), cd.Domain); err != nil {
		t.Fatal(err)
	}
	if st := c.sync(cd); !st.OK || st.Placeholder {
		t.Fatalf("expected the real certificate, got %+v", st)
	}
	cert, key := cd.Paths(copies)
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureCertsLeavesForeignFoldersAlone(t *testing.T) {
	foreign, data := t.TempDir(), t.TempDir()
	d := spec.Daemon{Inbounds: []spec.Inbound{{Tag: "tls", Security: spec.Security{
		Type: spec.SecurityTLS, SNI: "x.example.com",
		CertPath: filepath.Join(foreign, "live", "fullchain.pem"), KeyPath: filepath.Join(foreign, "live", "privkey.pem"),
	}}}}
	if got := ensureCerts(&d, data); len(got) != 1 {
		t.Fatalf("redirected %v", got)
	}
	if _, err := os.Stat(filepath.Join(foreign, "live")); err == nil {
		t.Fatal("wrote into a folder another tool owns")
	}
	if !fileExists(d.Inbounds[0].Security.CertPath) {
		t.Fatal("no stand-in in place")
	}
}

// tlsSite is a TLS server that records the PROXY header it got, if any.
func tlsSite(t *testing.T, expectProxy bool) (string, chan net.Addr) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := selfSigned(cert, key, "site.example.com"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	seen := make(chan net.Addr, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if expectProxy {
					src, _, err := readProxyHeader(br)
					if err != nil {
						return
					}
					seen <- src
				}
				tc := tls.Server(&bufConn{Conn: c, r: br}, &tls.Config{Certificates: []tls.Certificate{pair}})
				_ = tc.Handshake()
			}()
		}
	}()
	return ln.Addr().String(), seen
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestTakeoverRelaysWithProxyHeader(t *testing.T) {
	target, seen := tlsSite(t, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveTakeover(ln, spec.Cloak{Target: target, XVer: 2, Timeout: 5}, false)

	if err := probeTLS(context.Background(), ln.Addr().String(), "site.example.com", 5*time.Second, 0); err != nil {
		t.Fatalf("handshake through the takeover: %v", err)
	}
	select {
	case src := <-seen:
		if src == nil || !src.(*net.TCPAddr).IP.IsLoopback() {
			t.Fatalf("target saw %v", src)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target got no PROXY header")
	}
}

// fakeRuntime is a supervised runtime whose liveness the test controls.
type fakeRuntime struct {
	Runtime
	alive    bool
	restarts int
	halts    int
}

func (f *fakeRuntime) Alive() bool                   { return f.alive }
func (f *fakeRuntime) SetHooks(func(), func())       {}
func (f *fakeRuntime) Restart(context.Context) error { f.restarts++; return nil }
func (f *fakeRuntime) Halt()                         { f.halts++; f.alive = false }

func TestGuardRestartsDeafCoreAndTakesOverDeadOne(t *testing.T) {
	target, _ := tlsSite(t, false)
	// a port that accepts but never speaks TLS stands in for a hung core
	deaf, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := deaf.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(deaf.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}

	rt := &fakeRuntime{alive: true}
	g := newGuards(rt)
	g.Want(spec.Daemon{Inbounds: []spec.Inbound{{
		Tag: "r", Protocol: spec.ProtoVLESS, Listen: "127.0.0.1", Port: p, Transport: spec.Transport{Type: "tcp"},
		Security: spec.Security{Type: spec.SecurityReality, Reality: &spec.Reality{Dest: target, ServerNames: []string{"site.example.com"}}},
		Options:  spec.Options{Guard: &spec.Guard{Enabled: true, Timeout: 1, Failures: 2}},
	}}})
	for i := 0; i < 2; i++ {
		for _, gd := range g.list {
			gd.next = time.Time{}
		}
		g.round(context.Background())
	}
	if rt.restarts != 1 {
		t.Fatalf("restarts = %d, want 1", rt.restarts)
	}

	deaf.Close()
	rt.alive = false
	g.round(context.Background())
	defer g.releaseAll()
	if err := probeTLS(context.Background(), deaf.Addr().String(), "site.example.com", 5*time.Second, 0); err != nil {
		t.Fatalf("port not served while the core is down: %v", err)
	}
}

func TestGuardGivesUpAfterFailedRestarts(t *testing.T) {
	target, _ := tlsSite(t, false)
	deaf, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := deaf.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(2 * time.Second); c.Close() }()
		}
	}()
	addr := deaf.Addr().(*net.TCPAddr)

	rt := &fakeRuntime{alive: true}
	g := newGuards(rt)
	g.Want(spec.Daemon{Inbounds: []spec.Inbound{{
		Tag: "r", Protocol: spec.ProtoVLESS, Listen: "127.0.0.1", Port: addr.Port, Transport: spec.Transport{Type: "tcp"},
		Security: spec.Security{Type: spec.SecurityReality, Reality: &spec.Reality{Dest: target, ServerNames: []string{"site.example.com"}}},
		Options:  spec.Options{Guard: &spec.Guard{Enabled: true, Timeout: 1, Failures: 1, GiveUp: 2}},
	}}})
	for i := 0; i < 3; i++ {
		for _, gd := range g.list {
			gd.next = time.Time{}
		}
		g.round(context.Background())
	}
	if rt.restarts != 2 || rt.halts != 1 {
		t.Fatalf("restarts = %d, halts = %d, want 2 and 1", rt.restarts, rt.halts)
	}
	deaf.Close()
	g.takeoverAll()
	defer g.releaseAll()
	if err := probeTLS(context.Background(), deaf.Addr().String(), "site.example.com", 5*time.Second, 0); err != nil {
		t.Fatalf("site not served after giving up: %v", err)
	}
}
