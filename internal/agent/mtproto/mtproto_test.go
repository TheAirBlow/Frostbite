package mtproto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"frostbite/internal/spec"
)

// fakeDC speaks the plain obfuscated2 a Telegram data center does, and echoes with a prefix.
func fakeDC(t *testing.T) (addr string, dcs chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	dcs = make(chan int, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				init := make([]byte, initLen)
				if _, err := io.ReadFull(c, init); err != nil {
					return
				}
				dec, enc, _, dc, err := accept(init, nil)
				if err != nil {
					return
				}
				dcs <- dc
				sc := &secretConn{Conn: c, dec: dec, enc: enc}
				buf := make([]byte, 1024)
				for {
					n, err := sc.Read(buf)
					if err != nil {
						return
					}
					if _, err := sc.Write(append([]byte("echo:"), buf[:n]...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), dcs
}

func freePort(t *testing.T) int {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func testInbound(t *testing.T, mode string, secrets map[string][]byte) (*Runtime, int) {
	t.Helper()
	dc, _ := fakeDC(t)
	rt := New()
	rt.dcs = map[int]string{1: dc, 2: dc, 3: dc, 4: dc, 5: dc}
	t.Cleanup(func() { rt.Close() })
	port := freePort(t)
	in := spec.Inbound{Tag: "mt", Protocol: spec.ProtoMTProto, Listen: "127.0.0.1", Port: port, Options: spec.Options{MTMode: mode, MTDomain: "127.0.0.1"}}
	for name, s := range secrets {
		in.Users = append(in.Users, spec.User{Name: name, Password: hex.EncodeToString(s)})
	}
	if err := rt.Apply(nil, spec.Daemon{Inbounds: []spec.Inbound{in}}, nil); err != nil {
		t.Fatal(err)
	}
	return rt, port
}

// clientHello builds what a Telegram client sends first in faketls mode.
func clientHello(secret []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	sid := make([]byte, 32)
	rand.Read(sid)
	body = append(body, sid...)
	body = append(body, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	body = append(body, make([]byte, 40)...)
	hs := append([]byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{recHello, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(rec)
	sum := mac.Sum(nil)
	ts := make([]byte, 4)
	binary.LittleEndian.PutUint32(ts, uint32(time.Now().Unix()))
	for i := 0; i < 4; i++ {
		sum[28+i] ^= ts[i]
	}
	copy(rec[11:43], sum)
	return rec
}

// connect plays a client: handshake, one message, one reply.
func connect(t *testing.T, mode string, port int, secret []byte) (string, error) {
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))

	var wire net.Conn = c
	if mode == "faketls" {
		hello := clientHello(secret)
		c.Write(hello)
		head := make([]byte, 5)
		// the server flight is a hello, a ccs and some data; read all three records
		for i := 0; i < 3; i++ {
			if _, err := io.ReadFull(c, head); err != nil {
				return "", err
			}
			body := make([]byte, binary.BigEndian.Uint16(head[3:5]))
			if _, err := io.ReadFull(c, body); err != nil {
				return "", err
			}
		}
		wire = &recordConn{Conn: c}
	}
	init, enc, dec := dial(secret, tagPadded, 2)
	if _, err := wire.Write(init); err != nil {
		return "", err
	}
	sc := &secretConn{Conn: wire, dec: dec, enc: enc}
	if _, err := sc.Write([]byte("ping")); err != nil {
		return "", err
	}
	buf := make([]byte, 64)
	n, err := sc.Read(buf)
	return string(buf[:n]), err
}

func TestPaddedPerUserSecrets(t *testing.T) {
	alice, bob := make([]byte, 16), make([]byte, 16)
	rand.Read(alice)
	rand.Read(bob)
	rt, port := testInbound(t, "padded", map[string][]byte{"u1": alice, "u2": bob})

	for _, s := range [][]byte{alice, bob} {
		got, err := connect(t, "padded", port, s)
		if err != nil || got != "echo:ping" {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	stranger := make([]byte, 16)
	rand.Read(stranger)
	if got, err := connect(t, "padded", port, stranger); err == nil && got != "" {
		t.Fatalf("a stranger got through: %q", got)
	}

	time.Sleep(100 * time.Millisecond)
	st, _ := rt.Stats(nil)
	if st.Users["u1"].Up == 0 || st.Users["u2"].Down == 0 {
		t.Fatalf("usage not counted: %+v", st.Users)
	}
	if st.Users["u1"].Up != int64(len("ping")) {
		t.Fatalf("u1 up = %d", st.Users["u1"].Up)
	}
}

func TestFakeTLS(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)
	_, port := testInbound(t, "faketls", map[string][]byte{"u1": secret})
	got, err := connect(t, "faketls", port, secret)
	if err != nil || got != "echo:ping" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRemovedUserIsKicked(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)
	rt, port := testInbound(t, "padded", map[string][]byte{"u1": secret})

	c, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	defer c.Close()
	init, enc, dec := dial(secret, tagPadded, 2)
	c.Write(init)
	sc := &secretConn{Conn: c, dec: dec, enc: enc}
	sc.Write([]byte("hi"))
	c.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := sc.Read(buf); err != nil {
		t.Fatal(err)
	}

	in := spec.Inbound{Tag: "mt", Protocol: spec.ProtoMTProto, Listen: "127.0.0.1", Port: port, Options: spec.Options{MTMode: "padded", MTDomain: "127.0.0.1"}}
	if err := rt.Apply(nil, spec.Daemon{Inbounds: []spec.Inbound{in}}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	sc.Write([]byte("again"))
	if _, err := sc.Read(buf); err == nil {
		t.Fatal("the removed user is still connected")
	}
}

func TestFrontsStrangers(t *testing.T) {
	site, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	got := make(chan string, 1)
	go func() {
		c, err := site.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		io.ReadFull(c, buf)
		got <- string(buf)
		c.Write([]byte("hello from the site"))
	}()

	secret := make([]byte, 16)
	rand.Read(secret)
	rt := New()
	defer rt.Close()
	port := freePort(t)
	in := spec.Inbound{Tag: "mt", Protocol: spec.ProtoMTProto, Listen: "127.0.0.1", Port: port,
		Options: spec.Options{MTMode: "faketls", MTDomain: site.Addr().String()},
		Users:   []spec.User{{Name: "u1", Password: hex.EncodeToString(secret)}}}
	if err := rt.Apply(nil, spec.Daemon{Inbounds: []spec.Inbound{in}}, nil); err != nil {
		t.Fatal(err)
	}

	c, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(clientHello(make([]byte, 16))) // a hello made with the wrong secret
	if s := <-got; s[0] != recHello {
		t.Fatalf("site saw %q", s)
	}
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	if string(buf[:n]) != "hello from the site" {
		t.Fatalf("stranger saw %q", buf[:n])
	}
}
