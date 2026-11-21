package trojan

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"frostbite/internal/spec"
)

// quiet keeps the daemon's log out of benchmark output.
func quiet(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	b.Cleanup(func() { slog.SetDefault(prev) })
}

// sinkServer reads and drops everything it gets.
func sinkServer(t testing.TB) string {
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
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	return l.Addr().String()
}

func BenchmarkUpload(b *testing.B) {
	quiet(b)
	f := newFixture(b, nil)
	c := f.connect(b, "pw1", sinkServer(b), nil)
	chunk := make([]byte, 1<<20)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEcho(b *testing.B) {
	quiet(b)
	f := newFixture(b, nil)
	c := f.connect(b, "pw1", f.echo, nil)
	chunk := make([]byte, 1<<20)
	back := make([]byte, len(chunk))
	b.SetBytes(int64(len(chunk)) * 2)
	b.ReportAllocs()
	for b.Loop() {
		errc := make(chan error, 1)
		go func() { _, err := c.Write(chunk); errc <- err }()
		if _, err := io.ReadFull(c, back); err != nil {
			b.Fatal(err)
		}
		if err := <-errc; err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConnect measures a whole short tunnel: handshake, request, one round trip, close.
func BenchmarkConnect(b *testing.B) {
	quiet(b)
	for _, tc := range []struct {
		name string
		dst  func(f *fixture) string
	}{
		{"address", func(f *fixture) string { return f.echo }},
		{"name", func(f *fixture) string {
			_, port, _ := net.SplitHostPort(f.echo)
			return net.JoinHostPort("localhost", port)
		}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			f := newFixture(b, func(in *spec.Inbound) { in.Sniffing.Enabled = false })
			dst := tc.dst(f)
			cache := tls.NewLRUClientSessionCache(1)
			b.ReportAllocs()
			for b.Loop() {
				c, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache})
				if err != nil {
					b.Fatal(err)
				}
				if _, err := c.Write(append(header("pw1", cmdConnect, dst), 'x')); err != nil {
					b.Fatal(err)
				}
				var one [1]byte
				if _, err := io.ReadFull(c, one[:]); err != nil {
					b.Fatal(err)
				}
				c.Close()
			}
		})
	}
}

func BenchmarkUDP(b *testing.B) {
	quiet(b)
	f := newFixture(b, nil)
	echo := udpEcho(b)
	c := f.dialTLS(b, nil)
	if _, err := c.Write(header("pw1", cmdUDP, echo)); err != nil {
		b.Fatal(err)
	}
	pk := &trojanPackets{r: c, w: c}
	to := addrOf(netip.MustParseAddrPort(echo))
	pkt, back := make([]byte, 1200), make([]byte, maxPacket)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		if err := pk.writePacket(pkt, to); err != nil {
			b.Fatal(err)
		}
		if _, _, err := pk.readPacket(back); err != nil {
			b.Fatal(err)
		}
	}
}
