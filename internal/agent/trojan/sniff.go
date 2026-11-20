package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

// sniffName reads the server name a client asks for at the start of a tunnel: the SNI of a TLS hello or the Host of
// an HTTP/1 request. It returns an empty string for anything else.
func sniffName(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == 0x16 {
		return helloName(b)
	}
	head, _, _ := bytes.Cut(b, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	if requestPath(append([]byte(lines[0]), "\r\n"...)) == "" {
		return ""
	}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			host := strings.TrimSpace(v)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return strings.Trim(host, "[]")
		}
	}
	return ""
}

var errSeen = errors.New("hello seen")

// helloName parses a TLS client hello for its server name, without answering it.
func helloName(b []byte) string {
	var name string
	_ = tls.Server(&replayConn{r: bytes.NewReader(b)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errSeen
		},
	}).Handshake()
	return name
}

// replayConn feeds recorded bytes to a TLS server and swallows what it writes.
type replayConn struct{ r *bytes.Reader }

func (c *replayConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *replayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *replayConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }
