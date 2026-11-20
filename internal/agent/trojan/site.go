package trojan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"

	coretrojan "frostbite/internal/core/trojan"
	"frostbite/internal/spec"
)

// visit is someone who is not a trojan user, on their way to the site.
type visit struct {
	conn      net.Conn      // the visitor, after TLS when there was any
	br        *bufio.Reader // what the visitor already sent, followed by the rest
	sni, alpn string
	src, dst  net.Addr // the two ends of the visitor's connection, for the PROXY header
}

var discardLog = log.New(io.Discard, "", 0)

// site sends a visitor on to the real site, either byte for byte or, when headers have to be added, request by request.
func (s *server) site(v visit, st *state) {
	site := st.ib.Site
	if site.HTTP() {
		s.siteHTTP(v, site)
		return
	}
	head, _ := v.br.Peek(v.br.Buffered())
	dest := pickDest(site, v.sni, v.alpn, requestPath(head))
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	up, err := dialSite(ctx, site, dest, v, v.alpn)
	cancel()
	if err != nil {
		s.rt.logf(levelWarning, "could not reach the site %s: %v", dest, err)
		return
	}
	defer up.Close()
	relay(&bufConn{Conn: v.conn, r: v.br}, up)
}

// siteHTTP serves a visitor as an HTTP server and passes every request to the site with the extra headers set.
func (s *server) siteHTTP(v visit, site coretrojan.Site) {
	ip := addrIP(v.src)
	tr := &http.Transport{
		// each visitor gets connections of their own, so the PROXY header and the server name are always theirs
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialSite(ctx, site, address, v, "http/1.1")
		},
		MaxIdleConnsPerHost: 4,
		DisableCompression:  true, // the visitor gets the site's bytes as they are
		IdleConnTimeout:     90 * time.Second,
	}
	defer tr.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pickDest(site, v.sni, v.alpn, pr.In.URL.Path)
			pr.Out.Host = pr.In.Host
			if site.IPHeader != "" {
				pr.Out.Header.Set(site.IPHeader, ip)
			}
			for k, val := range site.Headers {
				pr.Out.Header.Set(k, val)
			}
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      discardLog,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.rt.logf(levelWarning, "could not reach the site for %s: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	conn := &bufConn{Conn: v.conn, r: v.br}
	head, _ := v.br.Peek(min(v.br.Buffered(), len(http2.ClientPreface)))
	if v.alpn == "h2" || string(head) == http2.ClientPreface {
		(&http2.Server{IdleTimeout: 75 * time.Second}).ServeConn(conn, &http2.ServeConnOpts{
			Handler: proxy, BaseConfig: &http.Server{ErrorLog: discardLog},
		})
		return
	}
	closed := make(chan struct{})
	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: requestTimeout, IdleTimeout: 75 * time.Second, ErrorLog: discardLog}
	go func() { _ = srv.Serve(&oneConn{conn: &notifyConn{Conn: conn, closed: closed}}) }()
	<-closed
}

// dialSite connects to the site: the PROXY header first when asked for, then TLS when the site speaks it.
func dialSite(ctx context.Context, site coretrojan.Site, dest string, v visit, alpn string) (net.Conn, error) {
	d := net.Dialer{KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}
	if site.Proxy > 0 {
		if _, err := proxyproto.HeaderProxyFromAddrs(byte(site.Proxy), v.src, v.dst).WriteTo(c); err != nil {
			c.Close()
			return nil, err
		}
	}
	if !site.TLS {
		return c, nil
	}
	name := site.SNI
	if name == "" {
		name = v.sni
	}
	if name == "" {
		name, _, _ = net.SplitHostPort(dest)
	}
	cfg := &tls.Config{ServerName: name, InsecureSkipVerify: site.Insecure}
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("tls: %w", err)
	}
	return tc, nil
}

// pickDest finds where a visitor goes: by server name, then by ALPN, then by path, as Xray's fallbacks do.
func pickDest(site coretrojan.Site, sni, alpn, path string) string {
	if d := byName(site.BySNI, sni); d != "" {
		return d
	}
	if d, ok := site.ByALPN[alpn]; ok && alpn != "" {
		return d
	}
	if path != "" {
		best, dest := "", ""
		for p, d := range site.ByPath {
			if strings.HasPrefix(path, p) && len(p) > len(best) {
				best, dest = p, d
			}
		}
		if dest != "" {
			return dest
		}
	}
	return site.Dest
}

// byName looks a server name up among exact names first and *.example.com patterns second, longest first.
func byName(m map[string]string, name string) string {
	if name == "" || len(m) == 0 {
		return ""
	}
	name = strings.ToLower(name)
	for k, d := range m {
		if strings.EqualFold(k, name) {
			return d
		}
	}
	best, dest := "", ""
	for k, d := range m {
		if rest, ok := strings.CutPrefix(strings.ToLower(k), "*."); ok && strings.HasSuffix(name, "."+rest) && len(rest) > len(best) {
			best, dest = rest, d
		}
	}
	return dest
}

// requestPath is the path of an HTTP/1 request line at the start of b, empty when b does not start with one.
func requestPath(b []byte) string {
	line, _, ok := bytes.Cut(b, []byte("\r\n"))
	if !ok {
		return ""
	}
	f := strings.Fields(string(line))
	if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/") {
		return ""
	}
	path, _, _ := strings.Cut(f[1], "?")
	return path
}

// nginxPlain is what nginx answers when plain HTTP reaches its TLS port.
const nginxPlain = "<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n<body>\r\n" +
	"<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was sent to HTTPS port</center>\r\n" +
	"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

// plain answers someone who speaks plain HTTP to the TLS port, as the inbound asks.
func (s *server) plain(c net.Conn, br *bufio.Reader, st *state) {
	switch st.ib.Plain {
	case spec.TrojanPlainSite:
		_ = c.SetDeadline(time.Time{})
		s.site(visit{conn: c, br: br, src: c.RemoteAddr(), dst: c.LocalAddr()}, st)
	case spec.TrojanPlainRedirect, spec.TrojanPlainNginx:
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		var resp string
		if st.ib.Plain == spec.TrojanPlainNginx {
			resp = fmt.Sprintf("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				time.Now().UTC().Format(http.TimeFormat), len(nginxPlain), nginxPlain)
		} else {
			host := strings.TrimSuffix(req.Host, ":443")
			resp = fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host, req.URL.RequestURI())
		}
		_, _ = io.WriteString(c, resp)
	}
}

// oneConn is a listener that hands out a single connection.
type oneConn struct {
	once sync.Once
	conn net.Conn
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

// notifyConn says when it was closed.
type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}
