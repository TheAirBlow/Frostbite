package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"frostbite/internal/spec"
)

// ensureCerts points TLS inbounds without certificate files, or whose files are missing, at a self signed stand-in
// under dir, so a fresh setup starts without writing into folders another tool owns. It returns the tags waiting for
// files that may still appear. Clients must allow insecure certificates while a stand-in is served.
func ensureCerts(d *spec.Daemon, dir string) []string {
	var redirected []string
	for i := range d.Inbounds {
		in := &d.Inbounds[i]
		s := &in.Security
		if s.Type != spec.SecurityTLS || s.ACME != nil || s.Existing != nil {
			continue
		}
		none := s.CertPath == "" && s.KeyPath == ""
		if !none && fileExists(s.CertPath) && fileExists(s.KeyPath) {
			continue
		}
		cert, key := filepath.Join(dir, in.Tag, "fullchain.pem"), filepath.Join(dir, in.Tag, "privkey.pem")
		if !fileExists(cert) || !fileExists(key) {
			if err := selfSigned(cert, key, s.SNI); err != nil {
				slog.Warn("could not create a placeholder certificate", "inbound", in.Tag, "err", err)
				continue
			}
		}
		if none {
			s.CertPath, s.KeyPath = cert, key
			continue
		}
		slog.Warn("certificate not found, serving a self signed stand-in until it appears", "inbound", in.Tag, "cert", s.CertPath)
		s.CertPath, s.KeyPath = cert, key
		redirected = append(redirected, in.Tag)
	}
	return redirected
}

// fileExists reports whether path is a readable file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// selfSigned writes a ten year ECDSA certificate for name.
func selfSigned(certPath, keyPath, name string) error {
	if name == "" {
		name = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// testTLS checks that dest completes a TLS 1.3 handshake with h2, which is what a REALITY target must do. sni is the name
// to ask for, the target's host when empty, and xver sends a PROXY header first for targets that expect one.
func testTLS(ctx context.Context, dest, sni string, xver int) (string, error) {
	if dest == "" {
		return "", fmt.Errorf("no target given")
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		return "", fmt.Errorf("target must look like host:port")
	}
	if sni == "" {
		sni = host
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", dest)
	if err != nil {
		return "", explainDial(err, dest, sni, xver)
	}
	defer raw.Close()
	if xver > 0 {
		// a real client's address, as the core sends it, so rules that filter by client IP show up here too
		if _, err := raw.Write(proxyHeader(xver, probeClient, raw.LocalAddr())); err != nil {
			return "", err
		}
	}
	// the certificate is checked by hand so a mismatch is reported rather than hiding the rest of the result
	conn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", explainDial(err, dest, sni, xver)
	}

	st := conn.ConnectionState()
	out := fmt.Sprintf("%s (%s) in %dms, %s, alpn %q", dest, sni, time.Since(start).Milliseconds(), tls.VersionName(st.Version), st.NegotiatedProtocol)
	if st.Version != tls.VersionTLS13 {
		return out, fmt.Errorf("the target does not speak TLS 1.3, REALITY needs it")
	}
	if st.NegotiatedProtocol != "h2" {
		return out, fmt.Errorf("the target does not offer h2, pick another one")
	}
	if len(st.PeerCertificates) > 0 && net.ParseIP(sni) == nil {
		if err := st.PeerCertificates[0].VerifyHostname(sni); err != nil {
			return out, fmt.Errorf("the target's certificate is not for %s", sni)
		}
	}
	return out, nil
}

// probeClient is the client address a probe puts in its PROXY header, from a range reserved for documentation.
var probeClient = &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 40000}

// explainDial turns the errors a handshake probe runs into into something a person can act on.
func explainDial(err error, dest, sni string, xver int) error {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("nothing is listening on %s", dest)
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s did not answer in time. Check the address and that the node can reach it", dest)
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), strings.Contains(err.Error(), "connection reset"),
		strings.Contains(err.Error(), "remote error: tls:"):
		hint := "it may expect a PROXY header, or it is not a TLS site"
		switch {
		case net.ParseIP(sni) != nil:
			hint = "it probably needs a server name and none was sent. Add one under Server names"
		case xver > 0:
			hint = "it got a PROXY header naming an outside client " + probeClient.IP.String() + ". It may not accept the header, or it drops clients by IP once it reads it"
		}
		return fmt.Errorf("%s refused the handshake (%s)", dest, hint)
	}
	return err
}
