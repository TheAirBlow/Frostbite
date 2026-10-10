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
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"frostbite/internal/spec"
)

// ensureCerts writes a self signed certificate for any TLS inbound whose files are missing, so a fresh setup starts.
// Clients must be told to allow insecure certificates until a real one is dropped in the same place.
func ensureCerts(d spec.Daemon) {
	for _, in := range d.Inbounds {
		s := in.Security
		if s.Type != spec.SecurityTLS || s.CertPath == "" || s.KeyPath == "" {
			continue
		}
		if fileExists(s.CertPath) && fileExists(s.KeyPath) {
			continue
		}
		if err := selfSigned(s.CertPath, s.KeyPath, s.SNI); err != nil {
			slog.Warn("could not create a placeholder certificate", "inbound", in.Tag, "err", err)
			continue
		}
		slog.Warn("no certificate found, created a self signed one", "inbound", in.Tag, "cert", s.CertPath)
	}
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

// testTLS checks that dest completes a TLS 1.3 handshake with h2, which is what a REALITY target must do.
func testTLS(ctx context.Context, dest string) (string, error) {
	if dest == "" {
		return "", fmt.Errorf("no target given")
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		return "", fmt.Errorf("target must look like host:port")
	}

	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config:    &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
	}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	st := conn.(*tls.Conn).ConnectionState()
	out := fmt.Sprintf("%s in %dms, %s, alpn %q", dest, time.Since(start).Milliseconds(), tls.VersionName(st.Version), st.NegotiatedProtocol)
	if st.Version != tls.VersionTLS13 {
		return out, fmt.Errorf("the target does not speak TLS 1.3, REALITY needs it")
	}
	if st.NegotiatedProtocol != "h2" {
		return out, fmt.Errorf("the target does not offer h2, pick another one")
	}
	return out, nil
}
