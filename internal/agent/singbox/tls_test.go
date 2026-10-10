//go:build !race

package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"frostbite/internal/spec"
)

// selfSignedFiles writes a certificate for localhost into dir.
func selfSignedFiles(t *testing.T) (cert, key string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kd, _ := x509.MarshalECPrivateKey(k)
	dir := t.TempDir()
	cert, key = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return cert, key
}

func TestTLSProtocolsChangeUsersLive(t *testing.T) {
	cert, key := selfSignedFiles(t)
	sec := spec.Security{Type: spec.SecurityTLS, SNI: "localhost", CertPath: cert, KeyPath: key}
	clientTLS := map[string]any{"enabled": true, "server_name": "localhost", "insecure": true}
	c := hotCase{
		protocol: spec.ProtoAnyTLS, security: sec,
		user: func(n int64) spec.User {
			return spec.User{ID: n, Name: fmt.Sprintf("u%d", n), Password: uuid.NewString()}
		},
		outbound: func(u spec.User) map[string]any {
			return map[string]any{"type": "anytls", "password": u.Password, "tls": clientTLS}
		},
	}
	t.Run(c.protocol, func(t *testing.T) { runHotCase(t, c) })
}
