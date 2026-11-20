package trojan

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"

	coretrojan "frostbite/internal/core/trojan"
	"frostbite/internal/spec"
)

// serverTLS builds the TLS side of an inbound, reading its certificate files.
func serverTLS(t coretrojan.TLS) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		NextProtos:             t.ALPN,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: t.NoTickets,
	}
	switch t.MinTLS {
	case "", "1.2":
	case "1.3":
		cfg.MinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("unknown TLS version %q", t.MinTLS)
	}
	for _, name := range t.Ciphers {
		id, ok := spec.TrojanCipher(name)
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite %q", name)
		}
		cfg.CipherSuites = append(cfg.CipherSuites, id)
	}
	for _, name := range t.Curves {
		id, ok := spec.TrojanCurve(name)
		if !ok {
			return nil, fmt.Errorf("unknown key exchange group %q", name)
		}
		cfg.CurvePreferences = append(cfg.CurvePreferences, id)
	}
	if t.ECHKey != "" {
		keys, err := echKeys(t.ECHKey)
		if err != nil {
			return nil, fmt.Errorf("ECH key: %w", err)
		}
		cfg.EncryptedClientHelloKeys = keys
	}
	return cfg, nil
}

// echKeys reads ECH keys as sing-box writes them (an ECH KEYS pem block) or as Xray does (the same bytes in base64):
// pairs of a private key and its config, each prefixed by a 16 bit length.
func echKeys(text string) ([]tls.EncryptedClientHelloKey, error) {
	var raw []byte
	if strings.Contains(text, "-----BEGIN") {
		block, _ := pem.Decode([]byte(text))
		if block == nil || block.Type != "ECH KEYS" {
			return nil, errors.New("not an ECH KEYS pem block")
		}
		raw = block.Bytes
	} else {
		var err error
		if raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(text)); err != nil {
			return nil, errors.New("neither pem nor base64")
		}
	}
	var keys []tls.EncryptedClientHelloKey
	s := cryptobyte.String(raw)
	for !s.Empty() {
		var key, config cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&key) || !s.ReadUint16LengthPrefixed(&config) {
			return nil, errors.New("malformed key list")
		}
		keys = append(keys, tls.EncryptedClientHelloKey{Config: config, PrivateKey: key, SendAsRetry: true})
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys")
	}
	return keys, nil
}
