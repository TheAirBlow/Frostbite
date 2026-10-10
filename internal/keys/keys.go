// Package keys generates the secrets the panel hands out.
package keys

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// Pair is a public/private key pair, encoded the way the target core expects.
type Pair struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

// Reality returns an x25519 pair in the unpadded url-safe base64 REALITY uses.
func Reality() (Pair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Pair{}, err
	}
	enc := base64.RawURLEncoding
	return Pair{Private: enc.EncodeToString(priv.Bytes()), Public: enc.EncodeToString(priv.PublicKey().Bytes())}, nil
}

// WireGuard returns an x25519 pair in standard padded base64.
func WireGuard() (Pair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Pair{}, err
	}
	enc := base64.StdEncoding
	return Pair{Private: enc.EncodeToString(priv.Bytes()), Public: enc.EncodeToString(priv.PublicKey().Bytes())}, nil
}

// RealityPublic derives the public key from a REALITY private key.
func RealityPublic(private string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil {
		return "", fmt.Errorf("private key is not base64: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("private key is not a valid x25519 key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// ShortID returns a random REALITY short id of n bytes (1-8).
func ShortID(n int) (string, error) {
	n = max(1, min(n, 8))
	return Hex(n)
}

// Hex returns n random bytes as hex.
func Hex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Token returns a url-safe random string with n bytes of entropy.
func Token(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// UUID returns a fresh v4 uuid.
func UUID() string { return uuid.NewString() }

// SS2022 returns a base64 key sized for the given 2022 cipher.
func SS2022(method string) (string, error) {
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// TurnablePair is an ML-KEM-768 key pair, both halves base64 encoded the way Turnable reads them.
type TurnablePair struct{ Private, Public string }

// Turnable generates the key pair of a Turnable server.
func Turnable() (TurnablePair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return TurnablePair{}, err
	}
	return TurnablePair{
		Private: base64.StdEncoding.EncodeToString(dk.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes()),
	}, nil
}

// WireGuardPublic derives the public key from a WireGuard private key.
func WireGuardPublic(private string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return "", fmt.Errorf("private key is not base64: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("private key is not a valid x25519 key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
