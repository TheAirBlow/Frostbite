package mtproto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"slices"
)

// Transport tags a client puts in its handshake.
var (
	tagAbridged     = [4]byte{0xef, 0xef, 0xef, 0xef}
	tagIntermediate = [4]byte{0xee, 0xee, 0xee, 0xee}
	tagPadded       = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}
)

// initLen is the size of the obfuscated2 handshake.
const initLen = 64

// ctr makes an AES-256-CTR stream.
func ctr(key, iv []byte) cipher.Stream {
	b, _ := aes.NewCipher(key)
	return cipher.NewCTR(b, iv)
}

// reversed returns a reversed copy.
func reversed(b []byte) []byte {
	r := slices.Clone(b)
	slices.Reverse(r)
	return r
}

// withSecret mixes a secret into a key the way Telegram clients do.
func withSecret(key, secret []byte) []byte {
	if len(secret) == 0 {
		return key
	}
	sum := sha256.Sum256(append(slices.Clone(key), secret...))
	return sum[:]
}

// accept reads a client's handshake and works out the two ciphers, or reports a secret mismatch.
func accept(init []byte, secret []byte) (dec, enc cipher.Stream, tag [4]byte, dc int, err error) {
	dec = ctr(withSecret(init[8:40], secret), init[40:56])
	plain := make([]byte, initLen)
	dec.XORKeyStream(plain, init)
	copy(tag[:], plain[56:60])
	if tag != tagAbridged && tag != tagIntermediate && tag != tagPadded {
		return nil, nil, tag, 0, errors.New("wrong secret")
	}
	dc = int(int16(binary.LittleEndian.Uint16(plain[60:62])))
	rev := reversed(init[8:56])
	enc = ctr(withSecret(rev[:32], secret), rev[32:48])
	return dec, enc, tag, dc, nil
}

// forbidden are first words an obfuscated stream may not start with, because they look like other protocols.
func forbidden(b []byte) bool {
	if b[0] == 0xef {
		return true
	}
	switch string(b[:4]) {
	case "HEAD", "POST", "GET ", "OPTI", "\xdd\xdd\xdd\xdd", "\xee\xee\xee\xee", "\x16\x03\x01\x02":
		return true
	}
	return bytes.Equal(b[4:8], []byte{0, 0, 0, 0})
}

// dial builds a handshake to send, plus the ciphers for the stream that follows it.
func dial(secret []byte, tag [4]byte, dc int) (init []byte, enc, dec cipher.Stream) {
	init = make([]byte, initLen)
	for {
		_, _ = rand.Read(init)
		if !forbidden(init) {
			break
		}
	}
	copy(init[56:60], tag[:])
	binary.LittleEndian.PutUint16(init[60:62], uint16(int16(dc)))

	enc = ctr(withSecret(init[8:40], secret), init[40:56])
	sealed := make([]byte, initLen)
	enc.XORKeyStream(sealed, init)
	copy(init[56:], sealed[56:])

	rev := reversed(init[8:56])
	dec = ctr(withSecret(rev[:32], secret), rev[32:48])
	return init, enc, dec
}

// secretConn encrypts everything written and decrypts everything read.
type secretConn struct {
	net.Conn
	dec, enc cipher.Stream
}

func (c *secretConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.dec.XORKeyStream(p[:n], p[:n])
	return n, err
}

func (c *secretConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	c.enc.XORKeyStream(buf, p)
	return c.Conn.Write(buf)
}
