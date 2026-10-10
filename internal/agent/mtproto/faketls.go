package mtproto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// TLS record types.
const (
	recCCS   = 0x14
	recData  = 0x17
	recHello = 0x16
)

// helloSkew is how far a client's clock may be from ours.
const helloSkew = 5 * time.Minute

// maxRecord is the biggest payload one record carries.
const maxRecord = 16384

var errNotHello = errors.New("not a faketls hello")

// readHello reads one whole TLS record, which should hold a client hello.
func readHello(r io.Reader) ([]byte, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[3:5]))
	if head[0] != recHello || head[1] != 3 || n < 80 || n > maxRecord {
		return head, errNotHello
	}
	rec := make([]byte, 5+n)
	copy(rec, head)
	_, err := io.ReadFull(r, rec[5:])
	return rec, err
}

// helloMAC computes the digest the client hid in its random field.
func helloMAC(secret, rec []byte) []byte {
	zeroed := append([]byte(nil), rec...)
	clear(zeroed[11:43])
	m := hmac.New(sha256.New, secret)
	m.Write(zeroed)
	return m.Sum(nil)
}

// checkHello tells whether rec was made by a client holding secret.
func checkHello(secret, rec []byte, now time.Time) bool {
	if len(rec) < 44 {
		return false
	}
	random := rec[11:43]
	mac := helloMAC(secret, rec)
	if !hmac.Equal(mac[:28], random[:28]) {
		return false
	}
	ts := int64(binary.LittleEndian.Uint32(random[28:32]) ^ binary.LittleEndian.Uint32(mac[28:32]))
	d := now.Sub(time.Unix(ts, 0))
	return d > -helloSkew && d < helloSkew
}

// sessionID pulls the session id out of a hello record.
func sessionID(rec []byte) []byte {
	n := int(rec[43])
	if 44+n > len(rec) {
		return nil
	}
	return rec[44 : 44+n]
}

// serverFlight builds the answer a real TLS 1.3 server would give, signed so the client knows it is us.
func serverFlight(secret, rec []byte) ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sid := sessionID(rec)

	exts := []byte{0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}
	exts = append(exts, key.PublicKey().Bytes()...)
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random, filled in once we can sign
	body = append(body, byte(len(sid)))
	body = append(body, sid...)
	body = append(body, 0x13, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	out := []byte{recHello, 3, 3}
	out = binary.BigEndian.AppendUint16(out, uint16(len(hs)))
	out = append(out, hs...)
	out = append(out, recCCS, 3, 3, 0, 1, 1)

	pad, _ := rand.Int(rand.Reader, big.NewInt(1000))
	junk := make([]byte, 2500+int(pad.Int64()))
	_, _ = rand.Read(junk)
	out = append(out, recData, 3, 3)
	out = binary.BigEndian.AppendUint16(out, uint16(len(junk)))
	out = append(out, junk...)

	m := hmac.New(sha256.New, secret)
	m.Write(rec[11:43])
	m.Write(out)
	copy(out[11:43], m.Sum(nil))
	return out, nil
}

// replays remembers hello randoms for a while so a captured hello cannot be played back.
type replays struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

// fresh reports whether random is new, and remembers it.
func (r *replays) fresh(random []byte, now time.Time) bool {
	var k [32]byte
	copy(k[:], random)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[[32]byte]time.Time{}
	}
	if len(r.seen) > 4096 {
		for key, at := range r.seen {
			if now.Sub(at) > 2*helloSkew {
				delete(r.seen, key)
			}
		}
	}
	if _, dup := r.seen[k]; dup {
		return false
	}
	r.seen[k] = now
	return true
}

// recordConn carries a byte stream inside tls application data records.
type recordConn struct {
	net.Conn
	left int // bytes of the current record not read yet
}

func (c *recordConn) Read(p []byte) (int, error) {
	for c.left == 0 {
		head := make([]byte, 5)
		if _, err := io.ReadFull(c.Conn, head); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(head[3:5]))
		switch head[0] {
		case recData:
			c.left = n
		case recCCS:
			if _, err := io.CopyN(io.Discard, c.Conn, int64(n)); err != nil {
				return 0, err
			}
		default:
			return 0, errors.New("unexpected tls record")
		}
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= n
	return n, err
}

func (c *recordConn) Write(p []byte) (int, error) {
	sent := 0
	for len(p) > 0 {
		n := min(len(p), maxRecord-64)
		buf := make([]byte, 0, 5+n)
		buf = append(buf, recData, 3, 3)
		buf = binary.BigEndian.AppendUint16(buf, uint16(n))
		buf = append(buf, p[:n]...)
		if _, err := c.Conn.Write(buf); err != nil {
			return sent, err
		}
		sent += n
		p = p[n:]
	}
	return sent, nil
}
