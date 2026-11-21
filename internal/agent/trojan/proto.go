package trojan

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
)

// The trojan request, see https://trojan-gfw.github.io/trojan/protocol.
const (
	hashLen = 56 // hex(SHA224(password))

	cmdConnect = 0x01
	cmdUDP     = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

var (
	errShort = errors.New("request is not complete yet")
	errBad   = errors.New("not a trojan request")
)

// addr is a destination as the client names it: a domain name or an address.
type addr struct {
	host string // a domain name, empty when ip is set
	ip   netip.Addr
	port uint16
}

func (a addr) String() string {
	if a.host != "" {
		return net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
	}
	return netip.AddrPortFrom(a.ip, a.port).String()
}

// socks is the address in sing's form.
func (a addr) socks() M.Socksaddr {
	if a.host != "" {
		return M.Socksaddr{Fqdn: a.host, Port: a.port}
	}
	return M.SocksaddrFrom(a.ip, a.port)
}

// addrOf turns a resolved address into a destination.
func addrOf(ap netip.AddrPort) addr { return addr{ip: ap.Addr().Unmap(), port: ap.Port()} }

// request is a parsed trojan header.
type request struct {
	hash string
	cmd  byte
	dst  addr
	size int // bytes the header took, payload follows
}

// parseRequest reads a trojan header from the start of b. It returns errShort while b could still become one and errBad
// as soon as it cannot, so strangers are sent to the site without waiting. known says whether a password hash belongs to
// a user, which is checked before anything after it.
func parseRequest(b []byte, known func(string) bool) (request, error) {
	for i := 0; i < len(b) && i < hashLen; i++ {
		if !isLowerHex(b[i]) {
			return request{}, errBad
		}
	}
	if len(b) < hashLen+2 {
		return request{}, errShort
	}
	if b[hashLen] != '\r' || b[hashLen+1] != '\n' || !known(string(b[:hashLen])) {
		return request{}, errBad
	}
	req := request{hash: string(b[:hashLen])}
	rest := b[hashLen+2:]
	if len(rest) < 1 {
		return request{}, errShort
	}
	req.cmd = rest[0]
	if req.cmd != cmdConnect && req.cmd != cmdUDP {
		return request{}, errBad
	}
	dst, n, err := parseAddr(rest[1:])
	if err != nil {
		return request{}, err
	}
	rest = rest[1+n:]
	if len(rest) < 2 {
		return request{}, errShort
	}
	if rest[0] != '\r' || rest[1] != '\n' {
		return request{}, errBad
	}
	req.dst = dst
	req.size = hashLen + 2 + 1 + n + 2
	return req, nil
}

// parseAddr reads ATYP ADDR PORT from b and says how many bytes it took.
func parseAddr(b []byte) (addr, int, error) {
	if len(b) < 1 {
		return addr{}, 0, errShort
	}
	var a addr
	var n int
	switch b[0] {
	case atypIPv4:
		n = 1 + 4
		if len(b) < n+2 {
			return addr{}, 0, errShort
		}
		a.ip = netip.AddrFrom4([4]byte(b[1:5]))
	case atypIPv6:
		n = 1 + 16
		if len(b) < n+2 {
			return addr{}, 0, errShort
		}
		a.ip = netip.AddrFrom16([16]byte(b[1:17])).Unmap()
	case atypDomain:
		if len(b) < 2 {
			return addr{}, 0, errShort
		}
		n = 2 + int(b[1])
		if b[1] == 0 {
			return addr{}, 0, errBad
		}
		if len(b) < n+2 {
			return addr{}, 0, errShort
		}
		a.host = string(b[2:n])
		// some clients put an address where a name goes
		if ip, err := netip.ParseAddr(a.host); err == nil {
			a.host, a.ip = "", ip.Unmap()
		}
	default:
		return addr{}, 0, errBad
	}
	a.port = binary.BigEndian.Uint16(b[n:])
	return a, n + 2, nil
}

// appendAddr writes ATYP ADDR PORT.
func appendAddr(b []byte, a addr) []byte {
	switch {
	case a.host != "":
		b = append(b, atypDomain, byte(len(a.host)))
		b = append(b, a.host...)
	case a.ip.Is4():
		ip := a.ip.As4()
		b = append(b, atypIPv4)
		b = append(b, ip[:]...)
	default:
		ip := a.ip.As16()
		b = append(b, atypIPv6)
		b = append(b, ip[:]...)
	}
	return binary.BigEndian.AppendUint16(b, a.port)
}

func isLowerHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// maxPacket is the largest UDP payload a trojan packet can carry.
const maxPacket = 65535

// trojanPackets carries UDP packets over a trojan stream, each framed as ATYP ADDR PORT LENGTH CRLF PAYLOAD.
type trojanPackets struct {
	r  io.Reader
	w  io.Writer
	mu sync.Mutex
	wb []byte
}

func (p *trojanPackets) readPacket(buf []byte) (int, addr, error) {
	var head [1 + 1 + 255 + 2]byte
	if _, err := io.ReadFull(p.r, head[:1]); err != nil {
		return 0, addr{}, err
	}
	var rest int
	switch head[0] {
	case atypIPv4:
		rest = 4 + 2
	case atypIPv6:
		rest = 16 + 2
	case atypDomain:
		if _, err := io.ReadFull(p.r, head[1:2]); err != nil {
			return 0, addr{}, err
		}
		rest = int(head[1]) + 2
	default:
		return 0, addr{}, errBad
	}
	start := 1
	if head[0] == atypDomain {
		start = 2
	}
	if _, err := io.ReadFull(p.r, head[start:start+rest]); err != nil {
		return 0, addr{}, err
	}
	dst, _, err := parseAddr(head[:start+rest])
	if err != nil {
		return 0, addr{}, errBad
	}
	var tail [4]byte
	if _, err := io.ReadFull(p.r, tail[:]); err != nil {
		return 0, addr{}, err
	}
	if tail[2] != '\r' || tail[3] != '\n' {
		return 0, addr{}, errBad
	}
	size := int(binary.BigEndian.Uint16(tail[:2]))
	if size > len(buf) {
		return 0, addr{}, errBad
	}
	if _, err := io.ReadFull(p.r, buf[:size]); err != nil {
		return 0, addr{}, err
	}
	return size, dst, nil
}

func (p *trojanPackets) writePacket(b []byte, from addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wb = appendAddr(p.wb[:0], from)
	p.wb = binary.BigEndian.AppendUint16(p.wb, uint16(len(b)))
	p.wb = append(p.wb, '\r', '\n')
	p.wb = append(p.wb, b...)
	_, err := p.w.Write(p.wb)
	return err
}
