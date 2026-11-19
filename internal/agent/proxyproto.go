package agent

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// proxySig opens every PROXY protocol v2 header.
var proxySig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyHeader builds a PROXY protocol header of version 1 or 2. Without tcp addresses it says LOCAL (v2) or UNKNOWN (v1).
func proxyHeader(ver int, src, dst net.Addr) []byte {
	sa, ok1 := src.(*net.TCPAddr)
	da, ok2 := dst.(*net.TCPAddr)
	known := ok1 && ok2 && sa != nil && da != nil
	if ver == 1 {
		if !known {
			return []byte("PROXY UNKNOWN\r\n")
		}
		fam := "TCP4"
		if sa.IP.To4() == nil || da.IP.To4() == nil {
			fam = "TCP6"
		}
		ip := func(a *net.TCPAddr) string {
			if fam == "TCP4" {
				return a.IP.To4().String()
			}
			return a.IP.To16().String()
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, ip(sa), ip(da), sa.Port, da.Port))
	}

	var b bytes.Buffer
	b.Write(proxySig)
	if !known {
		b.Write([]byte{0x20, 0x00, 0x00, 0x00})
		return b.Bytes()
	}
	b.WriteByte(0x21)
	if s4, d4 := sa.IP.To4(), da.IP.To4(); s4 != nil && d4 != nil {
		b.Write([]byte{0x11, 0x00, 0x0C})
		b.Write(s4)
		b.Write(d4)
	} else {
		b.Write([]byte{0x21, 0x00, 0x24})
		b.Write(sa.IP.To16())
		b.Write(da.IP.To16())
	}
	_ = binary.Write(&b, binary.BigEndian, [2]uint16{uint16(sa.Port), uint16(da.Port)})
	return b.Bytes()
}

// readProxyHeader consumes a v1 or v2 PROXY header and returns the addresses it carries, nil for LOCAL or UNKNOWN.
func readProxyHeader(r *bufio.Reader) (src, dst net.Addr, err error) {
	peek, err := r.Peek(len(proxySig))
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(peek, proxySig) {
		return readProxyV2(r)
	}
	if bytes.HasPrefix(peek, []byte("PROXY ")) {
		return readProxyV1(r)
	}
	return nil, nil, errors.New("no PROXY header")
}

func readProxyV1(r *bufio.Reader) (net.Addr, net.Addr, error) {
	var line []byte
	for len(line) < 107 {
		c, err := r.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		line = append(line, c)
		if bytes.HasSuffix(line, []byte("\r\n")) {
			break
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, nil, errors.New("PROXY v1 header too long")
	}
	f := strings.Fields(string(line))
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return nil, nil, nil
	}
	if len(f) != 6 {
		return nil, nil, errors.New("bad PROXY v1 header")
	}
	addr := func(ip, port string) (*net.TCPAddr, error) {
		p, err := strconv.Atoi(port)
		if parsed := net.ParseIP(ip); parsed != nil && err == nil && p >= 0 && p < 65536 {
			return &net.TCPAddr{IP: parsed, Port: p}, nil
		}
		return nil, errors.New("bad address in PROXY v1 header")
	}
	src, err := addr(f[2], f[4])
	if err != nil {
		return nil, nil, err
	}
	dst, err := addr(f[3], f[5])
	if err != nil {
		return nil, nil, err
	}
	return src, dst, nil
}

func readProxyV2(r *bufio.Reader) (net.Addr, net.Addr, error) {
	head := make([]byte, 16)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, nil, err
	}
	if head[12]>>4 != 2 {
		return nil, nil, errors.New("bad PROXY v2 version")
	}
	body := make([]byte, binary.BigEndian.Uint16(head[14:16]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	if head[12]&0x0F == 0 {
		return nil, nil, nil
	}
	switch head[13] >> 4 {
	case 1:
		if len(body) < 12 {
			return nil, nil, errors.New("short PROXY v2 header")
		}
		return &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))},
			&net.TCPAddr{IP: net.IP(body[4:8]), Port: int(binary.BigEndian.Uint16(body[10:12]))}, nil
	case 2:
		if len(body) < 36 {
			return nil, nil, errors.New("short PROXY v2 header")
		}
		return &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))},
			&net.TCPAddr{IP: net.IP(body[16:32]), Port: int(binary.BigEndian.Uint16(body[34:36]))}, nil
	}
	return nil, nil, nil
}
