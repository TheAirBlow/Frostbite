package spec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
)

// UserName is the stable label a user carries inside every core, so stats can be mapped back.
func UserName(id int64) string { return fmt.Sprintf("u%d", id) }

// UserID parses a label made by UserName, reporting false for system users.
func UserID(name string) (int64, bool) {
	var id int64
	if _, err := fmt.Sscanf(name, "u%d", &id); err != nil || UserName(id) != name {
		return 0, false
	}
	return id, true
}

// CredentialsFor derives the per-protocol uuid and password from a user's two master secrets.
// Nothing here is stored, so rotating a master secret rotates every protocol at once.
func CredentialsFor(protocol, method, userUUID, password string) (id, pass string) {
	if protocol == ProtoWireGuard {
		// a private key every user can be handed without storing anything
		mac := hmac.New(sha256.New, []byte(password))
		mac.Write([]byte("wireguard"))
		key := mac.Sum(nil)
		key[0] &= 248
		key[31] = (key[31] & 127) | 64
		return userUUID, base64.StdEncoding.EncodeToString(key)
	}
	if protocol == ProtoMTProto {
		// the 16 byte secret Telegram clients carry, as hex
		mac := hmac.New(sha256.New, []byte(password))
		mac.Write([]byte("mtproto"))
		return userUUID, hex.EncodeToString(mac.Sum(nil)[:16])
	}
	if protocol == ProtoShadowsocks && strings.HasPrefix(method, "2022-") {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		mac := hmac.New(sha256.New, []byte(password))
		mac.Write([]byte("ss2022"))
		return userUUID, base64.StdEncoding.EncodeToString(mac.Sum(nil)[:size])
	}
	return userUUID, password
}

// SystemUser derives a credential for a non-human user such as a chain bridge, keyed by the panel secret.
func SystemUser(secret, name string) User {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(name))
	sum := mac.Sum(nil)
	id, _ := uuid.FromBytes(sum[:16])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return User{Name: name, UUID: id.String(), Password: base64.RawURLEncoding.EncodeToString(sum[16:])}
}

// WGAddress gives a user their address inside a WireGuard subnet, counting up from the first host.
func WGAddress(subnet string, userID int64) (string, error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("the tunnel subnet %q is not a network like 10.8.0.0/16", subnet)
	}
	if !p.Addr().Is4() || p.Bits() > 30 {
		return "", fmt.Errorf("the tunnel subnet must be an ipv4 network with room for users")
	}
	a := p.Masked().Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	host := n + 1 + uint32(userID) // .1 is the server
	if host >= n+(1<<(32-p.Bits()))-1 {
		return "", fmt.Errorf("the subnet %s is too small for user %d", subnet, userID)
	}
	return netip.AddrFrom4([4]byte{byte(host >> 24), byte(host >> 16), byte(host >> 8), byte(host)}).String(), nil
}

// WGServerAddress is the server's own address in the subnet, with the prefix length.
func WGServerAddress(subnet string) (string, error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", err
	}
	a := p.Masked().Addr().As4()
	n := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) + 1
	return fmt.Sprintf("%s/%d", netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), p.Bits()), nil
}
