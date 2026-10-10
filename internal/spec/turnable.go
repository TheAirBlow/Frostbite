package spec

import (
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// TurnableRoute is the id of the one route every Turnable server offers.
const TurnableRoute = "main"

// Turnable defaults, used when an option is left empty.
const (
	TurnablePlatform   = "vk.com"
	TurnableProto      = "dtls"
	TurnableTransport  = "mpath"
	TurnableEncryption = "handshake"
	TurnablePeers      = 5
)

// TurnableTarget splits the destination into an address and a port.
func (o Options) TurnableTarget() (string, int, error) {
	host, port, err := net.SplitHostPort(o.TTarget)
	if err != nil {
		return "", 0, fmt.Errorf("the destination must look like 10.0.0.1:443")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("the destination port %q is not valid", port)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", 0, fmt.Errorf("the destination host must be an IP address")
	}
	return host, n, nil
}

// validateTurnable checks the Turnable fields of an inbound.
func (o Options) validateTurnable() error {
	if p := o.TPlatform; p != "" && p != TurnablePlatform {
		return fmt.Errorf("unknown platform %q", p)
	}
	if o.TCallID == "" {
		return fmt.Errorf("a call id is required")
	}
	switch o.TProto {
	case "", "dtls", "srtp", "none":
	default:
		return fmt.Errorf("unknown wrapper %q", o.TProto)
	}
	switch o.TEncryption {
	case "", "handshake", "full":
	default:
		return fmt.Errorf("unknown encryption mode %q", o.TEncryption)
	}
	transport := o.TTransport
	switch transport {
	case "":
		transport = TurnableTransport
	case "mpath", "kcp", "sctp", "none":
	default:
		return fmt.Errorf("unknown route transport %q", transport)
	}
	switch o.TSocket {
	case "tcp":
		if transport == "none" {
			return fmt.Errorf("tcp needs a route transport other than none")
		}
	case "udp":
	default:
		return fmt.Errorf("pick tcp or udp for the destination socket")
	}
	if _, _, err := o.TurnableTarget(); err != nil {
		return err
	}
	if o.TPeers < 0 {
		return fmt.Errorf("peer connections cannot be negative")
	}
	pub, err := base64.StdEncoding.DecodeString(o.TPublic)
	if err != nil {
		return fmt.Errorf("the public key is not base64")
	}
	if _, err := mlkem.NewEncapsulationKey768(pub); err != nil {
		return fmt.Errorf("the public key is not an ML-KEM-768 key")
	}
	priv, err := base64.StdEncoding.DecodeString(o.TPrivate)
	if err != nil {
		return fmt.Errorf("the private key is not base64")
	}
	if _, err := mlkem.NewDecapsulationKey768(priv); err != nil {
		return fmt.Errorf("the private key is not an ML-KEM-768 key")
	}
	return nil
}

// TurnableDefaults fills the options that have a default.
func (o Options) TurnableDefaults() Options {
	if o.TPlatform == "" {
		o.TPlatform = TurnablePlatform
	}
	if o.TProto == "" {
		o.TProto = TurnableProto
	}
	if o.TTransport == "" {
		o.TTransport = TurnableTransport
	}
	if o.TEncryption == "" {
		o.TEncryption = TurnableEncryption
	}
	if o.TPeers == 0 {
		o.TPeers = TurnablePeers
	}
	return o
}
