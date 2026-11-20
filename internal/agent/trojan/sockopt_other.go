//go:build !linux

package trojan

import (
	"errors"
	"syscall"
)

// listenControl refuses socket options this system does not offer.
func listenControl(reusePort, fastOpen bool) func(network, address string, c syscall.RawConn) error {
	if !reusePort && !fastOpen {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("reuse port and TCP Fast Open need Linux")
	}
}

// bindControl refuses interface binding, which needs Linux.
func bindControl(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("binding to an interface needs Linux")
	}
}
