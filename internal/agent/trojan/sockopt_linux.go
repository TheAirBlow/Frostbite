package trojan

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// fastOpenQueue is how many TCP Fast Open handshakes may wait at once, upstream trojan's default.
const fastOpenQueue = 20

// listenControl sets the options a listening socket needs before it binds.
func listenControl(reusePort, fastOpen bool) func(network, address string, c syscall.RawConn) error {
	if !reusePort && !fastOpen {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if reusePort {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); serr != nil {
					return
				}
			}
			if fastOpen {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, fastOpenQueue)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
