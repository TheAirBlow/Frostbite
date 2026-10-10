// Package mtproto "renders" the config of the Telegram proxy daemon, which is simply its inbounds.
package mtproto

import (
	"encoding/json"

	"frostbite/internal/core"
	"frostbite/internal/spec"
)

func init() {
	core.Register(core.Descriptor{
		Kind:        "mtproto",
		DisplayName: "MTProto",
		Caps: core.Capabilities{
			Protocols:  []string{spec.ProtoMTProto},
			Transports: []string{spec.TransportTCP},
			Securities: []string{spec.SecurityNone},
			HotUsers:   true,
		},
		Render: Render,
	})
}

// Render returns the inbounds as json.
func Render(d spec.Daemon) ([]byte, error) {
	return json.MarshalIndent(d.Inbounds, "", "  ")
}
