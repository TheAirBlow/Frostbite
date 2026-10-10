// Package turnable "renders" the config of the Turnable daemon, which is simply its inbounds.
package turnable

import (
	"encoding/json"

	"frostbite/internal/core"
	"frostbite/internal/spec"
)

func init() {
	core.Register(core.Descriptor{
		Kind:        "turnable",
		DisplayName: "Turnable",
		Caps: core.Capabilities{
			Protocols:  []string{spec.ProtoTurnable},
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
