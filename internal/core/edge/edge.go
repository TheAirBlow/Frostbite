// Package edge "renders" the config of the edge daemon, which is simply its spec.
package edge

import (
	"encoding/json"
	"fmt"

	"frostbite/internal/core"
	"frostbite/internal/spec"
)

func init() {
	core.Register(core.Descriptor{
		Kind:        "edge",
		DisplayName: "Edge",
		Caps:        core.Capabilities{HotUsers: true},
		Render:      Render,
	})
}

// Render returns the routing table as json.
func Render(d spec.Daemon) ([]byte, error) {
	if d.Edge == nil {
		return nil, fmt.Errorf("an edge daemon needs an edge section")
	}
	return json.MarshalIndent(d.Edge, "", "  ")
}
