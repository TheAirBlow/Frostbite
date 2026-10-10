// Package core holds the renderers that turn a spec into a native core config.
package core

import (
	"slices"

	"frostbite/internal/spec"
)

// Capabilities says what a core can run, so the panel can refuse early and the UI can hide dead options.
type Capabilities struct {
	Protocols  []string `json:"protocols"`
	Transports []string `json:"transports"`
	Securities []string `json:"securities"`
	Outbounds  []string `json:"outbounds"`
	HotUsers   bool     `json:"hot_users"` // users can change without a restart
}

// Descriptor pairs a core's metadata with its renderer.
type Descriptor struct {
	Kind        string                            `json:"kind"`
	DisplayName string                            `json:"display_name"`
	Caps        Capabilities                      `json:"caps"`
	Render      func(spec.Daemon) ([]byte, error) `json:"-"`
}

// registry is the list of known cores.
var registry []Descriptor

// Register adds a core. Renderer packages call it from init.
func Register(d Descriptor) { registry = append(registry, d) }

// GetAll returns every registered core.
func GetAll() []Descriptor { return registry }

// Get returns a registered core by kind.
func Get(kind string) *Descriptor {
	for i := range registry {
		if registry[i].Kind == kind {
			return &registry[i]
		}
	}
	return nil
}

// Check makes sure the core can actually run everything in d.
func (c Capabilities) Check(d spec.Daemon) error {
	for _, in := range d.Inbounds {
		if !slices.Contains(c.Protocols, in.Protocol) {
			return spec.Invalid("protocol", "protocol %s is not supported by this core", in.Protocol)
		}
		if t := in.Transport.Type; t != "" && !slices.Contains(c.Transports, t) {
			return spec.Invalid("transport.type", "transport %s is not supported by this core", t)
		}
		if s := in.Security.Type; s != "" && !slices.Contains(c.Securities, s) {
			return spec.Invalid("security.type", "security %s is not supported by this core", s)
		}
	}
	return nil
}
