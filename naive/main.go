// Command naive-caddy is Caddy with the NaiveProxy fork of forwardproxy and the Frostbite gate, which owns users,
// usage counting and kicking for the proxy.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/caddyserver/forwardproxy"

	_ "frostbite/naive/gate"
)

func main() { caddycmd.Main() }
