// Package naive renders the config of the naive daemon: Caddy serving NaiveProxy tunnels, where every visitor that is
// no proxy user is sent on to a real site.
package naive

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"frostbite/internal/core"
	"frostbite/internal/core/singbox"
	"frostbite/internal/spec"
)

func init() {
	core.Register(core.Descriptor{
		Kind:        "naive",
		DisplayName: "Naive",
		Caps: core.Capabilities{
			Protocols:  []string{spec.ProtoNaive},
			Transports: []string{spec.TransportTCP},
			Securities: []string{spec.SecurityTLS},
			Outbounds:  []string{spec.OutDirect, spec.OutBlock, spec.OutProxy, spec.OutWarp},
			HotUsers:   true,
		},
		Render: Render,
	})
}

// GateModule is the handler that checks proxy users and tunnels them, see internal/agent/naive/gate.
const GateModule = "frostbite_gate"

// EgressApp is the Caddy app that sniffs, routes, resolves and dials for the tunnels, see internal/agent/egress.
const EgressApp = "frostbite_egress"

// Render builds the Caddy config for d. Users are not part of it: they live in the running process, so adding and
// removing them never needs a reload.
func Render(d spec.Daemon) ([]byte, error) {
	servers := map[string]any{}
	var certs []any
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoNaive {
			continue
		}
		srv, err := server(in)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		if err := core.ApplyPatch(srv, in.RawPatch); err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		servers[in.Tag] = srv
		certs = append(certs, map[string]any{"certificate": in.Security.CertPath, "key": in.Security.KeyPath, "format": "pem", "tags": []string{in.Tag}})
	}

	apps := map[string]any{}
	if len(servers) > 0 {
		egress, err := egress(d)
		if err != nil {
			return nil, err
		}
		apps["http"] = map[string]any{"servers": servers}
		apps["tls"] = map[string]any{"certificates": map[string]any{"load_files": certs}}
		apps[EgressApp] = egress
	}
	cfg := map[string]any{
		// the agent drives Caddy in its own process, so the admin api would only be a way in
		"admin": map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{
			"level": logLevel(d.Log.Level), "encoder": map[string]any{"format": "console"}, "writer": map[string]any{"output": "frostbite"},
		}}},
		"apps": apps,
	}
	if err := core.ApplyPatch(cfg, d.RawPatch); err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// logLevel maps a panel log level to Caddy's.
func logLevel(l string) string {
	switch l {
	case "debug":
		return "DEBUG"
	case "warning":
		return "WARN"
	case "error":
		return "ERROR"
	case "none":
		return "FATAL"
	}
	return "INFO"
}

// egress renders the way out of the tunnels. Private ranges stay refused unless a rule sends them somewhere, as
// NaiveProxy's forwardproxy always did.
func egress(d spec.Daemon) (map[string]any, error) {
	cfg, err := singbox.RenderEgress(d)
	if err != nil {
		return nil, err
	}
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		cfg["route"] = route
	}
	rules, _ := route["rules"].([]any)
	route["rules"] = append(rules, map[string]any{"ip_is_private": true, "action": "reject"})
	return cfg, nil
}

// server renders one inbound as a Caddy http server.
func server(in spec.Inbound) (map[string]any, error) {
	if in.Security.CertPath == "" || in.Security.KeyPath == "" {
		return nil, fmt.Errorf("no certificate to serve")
	}
	o := in.Options
	srv := map[string]any{
		"listen":                  []string{net.JoinHostPort(in.Listen, strconv.Itoa(in.Port))},
		"protocols":               []string{"h1", "h2"},
		"automatic_https":         map[string]any{"disable": true},
		"tls_connection_policies": []any{map[string]any{"certificate_selection": map[string]any{"any_tag": []string{in.Tag}}}},
		"routes": []any{
			map[string]any{"handle": []any{map[string]any{"handler": GateModule, "inbound": in.Tag}}},
			map[string]any{"handle": []any{hideVia(), site(o)}},
		},
	}
	if o.AcceptProxy {
		srv["listener_wrappers"] = []any{
			map[string]any{"wrapper": "proxy_protocol", "allow": []string{"127.0.0.1/32", "::1/128"}},
			map[string]any{"wrapper": "tls"},
		}
	}
	return srv, nil
}

// site renders the handler every other visitor reaches.
func site(o spec.Options) map[string]any {
	// Caddy points Host at the upstream by itself, and the site has to see the name the visitor asked for
	set := map[string]any{"Host": []string{"{http.request.hostport}"}}
	del := []string{"Proxy-Authorization"}
	if h := o.NaiveIPHeader(); h != "" {
		set[h] = []string{"{http.request.remote.host}"}
		if !strings.EqualFold(h, spec.NaiveDefaultHeader) {
			// Caddy adds this one by itself, and the site was told to read another
			del = append(del, spec.NaiveDefaultHeader)
		}
	} else {
		del = append(del, spec.NaiveDefaultHeader)
	}

	transport := map[string]any{"protocol": "http"}
	if o.NaiveTLS {
		sni := o.NaiveSNI
		if sni == "" {
			sni = "{http.request.host}"
		}
		tls := map[string]any{"server_name": sni}
		if o.NaiveSkip {
			tls["insecure_skip_verify"] = true
		}
		transport["tls"] = tls
	}
	if o.NaiveProxy != "" {
		transport["proxy_protocol"] = o.NaiveProxy
	}

	request := map[string]any{"delete": del}
	if len(set) > 0 {
		request["set"] = set
	}
	return map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []any{map[string]any{"dial": o.NaiveDest}},
		"transport": transport,
		"headers": map[string]any{
			"request": request,
		},
	}
}

// hideVia keeps the reverse proxy out of the response. Caddy adds Via itself right before the response goes out, so
// only a deferred header operation can remove it.
func hideVia() map[string]any {
	return map[string]any{"handler": "headers", "response": map[string]any{"deferred": true, "delete": []string{"Via"}}}
}
