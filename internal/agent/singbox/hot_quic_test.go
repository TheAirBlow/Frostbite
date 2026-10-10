//go:build with_quic && !race

package singbox

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"frostbite/internal/spec"
)

func TestQUICProtocolsChangeUsersLive(t *testing.T) {
	cert, key := selfSignedFiles(t)
	sec := spec.Security{Type: spec.SecurityTLS, SNI: "localhost", CertPath: cert, KeyPath: key, ALPN: []string{"h3"}}
	clientTLS := map[string]any{"enabled": true, "server_name": "localhost", "insecure": true, "alpn": []string{"h3"}}

	cases := []hotCase{
		{
			protocol: spec.ProtoHysteria2, security: sec,
			user: func(n int64) spec.User {
				return spec.User{ID: n, Name: fmt.Sprintf("u%d", n), Password: uuid.NewString()}
			},
			outbound: func(u spec.User) map[string]any {
				return map[string]any{"type": "hysteria2", "password": u.Password, "tls": clientTLS}
			},
		},
		{
			protocol: spec.ProtoTUIC, security: sec,
			user: func(n int64) spec.User {
				return spec.User{ID: n, Name: fmt.Sprintf("u%d", n), UUID: uuid.NewString(), Password: uuid.NewString()}
			},
			outbound: func(u spec.User) map[string]any {
				return map[string]any{"type": "tuic", "uuid": u.UUID, "password": u.Password, "tls": clientTLS}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.protocol, func(t *testing.T) { runHotCase(t, c) })
	}
}
