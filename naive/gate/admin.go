package gate

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func init() { caddy.RegisterModule(Admin{}) }

// Admin exposes the user table and the counters on Caddy's admin api.
//
//	PUT  /frostbite/users/{inbound}  body {"users":[{"name","password"}]} replaces the users, cutting the ones gone
//	POST /frostbite/usage            returns and resets the traffic counters, and lists who is connected
type Admin struct{}

// CaddyModule returns the module information.
func (Admin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.frostbite",
		New: func() caddy.Module { return new(Admin) },
	}
}

// Routes lists the admin endpoints.
func (Admin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/frostbite/users/", Handler: caddy.AdminHandlerFunc(putUsers)},
		{Pattern: "/frostbite/usage", Handler: caddy.AdminHandlerFunc(getUsage)},
	}
}

func putUsers(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPut {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: errMethod}
	}
	inbound := strings.TrimPrefix(r.URL.Path, "/frostbite/users/")
	if inbound == "" {
		return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: errInbound}
	}
	var body struct {
		Users []Credential `json:"users"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: err}
	}
	cut := registry.replace(inbound, body.Users)
	return json.NewEncoder(w).Encode(map[string]int{"cut": cut})
}

func getUsage(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: errMethod}
	}
	return json.NewEncoder(w).Encode(registry.drain())
}

type adminError string

func (e adminError) Error() string { return string(e) }

const (
	errMethod  = adminError("method not allowed")
	errInbound = adminError("the inbound is missing from the path")
)
