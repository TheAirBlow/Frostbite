package api

import (
	"net/http"

	"frostbite/internal/hub"
	"frostbite/internal/keys"
	"frostbite/internal/link"
)

// registerTools registers the small helpers the UI uses while filling forms.
func (s *Server) registerTools(mux authMux) {
	mux.Admin("POST /tools/keys", s.genKeys)
	mux.Admin("POST /tools/parse-link", s.parseLink)
	mux.Admin("POST /tools/test-reality", s.testReality)
}

// genKeys generates a secret of the requested kind.
func (s *Server) genKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type    string `json:"type"`
		Method  string `json:"method"`
		Private string `json:"private"`
	}
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}

	var (
		out any
		err error
	)
	switch req.Type {
	case "reality":
		if req.Private != "" {
			var pub string
			pub, err = keys.RealityPublic(req.Private)
			out = keys.Pair{Private: req.Private, Public: pub}
		} else {
			out, err = keys.Reality()
		}
	case "wireguard":
		out, err = keys.WireGuard()
	case "ss2022":
		var k string
		k, err = keys.SS2022(req.Method)
		out = map[string]string{"key": k}
	case "short_id":
		var id string
		id, err = keys.ShortID(4)
		out = map[string]string{"short_id": id}
	case "uuid":
		out = map[string]string{"uuid": keys.UUID()}
	case "password":
		var t string
		t, err = keys.Token(18)
		out = map[string]string{"password": t}
	default:
		badRequest(w, "unknown key type")
		return
	}
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	ok(w, out)
}

// parseLink turns a pasted share link into an upstream, so the UI can show what it understood.
func (s *Server) parseLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link string `json:"link"`
	}
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	up, err := parseUpstreamLink(req.Link)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	up.Password, up.UUID = mask(up.Password), mask(up.UUID)
	ok(w, up)
}

// mask hides most of a secret in previews.
func mask(s string) string {
	if len(s) <= 6 {
		return s
	}
	return s[:3] + "…" + s[len(s)-3:]
}

// testReality asks a node whether it can complete a TLS 1.3 handshake with a REALITY target.
func (s *Server) testReality(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DaemonID int64  `json:"daemon_id"`
		Dest     string `json:"dest"`
	}
	if err := decode(r, &req); err != nil || req.Dest == "" {
		badRequest(w, "dest is required")
		return
	}
	res, err := s.Hub.Command(r.Context(), req.DaemonID, link.CmdTestReality, map[string]string{"dest": req.Dest})
	switch err {
	case nil:
		ok(w, res)
	case hub.ErrOffline:
		conflict(w, "the daemon is offline")
	default:
		fail(w, http.StatusGatewayTimeout, "timeout", err.Error())
	}
}
