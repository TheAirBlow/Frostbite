package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"frostbite/internal/spec"
)

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestBadInputNamesTheFieldWhenItKnowsOne(t *testing.T) {
	rec := httptest.NewRecorder()
	badInput(rec, spec.Invalid("options.t_routes.1.target", "the destination must look like 10.0.0.1:443"))
	body := errorBody(t, rec)
	if rec.Code != http.StatusBadRequest || body["field"] != "options.t_routes.1.target" || body["detail"] != "the destination must look like 10.0.0.1:443" {
		t.Fatalf("got %d %v", rec.Code, body)
	}

	rec = httptest.NewRecorder()
	badInput(rec, errors.New("something general"))
	if body := errorBody(t, rec); body["field"] != "" || body["detail"] != "something general" {
		t.Fatalf("a plain error must not invent a field: %v", body)
	}
}

func TestDaemonValidationErrorsKeepTheirFieldThroughWrapping(t *testing.T) {
	d := spec.Daemon{Kind: "xray", Inbounds: []spec.Inbound{
		{Tag: "a", Protocol: spec.ProtoVLESS, Port: 443, Security: spec.Security{Type: spec.SecurityReality}},
	}}
	path, msg, ok := spec.FieldOf(d.Validate())
	if !ok || path != "security.reality.dest" || msg == "" {
		t.Fatalf("got %q %q %v", path, msg, ok)
	}

	d.Inbounds = []spec.Inbound{
		{Tag: "a", Protocol: spec.ProtoVLESS, Port: 443, Security: spec.Security{Type: spec.SecurityNone}},
		{Tag: "b", Protocol: spec.ProtoVLESS, Port: 443, Security: spec.Security{Type: spec.SecurityNone}},
	}
	if path, _, _ := spec.FieldOf(d.Validate()); path != "port" {
		t.Fatalf("a taken port belongs on the port field, got %q", path)
	}
}

func TestRuleChecksNameTheirField(t *testing.T) {
	cases := map[string]struct {
		req   ruleRequest
		field string
	}{
		"no outbound":  {ruleRequest{Match: spec.Rule{Domain: []string{"a.com"}}}, "outbound"},
		"no condition": {ruleRequest{Outbound: "direct"}, "match"},
		"bad range":    {ruleRequest{Outbound: "direct", Match: spec.Rule{IPCIDR: []string{"10.0.0.0/99"}}}, "match.ip_cidr"},
		"bad port":     {ruleRequest{Outbound: "direct", Match: spec.Rule{Port: []string{"http"}}}, "match.port"},
		"bad country":  {ruleRequest{Outbound: "direct", Match: spec.Rule{GeoIP: []string{"russia"}}}, "match.geoip"},
		"fine":         {ruleRequest{Outbound: "block", Match: spec.Rule{IPCIDR: []string{"10.0.0.0/8", "1.1.1.1"}, Port: []string{"443", "6881-6889"}}}, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := cleanRule(&c.req)
			if c.field == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if path, _, _ := spec.FieldOf(err); path != c.field {
				t.Fatalf("want %q, got %v", c.field, err)
			}
		})
	}
}

func TestUniqueViolationsPointAtTheField(t *testing.T) {
	for constraint, want := range map[string]string{
		"users_username_key":         "username",
		"squads_name_key":            "name",
		"inbounds_daemon_id_tag_key": "tag",
		"something_else":             "",
	} {
		if got := uniqueField(constraint); got != want {
			t.Errorf("%s: want %q, got %q", constraint, want, got)
		}
	}
}
