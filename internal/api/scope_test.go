package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"

	"frostbite/internal/common"
	"frostbite/internal/db"
	"frostbite/internal/hub"
)

func testScope() *nodeScope {
	return &nodeScope{adminID: 7, nodes: map[int64]bool{1: true, 2: true}, squads: map[int64][]int64{
		10: {1},    // only on a scoped node
		11: {1, 3}, // reaches node 3 too
		12: {3},
		13: nil, // grants nothing
	}}
}

func TestNodeScopeOwnsOnlySquadsEntirelyOnItsNodes(t *testing.T) {
	sc := testScope()
	for id, want := range map[int64]bool{10: true, 11: false, 12: false, 13: false, 99: false} {
		if got := sc.ownsSquad(id); got != want {
			t.Errorf("squad %d: got %v, want %v", id, got, want)
		}
	}
	var none *nodeScope
	if !none.ownsSquad(12) {
		t.Error("an unscoped caller must own every squad")
	}
}

func TestNodeScopeManagesCreatedUsersAndUsersOnlyOnItsNodes(t *testing.T) {
	sc := testScope()
	cases := []struct {
		name  string
		owner *int64
		nodes []int64
		want  bool
	}{
		{"created by them, elsewhere", ptr[int64](7), []int64{3}, true},
		{"created by them, no access", ptr[int64](7), nil, true},
		{"only on their nodes", ptr[int64](8), []int64{1, 2}, true},
		{"also on another node", nil, []int64{1, 3}, false},
		{"no access at all", nil, nil, false},
		{"only elsewhere", nil, []int64{3}, false},
	}
	for _, c := range cases {
		if got := sc.manages(db.User{OwnerID: c.owner}, c.nodes); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReadScopeBodyLeavesTheBodyForTheHandler(t *testing.T) {
	r := httptest.NewRequest("POST", "/inbounds", strings.NewReader(`{"daemon_id": 4, "tag": "x"}`))
	b, err := readScopeBody(r)
	if err != nil || b.DaemonID == nil || *b.DaemonID != 4 {
		t.Fatalf("got %+v, %v", b, err)
	}
	var again map[string]any
	if err := decode(r, &again); err != nil || again["tag"] != "x" {
		t.Fatalf("body was not restored: %v %v", again, err)
	}
}

// scopeEnv is a panel on a throwaway database with one node admin who manages node A but not node B.
type scopeEnv struct {
	t       *testing.T
	srv     *Server
	pool    *pgxpool.Pool
	handler http.Handler
	tokens  map[string]string
	ids     map[string]int64
}

// newScopeEnv needs FROSTBITE_TEST_DATABASE, a Postgres URL whose user may create databases.
func newScopeEnv(t *testing.T) *scopeEnv {
	base := os.Getenv("FROSTBITE_TEST_DATABASE")
	if base == "" {
		t.Skip("FROSTBITE_TEST_DATABASE is not set")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("frostbite_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	dsn := withDatabase(t, base, name)
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE " + name + " WITH (FORCE)")
		admin.Close()
	})

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(sqlDB); err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	q := db.New(pool)
	s := &Server{Queries: q, Pool: pool, Hub: hub.New(q, common.LinkConfig{})}
	mux := http.NewServeMux()
	s.Register(mux)
	e := &scopeEnv{t: t, srv: s, pool: pool, handler: mux, tokens: map[string]string{}, ids: map[string]int64{}}
	e.seed()
	return e
}

// withDatabase swaps the database name in a postgres URL.
func withDatabase(t *testing.T, dsn, name string) string {
	i := strings.LastIndex(dsn, "/")
	if i < len("postgres://") {
		t.Fatalf("FROSTBITE_TEST_DATABASE must be a URL like postgres://user@host:port/db, got %q", dsn)
	}
	rest := ""
	if j := strings.Index(dsn[i:], "?"); j >= 0 {
		rest = dsn[i+j:]
	}
	return dsn[:i+1] + name + rest
}

func (e *scopeEnv) one(query string, args ...any) int64 {
	e.t.Helper()
	var id int64
	if err := e.pool.QueryRow(context.Background(), query, args...).Scan(&id); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return id
}

func (e *scopeEnv) account(name, role string) int64 {
	id := e.one(`INSERT INTO admins (username, password_hash, role) VALUES ($1, 'x', $2) RETURNING id`, name, role)
	token := apiTokenPrefix + name
	e.one(`INSERT INTO api_tokens (admin_id, name, token_hash) VALUES ($1, 't', $2) RETURNING id`, id, HashToken(token))
	e.tokens[name] = token
	return id
}

func (e *scopeEnv) seed() {
	ids := e.ids
	ids["owner"] = e.account("owner", RoleOwner)
	ids["nodeadm"] = e.account("nodeadm", RoleNodeAdmin)
	for _, n := range []string{"A", "B"} {
		ids["node"+n] = e.one(`INSERT INTO nodes (name, address) VALUES ($1, 'example.com') RETURNING id`, n)
		ids["daemon"+n] = e.one(`INSERT INTO daemons (node_id, kind, name, token_hash) VALUES ($1, 'xray', 'xray', $2) RETURNING id`, ids["node"+n], "h"+n)
		ids["inbound"+n] = e.one(`INSERT INTO inbounds (daemon_id, tag, protocol, port) VALUES ($1, 'vless', 'vless', 443) RETURNING id`, ids["daemon"+n])
		ids["host"+n] = e.one(`INSERT INTO hosts (inbound_id) VALUES ($1) RETURNING id`, ids["inbound"+n])
		ids["squad"+n] = e.one(`INSERT INTO squads (name) VALUES ($1) RETURNING id`, n)
		e.one(`INSERT INTO squad_inbounds (squad_id, inbound_id) VALUES ($1, $2) RETURNING squad_id`, ids["squad"+n], ids["inbound"+n])
	}
	ids["squadAB"] = e.one(`INSERT INTO squads (name) VALUES ('AB') RETURNING id`)
	e.one(`INSERT INTO squad_inbounds (squad_id, inbound_id) VALUES ($1, $2), ($1, $3) RETURNING squad_id`, ids["squadAB"], ids["inboundA"], ids["inboundB"])
	e.one(`INSERT INTO admin_nodes (admin_id, node_id) VALUES ($1, $2) RETURNING node_id`, ids["nodeadm"], ids["nodeA"])

	user := func(name string, owner *int64, squads ...int64) int64 {
		id := e.one(`INSERT INTO users (username, uuid, password, sub_token, owner_id) VALUES ($1, gen_random_uuid(), 'p', $1, $2) RETURNING id`, name, owner)
		for _, sq := range squads {
			e.one(`INSERT INTO user_squads (user_id, squad_id) VALUES ($1, $2) RETURNING user_id`, id, sq)
		}
		return id
	}
	ids["onA"] = user("on-a", nil, ids["squadA"])
	ids["onAB"] = user("on-ab", nil, ids["squadA"], ids["squadB"])
	ids["onB"] = user("on-b", nil, ids["squadB"])
	ids["mine"] = user("mine", ptr(ids["nodeadm"]), ids["squadB"])
}

// call makes a request as one of the seeded accounts and decodes the JSON answer into out, if given.
func (e *scopeEnv) call(who, method, path string, body any, out any) int {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			e.t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "/api"+path, &buf)
	r.Header.Set("Authorization", "Bearer "+e.tokens[who])
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, r)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func (e *scopeEnv) expect(who, method, path string, body any, want int) {
	e.t.Helper()
	if got := e.call(who, method, path, body, nil); got != want {
		e.t.Errorf("%s %s %s: got %d, want %d", who, method, path, got, want)
	}
}

func (e *scopeEnv) squadsOf(user int64) []int64 {
	ids, err := e.srv.Queries.ListUserSquadIDs(context.Background(), user)
	if err != nil {
		e.t.Fatal(err)
	}
	slices.Sort(ids)
	return ids
}

func TestNodeAdminSeesOnlyTheirNodes(t *testing.T) {
	e := newScopeEnv(t)
	var nodes []nodeResponse
	e.call("nodeadm", "GET", "/nodes", nil, &nodes)
	if len(nodes) != 1 || nodes[0].ID != e.ids["nodeA"] || len(nodes[0].Daemons) != 1 {
		t.Fatalf("got %+v", nodes)
	}
	var inbounds []inboundResponse
	e.call("nodeadm", "GET", "/inbounds", nil, &inbounds)
	if len(inbounds) != 1 || inbounds[0].ID != e.ids["inboundA"] {
		t.Fatalf("got %+v", inbounds)
	}
	var squads []squadResponse
	e.call("nodeadm", "GET", "/squads", nil, &squads)
	if len(squads) != 1 || squads[0].ID != e.ids["squadA"] {
		t.Fatalf("a node admin must see only squads built from their nodes, got %+v", squads)
	}
	e.call("owner", "GET", "/nodes", nil, &nodes)
	if len(nodes) != 2 {
		t.Fatalf("the owner must see every node, got %d", len(nodes))
	}
}

func TestNodeAdminIsHeldToTheirNodesOnEveryInfraRoute(t *testing.T) {
	e := newScopeEnv(t)
	id := func(k string) string { return fmt.Sprint(e.ids[k]) }
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"POST", "/nodes", map[string]any{"name": "x", "address": "x.com"}, http.StatusForbidden},
		{"DELETE", "/nodes/" + id("nodeA"), nil, http.StatusForbidden},
		{"PUT", "/nodes/" + id("nodeB"), map[string]any{"name": "x", "address": "x.com"}, http.StatusForbidden},
		{"PUT", "/nodes/" + id("nodeA"), map[string]any{"name": "renamed", "address": "a.com"}, http.StatusOK},
		{"POST", "/nodes/" + id("nodeB") + "/daemons", map[string]any{"kind": "xray"}, http.StatusForbidden},
		{"GET", "/daemons/" + id("daemonB") + "/preview", nil, http.StatusForbidden},
		{"POST", "/daemons/" + id("daemonB") + "/rotate", nil, http.StatusForbidden},
		{"DELETE", "/daemons/" + id("daemonB"), nil, http.StatusForbidden},
		{"DELETE", "/daemons/999999", nil, http.StatusNotFound},
		{"POST", "/inbounds", map[string]any{"daemon_id": e.ids["daemonB"], "tag": "x", "protocol": "vless", "port": 8443}, http.StatusForbidden},
		{"POST", "/inbounds", map[string]any{"tag": "x", "protocol": "vless", "port": 8443}, http.StatusForbidden},
		{"PUT", "/inbounds/" + id("inboundB"), map[string]any{}, http.StatusForbidden},
		{"DELETE", "/inbounds/" + id("inboundB"), nil, http.StatusForbidden},
		{"POST", "/hosts", map[string]any{"inbound_id": e.ids["inboundB"]}, http.StatusForbidden},
		{"PUT", "/hosts/" + id("hostB"), map[string]any{}, http.StatusForbidden},
		{"DELETE", "/hosts/" + id("hostB"), nil, http.StatusForbidden},
		{"DELETE", "/hosts/" + id("hostA"), nil, http.StatusNoContent},
		{"POST", "/outbounds", map[string]any{"daemon_id": e.ids["daemonB"], "tag": "x", "kind": "direct"}, http.StatusForbidden},
		{"POST", "/outbounds", map[string]any{"daemon_id": e.ids["daemonA"], "tag": "x", "kind": "proxy", "target_inbound_id": e.ids["inboundB"]}, http.StatusForbidden},
		{"POST", "/rules", map[string]any{"outbound": "block", "match": map[string]any{"network": "udp"}}, http.StatusForbidden},
		{"POST", "/rules", map[string]any{"daemon_id": e.ids["daemonB"], "outbound": "block", "match": map[string]any{"network": "udp"}}, http.StatusForbidden},
		{"POST", "/rules", map[string]any{"daemon_id": e.ids["daemonA"], "outbound": "block", "match": map[string]any{"network": "udp"}}, http.StatusCreated},
		{"POST", "/bridges", map[string]any{"kind": "relay", "bridge_daemon_id": e.ids["daemonA"], "target_inbound_id": e.ids["inboundB"]}, http.StatusForbidden},
		{"POST", "/squads", map[string]any{"name": "mixed", "inbound_ids": []int64{e.ids["inboundA"], e.ids["inboundB"]}}, http.StatusForbidden},
		{"POST", "/squads", map[string]any{"name": "mine", "inbound_ids": []int64{e.ids["inboundA"]}}, http.StatusCreated},
		{"PUT", "/squads/" + id("squadAB"), map[string]any{"name": "AB", "inbound_ids": []int64{e.ids["inboundA"]}}, http.StatusForbidden},
		{"PUT", "/squads/" + id("squadA"), map[string]any{"name": "A", "inbound_ids": []int64{e.ids["inboundB"]}}, http.StatusForbidden},
		{"DELETE", "/squads/" + id("squadB"), nil, http.StatusForbidden},
		{"POST", "/plans", map[string]any{"name": "p"}, http.StatusForbidden},
		{"GET", "/dashboard", nil, http.StatusForbidden},
		{"GET", "/settings", nil, http.StatusForbidden},
		{"GET", "/topology", nil, http.StatusForbidden},
		{"GET", "/admins", nil, http.StatusForbidden},
	} {
		e.expect("nodeadm", c.method, c.path, c.body, c.want)
	}
	var rules []db.Rule
	e.call("nodeadm", "GET", "/rules", nil, &rules)
	if len(rules) != 1 || rules[0].DaemonID == nil || *rules[0].DaemonID != e.ids["daemonA"] {
		t.Fatalf("got %+v", rules)
	}
	e.expect("nodeadm", "POST", "/rules/reorder", map[string]any{"ids": []int64{rules[0].ID}}, http.StatusNoContent)
}

func TestNodeAdminUserRules(t *testing.T) {
	e := newScopeEnv(t)
	id := func(k string) string { return fmt.Sprint(e.ids[k]) }

	var list struct {
		Items []userResponse `json:"items"`
		Total int64          `json:"total"`
	}
	e.call("nodeadm", "GET", "/users", nil, &list)
	got := map[string]bool{}
	for _, u := range list.Items {
		got[u.Username] = u.Manageable
		if !u.Manageable && (u.SubToken != "" || u.Uuid != "" || u.SubURL != "") {
			t.Errorf("%s: secrets leak to a node admin who can't manage the user", u.Username)
		}
	}
	want := map[string]bool{"on-a": true, "on-ab": false, "mine": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: manageable %v, want %v", k, got[k], v)
		}
	}

	e.expect("nodeadm", "PUT", "/users/"+id("onA"), map[string]any{"note": "ok"}, http.StatusOK)
	e.expect("nodeadm", "PUT", "/users/"+id("mine"), map[string]any{"note": "ok"}, http.StatusOK)
	e.expect("nodeadm", "PUT", "/users/"+id("onAB"), map[string]any{"note": "no"}, http.StatusForbidden)
	e.expect("nodeadm", "GET", "/users/"+id("onAB")+"/links", nil, http.StatusForbidden)
	e.expect("nodeadm", "GET", "/users/"+id("onB"), nil, http.StatusForbidden)
	e.expect("nodeadm", "POST", "/users/"+id("onB")+"/rotate", map[string]any{"what": "sub"}, http.StatusForbidden)

	// Any user can be put on, or taken off, their node; other squads stay as they were.
	e.expect("nodeadm", "PUT", "/users/"+id("onB")+"/access", map[string]any{"squad_ids": []int64{e.ids["squadA"]}}, http.StatusOK)
	if s := e.squadsOf(e.ids["onB"]); !slices.Equal(s, []int64{e.ids["squadA"], e.ids["squadB"]}) {
		t.Fatalf("on-b squads after grant: %v", s)
	}
	e.expect("nodeadm", "PUT", "/users/"+id("onAB")+"/access", map[string]any{"squad_ids": []int64{}}, http.StatusOK)
	if s := e.squadsOf(e.ids["onAB"]); !slices.Equal(s, []int64{e.ids["squadB"]}) {
		t.Fatalf("on-ab squads after revoke: %v", s)
	}
	e.expect("nodeadm", "PUT", "/users/"+id("onA")+"/access", map[string]any{"squad_ids": []int64{e.ids["squadB"]}}, http.StatusBadRequest)
	e.expect("nodeadm", "PUT", "/users/"+id("onA")+"/access", map[string]any{"squad_ids": []int64{e.ids["squadAB"]}}, http.StatusBadRequest)

	// Editing a managed user's squads can't strip squads on other nodes.
	e.expect("nodeadm", "PUT", "/users/"+id("mine"), map[string]any{"squad_ids": []int64{e.ids["squadA"]}}, http.StatusOK)
	if s := e.squadsOf(e.ids["mine"]); !slices.Equal(s, []int64{e.ids["squadA"], e.ids["squadB"]}) {
		t.Fatalf("mine squads after edit: %v", s)
	}

	var lookup []struct {
		Username string  `json:"username"`
		SquadIDs []int64 `json:"squad_ids"`
	}
	e.call("nodeadm", "GET", "/users/lookup?search=on-b", nil, &lookup)
	if len(lookup) != 1 || !slices.Equal(lookup[0].SquadIDs, []int64{e.ids["squadA"]}) {
		t.Fatalf("lookup: %+v", lookup)
	}

	e.expect("nodeadm", "POST", "/users", map[string]any{"username": "fresh", "squad_ids": []int64{e.ids["squadB"]}}, http.StatusBadRequest)
	e.expect("nodeadm", "POST", "/users", map[string]any{"username": "fresh", "squad_ids": []int64{e.ids["squadA"]}}, http.StatusCreated)
	e.expect("nodeadm", "POST", "/users/import", map[string]any{}, http.StatusForbidden)

	var res map[string]int
	e.call("nodeadm", "POST", "/users/bulk", map[string]any{"action": "delete", "ids": []int64{e.ids["onAB"], e.ids["onB"]}}, nil)
	if code := e.call("nodeadm", "POST", "/users/bulk", map[string]any{"action": "disable", "ids": []int64{e.ids["mine"], e.ids["onB"]}}, &res); code != http.StatusOK || res["affected"] != 1 {
		t.Fatalf("bulk disable: %d %v", code, res)
	}
	if _, err := e.srv.Queries.GetUser(context.Background(), e.ids["onB"]); err != nil {
		t.Fatalf("a bulk delete removed a user the node admin doesn't manage: %v", err)
	}
	e.expect("nodeadm", "POST", "/users/bulk", map[string]any{"action": "set_owner", "ids": []int64{e.ids["mine"]}}, http.StatusForbidden)
	e.expect("nodeadm", "POST", "/users/bulk", map[string]any{"action": "add_squads", "ids": []int64{e.ids["onB"]}, "squad_ids": []int64{e.ids["squadB"]}}, http.StatusBadRequest)
}

func TestOwnerAssignsNodesToANodeAdmin(t *testing.T) {
	e := newScopeEnv(t)
	e.expect("owner", "POST", "/admins", map[string]any{"username": "nodeless", "password": "password1", "role": RoleNodeAdmin}, http.StatusBadRequest)
	var a adminResponse
	if code := e.call("owner", "POST", "/admins", map[string]any{"username": "two", "password": "password1", "role": RoleNodeAdmin, "node_ids": []int64{e.ids["nodeA"], e.ids["nodeB"]}}, &a); code != http.StatusCreated || len(a.NodeIDs) != 2 {
		t.Fatalf("create: %d %+v", code, a)
	}
	if code := e.call("owner", "PUT", fmt.Sprintf("/admins/%d", a.ID), map[string]any{"role": RoleAdmin}, &a); code != http.StatusOK || len(a.NodeIDs) != 0 {
		t.Fatalf("a plain admin must not keep node scope: %d %+v", code, a)
	}
	var me adminResponse
	e.call("nodeadm", "GET", "/auth/me", nil, &me)
	if !slices.Equal(me.NodeIDs, []int64{e.ids["nodeA"]}) {
		t.Fatalf("me: %+v", me)
	}
}
