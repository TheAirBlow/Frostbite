package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/db"
)

// nodeScope is what a node admin may reach: their nodes, and the squads built only from those nodes.
type nodeScope struct {
	adminID int64
	nodes   map[int64]bool
	squads  map[int64][]int64 // every squad's nodes
}

// scopeCtxKey is the context key a node admin's scope is stored under.
const scopeCtxKey ctxKey = adminCtxKey + 1

// scopeFrom returns the caller's node scope, nil when they are not limited to nodes.
func scopeFrom(ctx context.Context) *nodeScope {
	sc, _ := ctx.Value(scopeCtxKey).(*nodeScope)
	return sc
}

// loadScope reads a node admin's nodes and the node footprint of every squad.
func (s *Server) loadScope(ctx context.Context, admin db.Admin) (*nodeScope, error) {
	ids, err := s.Queries.ListAdminNodeIDs(ctx, admin.ID)
	if err != nil {
		return nil, err
	}
	links, err := s.Queries.ListSquadNodes(ctx)
	if err != nil {
		return nil, err
	}
	sc := &nodeScope{adminID: admin.ID, nodes: map[int64]bool{}, squads: map[int64][]int64{}}
	for _, id := range ids {
		sc.nodes[id] = true
	}
	for _, l := range links {
		sc.squads[l.SquadID] = append(sc.squads[l.SquadID], l.NodeID)
	}
	return sc, nil
}

// ownsNodes reports whether nodes is non-empty and entirely inside the scope.
func (sc *nodeScope) ownsNodes(nodes []int64) bool {
	if len(nodes) == 0 {
		return false
	}
	for _, n := range nodes {
		if !sc.nodes[n] {
			return false
		}
	}
	return true
}

// ownsSquad reports whether a squad only grants inbounds on the scope's nodes. A nil scope owns everything.
func (sc *nodeScope) ownsSquad(id int64) bool {
	return sc == nil || sc.ownsNodes(sc.squads[id])
}

// manages reports whether the scope may fully manage a user: one it created, or one whose access is all on its nodes.
func (sc *nodeScope) manages(u db.User, nodes []int64) bool {
	return sc == nil || (u.OwnerID != nil && *u.OwnerID == sc.adminID) || sc.ownsNodes(nodes)
}

// userNodes maps each user to the nodes their squads reach.
func (s *Server) userNodes(ctx context.Context, ids []int64) (map[int64][]int64, error) {
	rows, err := s.Queries.ListUserNodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := map[int64][]int64{}
	for _, row := range rows {
		out[row.UserID] = append(out[row.UserID], row.NodeID)
	}
	return out, nil
}

// manageable reports whether the caller may fully manage u.
func (s *Server) manageable(ctx context.Context, u db.User) (bool, error) {
	sc := scopeFrom(ctx)
	if sc == nil {
		return true, nil
	}
	nodes, err := s.userNodes(ctx, []int64{u.ID})
	if err != nil {
		return false, err
	}
	return sc.manages(u, nodes[u.ID]), nil
}

// errForeignSquad is returned when a node admin names a squad that reaches beyond their nodes.
var errForeignSquad = errors.New("one of those squads reaches nodes you don't manage")

// checkSquads makes sure every squad is one the caller may hand out.
func checkSquads(ctx context.Context, ids []int64) error {
	sc := scopeFrom(ctx)
	for _, id := range ids {
		if !sc.ownsSquad(id) {
			return errForeignSquad
		}
	}
	return nil
}

// setOwnedSquads makes the user's membership in the caller's squads exactly want, leaving every other squad alone.
func (s *Server) setOwnedSquads(ctx context.Context, userID int64, want []int64) error {
	if err := checkSquads(ctx, want); err != nil {
		return err
	}
	sc := scopeFrom(ctx)
	cur, err := s.Queries.ListUserSquadIDs(ctx, userID)
	if err != nil {
		return err
	}
	var drop, add []int64
	for _, id := range cur {
		if sc.ownsSquad(id) && !slices.Contains(want, id) {
			drop = append(drop, id)
		}
	}
	for _, id := range want {
		if !slices.Contains(cur, id) {
			add = append(add, id)
		}
	}
	if len(drop) > 0 {
		if err := s.Queries.RemoveUserSquads(ctx, db.RemoveUserSquadsParams{UserID: userID, SquadIds: drop}); err != nil {
			return err
		}
	}
	if len(add) > 0 {
		return s.Queries.AddUserSquads(ctx, db.AddUserSquadsParams{Ids: []int64{userID}, SquadIds: add})
	}
	return nil
}

// daemonFilter returns a test for daemons on the caller's nodes, letting everything through when they are unscoped.
func (s *Server) daemonFilter(ctx context.Context) (func(daemonID int64) bool, error) {
	sc := scopeFrom(ctx)
	if sc == nil {
		return func(int64) bool { return true }, nil
	}
	daemons, err := s.Queries.ListDaemons(ctx)
	if err != nil {
		return nil, err
	}
	in := map[int64]bool{}
	for _, d := range daemons {
		in[d.ID] = sc.nodes[d.NodeID]
	}
	return func(id int64) bool { return in[id] }, nil
}

// scopeBody holds every body field a scope check looks at.
type scopeBody struct {
	DaemonID        *int64  `json:"daemon_id"`
	EdgeDaemonID    *int64  `json:"edge_daemon_id"`
	InboundID       *int64  `json:"inbound_id"`
	TargetInboundID *int64  `json:"target_inbound_id"`
	BridgeDaemonID  *int64  `json:"bridge_daemon_id"`
	InboundIDs      []int64 `json:"inbound_ids"`
	IDs             []int64 `json:"ids"`
}

// scopeCheck decides whether a node admin may make a request.
type scopeCheck func(s *Server, r *http.Request, body scopeBody, sc *nodeScope) (bool, error)

// readScopeBody parses the fields scope checks need and leaves the body readable for the handler.
func readScopeBody(r *http.Request) (scopeBody, error) {
	var body scopeBody
	if r.Body == nil {
		return body, nil
	}
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 4<<20))
	if err != nil {
		return body, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &body) // a malformed body is the handler's to reject
	}
	return body, nil
}

// Node registers handler for owners, admins, and node admins that pass check. A nil check lets every node admin through.
func (m authMux) Node(pattern string, check scopeCheck, handler http.HandlerFunc) {
	m.Auth(pattern, func(w http.ResponseWriter, r *http.Request) {
		admin, _ := AdminFromContext(r.Context())
		switch admin.Role {
		case RoleOwner, RoleAdmin:
			handler(w, r)
			return
		case RoleNodeAdmin:
		default:
			forbidden(w, "admin access required")
			return
		}
		if check != nil {
			body, err := readScopeBody(r)
			if err != nil {
				badRequest(w, err.Error())
				return
			}
			allowed, err := check(m.server, r, body, scopeFrom(r.Context()))
			if errors.Is(err, pgx.ErrNoRows) {
				notFound(w, "not found")
				return
			}
			if err != nil {
				internalError(w, err)
				return
			}
			if !allowed {
				forbidden(w, "that belongs to a node you don't manage")
				return
			}
		}
		handler(w, r)
	})
}

// daemonIn reports whether a daemon runs on one of the scope's nodes.
func (s *Server) daemonIn(ctx context.Context, sc *nodeScope, id int64) (bool, error) {
	d, err := s.Queries.GetDaemon(ctx, id)
	if err != nil {
		return false, err
	}
	return sc.nodes[d.NodeID], nil
}

// inboundIn reports whether an inbound runs on one of the scope's nodes.
func (s *Server) inboundIn(ctx context.Context, sc *nodeScope, id int64) (bool, error) {
	in, err := s.Queries.GetInbound(ctx, id)
	if err != nil {
		return false, err
	}
	return s.daemonIn(ctx, sc, in.DaemonID)
}

// allIn runs each test in order and reports whether every one passed.
func allIn(tests ...func() (bool, error)) (bool, error) {
	for _, t := range tests {
		good, err := t()
		if err != nil || !good {
			return false, err
		}
	}
	return true, nil
}

// optional wraps a check on an id that may be absent from the body.
func optional(id *int64, test func(int64) (bool, error)) func() (bool, error) {
	return func() (bool, error) {
		if id == nil || *id == 0 {
			return true, nil
		}
		return test(*id)
	}
}

// required wraps a check on an id the node admin must give.
func required(id *int64, test func(int64) (bool, error)) func() (bool, error) {
	return func() (bool, error) {
		if id == nil || *id == 0 {
			return false, nil
		}
		return test(*id)
	}
}

// scopeTests binds the per-object lookups to one request.
func scopeTests(s *Server, r *http.Request, sc *nodeScope) (daemon, inbound func(int64) (bool, error)) {
	ctx := r.Context()
	return func(id int64) (bool, error) { return s.daemonIn(ctx, sc, id) },
		func(id int64) (bool, error) { return s.inboundIn(ctx, sc, id) }
}

// nodeAtPath allows a node admin the {id} node.
func nodeAtPath(s *Server, r *http.Request, _ scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	return good && sc.nodes[id], nil
}

// daemonAtPath allows a node admin a daemon on their nodes.
func daemonAtPath(s *Server, r *http.Request, _ scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	if !good {
		return false, nil
	}
	return s.daemonIn(r.Context(), sc, id)
}

// daemonInBody allows a node admin the body's daemon_id when it is on their nodes.
func daemonInBody(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	daemon, _ := scopeTests(s, r, sc)
	return allIn(required(b.DaemonID, daemon))
}

// newInbound allows creating an inbound on, and behind an edge on, the admin's nodes.
func newInbound(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	daemon, _ := scopeTests(s, r, sc)
	return allIn(required(b.DaemonID, daemon), optional(b.EdgeDaemonID, daemon))
}

// inboundAtPath allows editing or deleting an inbound on the admin's nodes.
func inboundAtPath(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	if !good {
		return false, nil
	}
	daemon, inbound := scopeTests(s, r, sc)
	return allIn(required(&id, inbound), optional(b.EdgeDaemonID, daemon))
}

// newHost allows adding a host to an inbound on the admin's nodes.
func newHost(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	_, inbound := scopeTests(s, r, sc)
	return allIn(required(b.InboundID, inbound))
}

// hostAtPath allows a host whose inbound, and bridge inbound if any, are on the admin's nodes.
func hostAtPath(s *Server, r *http.Request, _ scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	if !good {
		return false, nil
	}
	h, err := s.Queries.GetHost(r.Context(), id)
	if err != nil {
		return false, err
	}
	_, inbound := scopeTests(s, r, sc)
	return allIn(required(&h.InboundID, inbound), optional(h.BridgeInboundID, inbound))
}

// newOutbound allows an outbound on the admin's daemons that targets only their inbounds.
func newOutbound(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	daemon, inbound := scopeTests(s, r, sc)
	return allIn(required(b.DaemonID, daemon), optional(b.TargetInboundID, inbound))
}

// outboundAtPath allows editing or deleting an outbound on the admin's daemons.
func outboundAtPath(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	if !good {
		return false, nil
	}
	o, err := s.Queries.GetOutbound(r.Context(), id)
	if err != nil {
		return false, err
	}
	daemon, inbound := scopeTests(s, r, sc)
	return allIn(required(&o.DaemonID, daemon), optional(o.TargetInboundID, inbound), optional(b.TargetInboundID, inbound))
}

// newRule allows a rule pinned to one of the admin's daemons. Rules for every daemon stay global.
func newRule(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	daemon, _ := scopeTests(s, r, sc)
	return allIn(required(b.DaemonID, daemon))
}

// ruleAtPath allows a rule pinned to the admin's daemons, which must stay pinned to them.
func ruleAtPath(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	if !good {
		return false, nil
	}
	rule, err := s.Queries.GetRule(r.Context(), id)
	if err != nil {
		return false, err
	}
	daemon, _ := scopeTests(s, r, sc)
	tests := []func() (bool, error){required(rule.DaemonID, daemon)}
	if r.Method == http.MethodPut {
		tests = append(tests, required(b.DaemonID, daemon))
	}
	return allIn(tests...)
}

// rulesInBody allows reordering only rules pinned to the admin's daemons.
func rulesInBody(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	daemon, _ := scopeTests(s, r, sc)
	for _, id := range b.IDs {
		rule, err := s.Queries.GetRule(r.Context(), id)
		if err != nil {
			return false, err
		}
		if good, err := required(rule.DaemonID, daemon)(); err != nil || !good {
			return false, err
		}
	}
	return true, nil
}

// newBridge allows a bridge whose daemon and target inbound are both on the admin's nodes.
func newBridge(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	daemon, inbound := scopeTests(s, r, sc)
	return allIn(required(b.BridgeDaemonID, daemon), optional(b.TargetInboundID, inbound))
}

// squadInbounds allows a squad body whose inbounds are all on the admin's nodes.
func squadInbounds(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	if len(b.InboundIDs) == 0 {
		return false, nil
	}
	_, inbound := scopeTests(s, r, sc)
	for _, id := range b.InboundIDs {
		if good, err := inbound(id); err != nil || !good {
			return false, err
		}
	}
	return true, nil
}

// squadAtPath allows a squad that only reaches the admin's nodes, and on edit keeps it that way.
func squadAtPath(s *Server, r *http.Request, b scopeBody, sc *nodeScope) (bool, error) {
	id, good := pathID(r)
	if !good || !sc.ownsSquad(id) {
		return false, nil
	}
	if r.Method == http.MethodPut {
		return squadInbounds(s, r, b, sc)
	}
	return true, nil
}

// nodeAdminsBarred answers with a 403 for node admins, on user routes that are open to resellers.
func nodeAdminsBarred(w http.ResponseWriter, r *http.Request) bool {
	if scopeFrom(r.Context()) != nil {
		forbidden(w, "node admins can't do that")
		return true
	}
	return false
}
