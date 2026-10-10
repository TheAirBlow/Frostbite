// Package compose builds the desired state of each daemon out of what is in the database.
package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/db"
	"frostbite/internal/warp"
)

// Routing holds the panel wide routing switches, stored under the "routing" setting.
type Routing struct {
	BlockBittorrent bool     `json:"block_bittorrent"`
	BlockPrivate    bool     `json:"block_private"`
	BlockAds        bool     `json:"block_ads"`
	BlockQUIC       bool     `json:"block_quic"`
	DirectDomains   []string `json:"direct_domains"`
}

// SecretKey is the setting that holds the panel secret used to derive system users.
const SecretKey = "secret"

// Topology is the part of the state that describes servers, without any user.
type Topology struct {
	Nodes         map[int64]db.Node
	Daemons       map[int64]db.Daemon
	Inbounds      map[int64]db.Inbound
	Hosts         map[int64][]db.Host // by inbound
	Outbounds     map[int64][]db.Outbound
	SquadInbounds map[int64][]int64 // squad id -> inbound ids

	byDaemon map[int64][]db.Inbound
}

// Snapshot is a consistent copy of everything a build needs.
type Snapshot struct {
	*Topology
	Rules   []db.Rule
	Users   []db.User
	Routing Routing
	Secret  string
	Warp    *warp.Account

	userByID     map[int64]db.User
	inboundUsers map[int64][]int64 // inbound id -> user ids
}

// LoadTopology reads nodes, daemons, inbounds, hosts, outbounds and squad membership.
func LoadTopology(ctx context.Context, q *db.Queries) (*Topology, error) {
	s := &Topology{
		Nodes: map[int64]db.Node{}, Daemons: map[int64]db.Daemon{}, Inbounds: map[int64]db.Inbound{},
		Hosts: map[int64][]db.Host{}, Outbounds: map[int64][]db.Outbound{},
		SquadInbounds: map[int64][]int64{}, byDaemon: map[int64][]db.Inbound{},
	}

	nodes, err := q.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("nodes: %w", err)
	}
	for _, n := range nodes {
		s.Nodes[n.ID] = n
	}
	daemons, err := q.ListDaemons(ctx)
	if err != nil {
		return nil, fmt.Errorf("daemons: %w", err)
	}
	for _, d := range daemons {
		s.Daemons[d.ID] = d
	}
	inbounds, err := q.ListInbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("inbounds: %w", err)
	}
	for _, in := range inbounds {
		s.Inbounds[in.ID] = in
		s.byDaemon[in.DaemonID] = append(s.byDaemon[in.DaemonID], in)
	}
	hosts, err := q.ListHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	for _, h := range hosts {
		s.Hosts[h.InboundID] = append(s.Hosts[h.InboundID], h)
	}
	outs, err := q.ListOutbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("outbounds: %w", err)
	}
	for _, o := range outs {
		s.Outbounds[o.DaemonID] = append(s.Outbounds[o.DaemonID], o)
	}
	squadInbounds, err := q.ListSquadInbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("squad inbounds: %w", err)
	}
	for _, si := range squadInbounds {
		s.SquadInbounds[si.SquadID] = append(s.SquadInbounds[si.SquadID], si.InboundID)
	}
	return s, nil
}

// Load reads the whole snapshot.
func Load(ctx context.Context, q *db.Queries) (*Snapshot, error) {
	topo, err := LoadTopology(ctx, q)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Topology: topo, inboundUsers: map[int64][]int64{}}

	if s.Rules, err = q.ListRules(ctx); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if s.Users, err = q.ListServingUsers(ctx); err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}
	if err := s.loadAccess(ctx, q); err != nil {
		return nil, err
	}
	if err := s.loadSettings(ctx, q); err != nil {
		return nil, err
	}
	return s, nil
}

// loadAccess works out which users may use which inbound, through their squads.
func (s *Snapshot) loadAccess(ctx context.Context, q *db.Queries) error {
	userSquads, err := q.ListUserSquads(ctx)
	if err != nil {
		return fmt.Errorf("user squads: %w", err)
	}

	serving := map[int64]bool{}
	s.userByID = map[int64]db.User{}
	for _, u := range s.Users {
		serving[u.ID] = true
		s.userByID[u.ID] = u
	}
	seen := map[[2]int64]bool{}
	for _, us := range userSquads {
		if !serving[us.UserID] {
			continue
		}
		for _, inID := range s.SquadInbounds[us.SquadID] {
			key := [2]int64{inID, us.UserID}
			if seen[key] {
				continue
			}
			seen[key] = true
			s.inboundUsers[inID] = append(s.inboundUsers[inID], us.UserID)
		}
	}
	return nil
}

// loadSettings reads the routing switches and the panel secret.
func (s *Snapshot) loadSettings(ctx context.Context, q *db.Queries) error {
	raw, err := q.GetSetting(ctx, "routing")
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("routing setting: %w", err)
	default:
		if err := json.Unmarshal(raw, &s.Routing); err != nil {
			return fmt.Errorf("routing setting: %w", err)
		}
	}

	raw, err = q.GetSetting(ctx, "warp")
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("warp setting: %w", err)
	default:
		var acc warp.Account
		if err := json.Unmarshal(raw, &acc); err == nil && acc.PrivateKey != "" {
			s.Warp = &acc
		}
	}

	raw, err = q.GetSetting(ctx, SecretKey)
	if err != nil {
		return fmt.Errorf("panel secret: %w", err)
	}
	return json.Unmarshal(raw, &s.Secret)
}
