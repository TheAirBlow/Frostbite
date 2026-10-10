package singbox

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unsafe"

	anytls "github.com/anytls/sing-anytls"
	"github.com/google/uuid"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"frostbite/internal/core/singbox"
	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

// Most sing-box inbounds only take their users at construction, and look a user's name up by index in a list they keep.
// To change users without a restart, a new user gets the next unused index: the list is copied with the new entries
// appended and swapped in, and only then is the protocol service told about the new users. Indexes are never reused and
// existing entries never move, so a connection that holds an index always finds the same user whichever copy it reads.
// Removed users leave a dead entry behind until the next restart.
//
// VMess swaps its tables one after another, so a handshake that lands in the middle can see a half updated set. Only a
// user that is being added right now can be affected, and their handshake simply fails once and is retried: everyone who
// stays keeps the same key in every table.
//
// AnyTLS keeps its users inside the service, SOCKS, HTTP, mixed and Naive check a table that is replaced as a whole, and
// WireGuard peers are changed through the device's own configuration interface. None of those need an index list.
//
// This reaches into sing-box internals (see the pinned version in go.mod). Anything unexpected makes the caller fall back
// to a restart, so the worst case is the old behaviour.

// maxAdded is how many user changes an inbound absorbs before it needs a restart to drop its dead entries.
const maxAdded = 4096

// errNoSlots means an inbound collected too many dead entries.
var errNoSlots = errors.New("too many user changes since the last restart")

// slotState tracks which user sits in which slot of one inbound.
type slotState struct {
	idx  map[string]int    // user label -> slot
	cred map[string]string // user label -> credential fingerprint
	next int               // first slot never used
	size int               // slots in total
	// direct inbounds hold their users in the service or in a table that is replaced whole, so no slots are used
	direct bool
}

// credOf fingerprints everything about a user that matters to the protocol.
func credOf(in spec.Inbound, u spec.User) string {
	return strings.Join([]string{u.UUID, u.Password, singbox.FlowOf(in, u)}, "|")
}

// slotChange is the result of planning a user update.
type slotChange struct {
	added   map[string]int // label -> newly assigned slot
	removed []string       // labels whose old credentials stop working
	idx     map[string]int // label -> slot, after the change
	cred    map[string]string
	next    int
}

// plan works out the slot changes for a new user list without touching any state.
func (s *slotState) plan(in spec.Inbound) (slotChange, error) {
	ch := slotChange{added: map[string]int{}, idx: map[string]int{}, cred: map[string]string{}, next: s.next}
	want := map[string]string{}
	for _, u := range in.Users {
		want[u.Name] = credOf(in, u)
	}
	for name, c := range s.cred {
		if w, ok := want[name]; !ok || w != c {
			ch.removed = append(ch.removed, name)
		}
	}
	slices.Sort(ch.removed)

	for _, u := range in.Users {
		c := want[u.Name]
		if i, ok := s.idx[u.Name]; ok && s.cred[u.Name] == c {
			ch.idx[u.Name], ch.cred[u.Name] = i, c
			continue
		}
		if !s.direct && ch.next >= s.size {
			return slotChange{}, errNoSlots
		}
		ch.idx[u.Name], ch.cred[u.Name], ch.added[u.Name] = ch.next, c, ch.next
		ch.next++
	}
	return ch, nil
}

// commit makes a planned change the current state.
func (s *slotState) commit(ch slotChange) {
	s.idx, s.cred, s.next = ch.idx, ch.cred, ch.next
}

// layoutOf records how the users of every inbound that supports live updates are laid out.
func layoutOf(opts *option.Options, d spec.Daemon) map[string]*slotState {
	out := map[string]*slotState{}
	find := func(tag string) *spec.Inbound {
		for j := range d.Inbounds {
			if d.Inbounds[j].Tag == tag {
				return &d.Inbounds[j]
			}
		}
		return nil
	}
	record := func(in *spec.Inbound, tag string, real int, padded, direct bool) {
		if real != len(in.Users) {
			return // the layout does not line up with the spec, so leave this inbound to restarts
		}
		st := &slotState{idx: map[string]int{}, cred: map[string]string{}, next: real, size: real, direct: direct}
		if padded {
			st.size = real + maxAdded
		}
		for k, u := range in.Users {
			st.idx[u.Name], st.cred[u.Name] = k, credOf(*in, u)
		}
		out[tag] = st
	}

	for i := range opts.Inbounds {
		ib := &opts.Inbounds[i]
		in := find(ib.Tag)
		if in == nil {
			continue
		}

		real, padded, direct := 0, false, false
		switch o := ib.Options.(type) {
		case *option.VLESSInboundOptions:
			real, padded = len(o.Users), true
		case *option.VMessInboundOptions:
			real, padded = len(o.Users), true
		case *option.TrojanInboundOptions:
			real, padded = len(o.Users), true
		case *option.Hysteria2InboundOptions:
			real, padded = len(o.Users), true
		case *option.TUICInboundOptions:
			real, padded = len(o.Users), true
		case *option.ShadowsocksInboundOptions:
			real = len(o.Users)
		case *option.AnyTLSInboundOptions:
			real, direct = len(o.Users), true
		case *option.NaiveInboundOptions:
			real, direct = len(o.Users), true
		case *option.SocksInboundOptions:
			real, direct = len(o.Users), true
		case *option.HTTPMixedInboundOptions:
			real, direct = len(o.Users), true
		}
		record(in, ib.Tag, real, padded, direct)
	}
	for i := range opts.Endpoints {
		ep := &opts.Endpoints[i]
		in := find(ep.Tag)
		if o, ok := ep.Options.(*option.WireGuardEndpointOptions); ok && in != nil {
			record(in, ep.Tag, len(o.Peers), false, true)
		}
	}
	return out
}

// spare returns a random secret nobody will ever send.
func spare() string {
	t, _ := keys.Token(18)
	return t
}

// hot applies a change that only touches users, or says why it cannot.
func (r *Runtime) hot(old, next spec.Daemon) error {
	for _, in := range next.Inbounds {
		var prev *spec.Inbound
		for j := range old.Inbounds {
			if old.Inbounds[j].Tag == in.Tag {
				prev = &old.Inbounds[j]
			}
		}
		if prev == nil {
			return fmt.Errorf("inbound %s is new", in.Tag)
		}
		if reflect.DeepEqual(prev.Users, in.Users) {
			continue
		}
		if err := r.hotInbound(*prev, in); err != nil {
			return fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
	}
	return nil
}

// hotInbound changes the users of one running inbound.
func (r *Runtime) hotInbound(prev, in spec.Inbound) error {
	st := r.slots[in.Tag]
	if st == nil {
		return errors.New("this inbound cannot change users live")
	}
	if in.Protocol == spec.ProtoWireGuard {
		return r.hotWireGuard(prev, in, st)
	}
	ib, ok := r.instance.Inbound().Get(in.Tag)
	if !ok {
		return errors.New("the running inbound is missing")
	}

	if in.Protocol == spec.ProtoShadowsocks {
		return r.hotShadowsocks(ib, in, st)
	}
	h, ok := hotProtocols[in.Protocol]
	if !ok {
		return fmt.Errorf("%s needs a restart to change users", in.Protocol)
	}

	ch, err := st.plan(in)
	if err != nil {
		return err
	}
	host := reflect.ValueOf(ib)
	if host.Kind() != reflect.Pointer || host.Elem().Kind() != reflect.Struct {
		return errors.New("unexpected inbound type")
	}
	host = host.Elem()

	byLabel := map[string]spec.User{}
	for _, u := range in.Users {
		byLabel[u.Name] = u
	}
	if h.field != "" {
		if err := grow(host, h, ch, byLabel, in); err != nil {
			return err
		}
	}

	// the service gets the whole active list; spare slots and removed users drop out
	var slots []int
	var active []spec.User
	for _, u := range in.Users {
		slots = append(slots, ch.idx[u.Name])
		active = append(active, u)
	}
	svc, err := unexported(host, h.service)
	if err != nil {
		return err
	}
	if err := h.call(svc, slots, active, in); err != nil {
		return err
	}

	st.commit(ch)
	for _, name := range ch.removed {
		r.tracker.kick(name, in.Tag)
	}
	return nil
}

// hotShadowsocks uses the update call sing-box exposes for shadowsocks.
func (r *Runtime) hotShadowsocks(ib adapter.Inbound, in spec.Inbound, st *slotState) error {
	m, ok := ib.(adapter.ManagedSSMServer)
	if !ok {
		return errors.New("this shadowsocks inbound has a single password, not users")
	}
	names := make([]string, len(in.Users))
	psks := make([]string, len(in.Users))
	for i, u := range in.Users {
		names[i], psks[i] = u.Name, u.Password
	}
	if err := m.UpdateUsers(names, psks); err != nil {
		return err
	}
	removed := map[string]bool{}
	for name := range st.cred {
		removed[name] = true
	}
	st.idx, st.cred = map[string]int{}, map[string]string{}
	for i, u := range in.Users {
		delete(removed, u.Name)
		st.idx[u.Name], st.cred[u.Name] = i, credOf(in, u)
	}
	for name := range removed {
		r.tracker.kick(name, in.Tag)
	}
	return nil
}

// hotProtocol knows how one protocol stores its users.
type hotProtocol struct {
	service string                                                     // name of the service field
	field   string                                                     // name of the list the inbound keeps its users in
	write   func(el reflect.Value, u spec.User, in spec.Inbound) error // fills one new entry of that list
	call    func(svc reflect.Value, slots []int, users []spec.User, in spec.Inbound) error
}

var hotProtocols = map[string]hotProtocol{
	spec.ProtoVLESS: {
		service: "service",
		field:   "users",
		write: func(el reflect.Value, u spec.User, in spec.Inbound) error {
			return fill(el, map[string]any{"Name": u.Name, "UUID": u.UUID, "Flow": singbox.FlowOf(in, u)})
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, in spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.UUID }), pick(users, func(u spec.User) string { return singbox.FlowOf(in, u) }))
		},
	},
	spec.ProtoTrojan: {
		service: "service",
		field:   "users",
		write: func(el reflect.Value, u spec.User, _ spec.Inbound) error {
			return fill(el, map[string]any{"Name": u.Name, "Password": u.Password})
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, _ spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.Password }))
		},
	},
	spec.ProtoVMess: {
		service: "service",
		field:   "users",
		write: func(el reflect.Value, u spec.User, _ spec.Inbound) error {
			return fill(el, map[string]any{"Name": u.Name, "UUID": u.UUID})
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, _ spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.UUID }), make([]int, len(users)))
		},
	},
	spec.ProtoAnyTLS: {
		service: "service",
		call: func(svc reflect.Value, _ []int, users []spec.User, _ spec.Inbound) error {
			list := make([]anytls.User, len(users))
			for i, u := range users {
				list[i] = anytls.User{Name: u.Name, Password: u.Password}
			}
			return update(svc, list)
		},
	},
	spec.ProtoNaive: {service: "authenticator", call: swapAuthenticator},
	spec.ProtoSOCKS: {service: "authenticator", call: swapAuthenticator},
	spec.ProtoHTTP:  {service: "authenticator", call: swapAuthenticator},
	spec.ProtoMixed: {service: "authenticator", call: swapAuthenticator},
	spec.ProtoHysteria2: {
		service: "service",
		field:   "userNameList",
		write: func(el reflect.Value, u spec.User, _ spec.Inbound) error {
			return setName(el, u.Name)
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, _ spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.Password }))
		},
	},
	spec.ProtoTUIC: {
		service: "server",
		field:   "userNameList",
		write: func(el reflect.Value, u spec.User, _ spec.Inbound) error {
			return setName(el, u.Name)
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, _ spec.Inbound) error {
			ids := make([][16]byte, len(users))
			for i, u := range users {
				id, err := uuid.Parse(u.UUID)
				if err != nil {
					return fmt.Errorf("user %s has no valid uuid: %w", u.Name, err)
				}
				ids[i] = id
			}
			return update(svc, slots, ids, pick(users, func(u spec.User) string { return u.Password }))
		},
	},
}

// pick maps users to one of their fields.
func pick(users []spec.User, f func(spec.User) string) []string {
	out := make([]string, len(users))
	for i, u := range users {
		out[i] = f(u)
	}
	return out
}

// unexported returns a settable view of a private struct field.
func unexported(host reflect.Value, name string) (reflect.Value, error) {
	f := host.FieldByName(name)
	if !f.IsValid() {
		return reflect.Value{}, fmt.Errorf("sing-box changed: no field %q", name)
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem(), nil
}

// grow publishes a copy of the inbound's user list with the new users appended. It does so before the service hears about
// them, so by the time anyone can authenticate as a new user the list already has their entry.
func grow(host reflect.Value, h hotProtocol, ch slotChange, byLabel map[string]spec.User, in spec.Inbound) error {
	list, err := unexported(host, h.field)
	if err != nil {
		return err
	}
	if list.Kind() != reflect.Slice {
		return fmt.Errorf("sing-box changed: %s is not a list", h.field)
	}
	n := max(ch.next, list.Len())
	next := reflect.MakeSlice(list.Type(), n, n)
	reflect.Copy(next, list)
	for name, slot := range ch.added {
		if err := h.write(next.Index(slot), byLabel[name], in); err != nil {
			return err
		}
	}
	list.Set(next)
	return nil
}

// fill writes fields into one user struct of a private list.
func fill(el reflect.Value, values map[string]any) error {
	for name, v := range values {
		f := el.FieldByName(name)
		if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.ValueOf(v).Kind() {
			return fmt.Errorf("sing-box changed: user field %q", name)
		}
		f.Set(reflect.ValueOf(v))
	}
	return nil
}

// setName writes one entry of a private list of names.
func setName(el reflect.Value, name string) error {
	if el.Kind() != reflect.String {
		return errors.New("sing-box changed: the user names are not strings")
	}
	el.SetString(name)
	return nil
}

// update calls the service's UpdateUsers with arguments of exactly the types it declares.
func update(svc reflect.Value, args ...any) error {
	m := svc.MethodByName("UpdateUsers")
	if !m.IsValid() {
		return errors.New("sing-box changed: the service has no UpdateUsers")
	}
	t := m.Type()
	if t.NumIn() != len(args) {
		return fmt.Errorf("sing-box changed: UpdateUsers takes %d arguments", t.NumIn())
	}
	in := make([]reflect.Value, len(args))
	for i, a := range args {
		v := reflect.ValueOf(a)
		if v.Type() != t.In(i) {
			return fmt.Errorf("sing-box changed: UpdateUsers argument %d is %s", i, t.In(i))
		}
		in[i] = v
	}
	out := m.Call(in)
	if n := len(out); n > 0 {
		if err, ok := out[n-1].Interface().(error); ok && err != nil {
			return err
		}
	}
	return nil
}

// swapAuthenticator replaces the table SOCKS, HTTP, mixed and Naive check credentials against. Each connection reads the
// field when it authenticates, so it sees the old table or the new one. With nobody left the table gets a login nobody
// knows: an empty one would let everyone in.
func swapAuthenticator(field reflect.Value, _ []int, users []spec.User, _ spec.Inbound) error {
	if field.Type() != reflect.TypeFor[*auth.Authenticator]() {
		return fmt.Errorf("sing-box changed: the credential table is %s", field.Type())
	}
	list := make([]auth.User, len(users))
	for i, u := range users {
		list[i] = auth.User{Username: u.Name, Password: u.Password}
	}
	if len(list) == 0 {
		list = []auth.User{{Username: spare(), Password: spare()}}
	}
	field.Set(reflect.ValueOf(auth.NewAuthenticator(list)))
	return nil
}

// hotWireGuard adds and removes peers of a running WireGuard endpoint through the device's own configuration interface.
func (r *Runtime) hotWireGuard(prev, in spec.Inbound, st *slotState) error {
	ep, ok := r.instance.Endpoint().Get(in.Tag)
	if !ok {
		return errors.New("the running endpoint is missing")
	}
	dev, err := wireguardDevice(ep)
	if err != nil {
		return err
	}

	ch, err := st.plan(in)
	if err != nil {
		return err
	}
	peerKey := func(u spec.User) (string, error) {
		pub, err := keys.WireGuardPublic(u.Password)
		if err != nil {
			return "", fmt.Errorf("user %s: %w", u.Name, err)
		}
		raw, err := base64.StdEncoding.DecodeString(pub)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}

	// removals go first, so a peer whose key changed is gone before the new one is added
	var conf strings.Builder
	oldByName := map[string]spec.User{}
	for _, u := range prev.Users {
		oldByName[u.Name] = u
	}
	for _, name := range ch.removed {
		old, ok := oldByName[name]
		if !ok {
			continue
		}
		k, err := peerKey(old)
		if err != nil {
			return err
		}
		fmt.Fprintf(&conf, "public_key=%s\nremove=true\n", k)
	}
	for _, u := range in.Users {
		if _, isNew := ch.added[u.Name]; !isNew {
			continue
		}
		k, err := peerKey(u)
		if err != nil {
			return err
		}
		ip, err := spec.WGAddress(in.Options.WGSubnet, u.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(&conf, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", k, ip)
	}

	if conf.Len() > 0 {
		m := dev.MethodByName("IpcSet")
		if !m.IsValid() || m.Type().NumIn() != 1 || m.Type().In(0).Kind() != reflect.String {
			return errors.New("sing-box changed: the WireGuard device has no IpcSet")
		}
		if out := m.Call([]reflect.Value{reflect.ValueOf(conf.String())}); len(out) == 1 {
			if err, _ := out[0].Interface().(error); err != nil {
				return err
			}
		}
	}

	st.commit(ch)
	for _, name := range ch.removed {
		r.tracker.kick(name, in.Tag)
	}
	return nil
}

// wireguardDevice reaches the wireguard-go device inside a running sing-box WireGuard endpoint.
func wireguardDevice(ep adapter.Endpoint) (reflect.Value, error) {
	host := reflect.ValueOf(ep)
	if host.Kind() != reflect.Pointer || host.Elem().Kind() != reflect.Struct {
		return reflect.Value{}, errors.New("unexpected endpoint type")
	}
	inner, err := unexported(host.Elem(), "endpoint")
	if err != nil {
		return reflect.Value{}, err
	}
	if inner.Kind() != reflect.Pointer || inner.IsNil() {
		return reflect.Value{}, errors.New("the WireGuard endpoint is not running")
	}
	dev, err := unexported(inner.Elem(), "device")
	if err != nil {
		return reflect.Value{}, err
	}
	if dev.Kind() != reflect.Pointer || dev.IsNil() {
		return reflect.Value{}, errors.New("the WireGuard device is not running")
	}
	return dev, nil
}
