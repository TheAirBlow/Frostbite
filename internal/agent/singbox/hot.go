package singbox

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"

	"frostbite/internal/core/singbox"
	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

// Most sing-box inbounds only take their users at construction. To change them without a restart, each inbound is built
// with spare, unusable user slots. A new user is written into a slot nobody has used yet and the protocol service is told
// about the new list. Slots are never reused, so no connection can be looking at an entry while it is written.
//
// VMess is left out on purpose: its service swaps four related tables one after another, so a handshake that lands in
// the middle could see a half updated set. It restarts as before.
//
// This reaches into sing-box internals (see the pinned version in go.mod). Anything unexpected makes the caller fall back
// to a restart, so the worst case is the old behaviour.

// spareSlots is how many user changes an inbound absorbs before it needs a restart.
const spareSlots = 512

// errNoSlots means an inbound used up its spare slots.
var errNoSlots = errors.New("out of spare user slots")

// slotState tracks which user sits in which slot of one inbound.
type slotState struct {
	idx  map[string]int    // user label -> slot
	cred map[string]string // user label -> credential fingerprint
	next int               // first slot never used
	size int               // slots in total
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
		if ch.next >= s.size {
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

// padUsers adds the spare slots to inbounds that support live updates and records the layout of every inbound.
func padUsers(opts *option.Options, d spec.Daemon) map[string]*slotState {
	out := map[string]*slotState{}
	for i := range opts.Inbounds {
		ib := &opts.Inbounds[i]
		var in *spec.Inbound
		for j := range d.Inbounds {
			if d.Inbounds[j].Tag == ib.Tag {
				in = &d.Inbounds[j]
			}
		}
		if in == nil {
			continue
		}

		real, padded := 0, false
		switch o := ib.Options.(type) {
		case *option.VLESSInboundOptions:
			real = len(o.Users)
			for range spareSlots {
				o.Users = append(o.Users, option.VLESSUser{UUID: uuid.NewString()})
			}
			padded = true
		case *option.TrojanInboundOptions:
			real = len(o.Users)
			for range spareSlots {
				o.Users = append(o.Users, option.TrojanUser{Password: spare()})
			}
			padded = true
		case *option.Hysteria2InboundOptions:
			real = len(o.Users)
			for range spareSlots {
				o.Users = append(o.Users, option.Hysteria2User{Password: spare()})
			}
			padded = true
		case *option.TUICInboundOptions:
			real = len(o.Users)
			for range spareSlots {
				o.Users = append(o.Users, option.TUICUser{UUID: uuid.NewString(), Password: spare()})
			}
			padded = true
		case *option.ShadowsocksInboundOptions:
			real = len(o.Users)
		}
		if real != len(in.Users) {
			continue // the layout does not line up with the spec, so leave this inbound to restarts
		}

		st := &slotState{idx: map[string]int{}, cred: map[string]string{}, next: real, size: real}
		if padded {
			st.size = real + spareSlots
		}
		for k, u := range in.Users {
			st.idx[u.Name], st.cred[u.Name] = k, credOf(*in, u)
		}
		out[ib.Tag] = st
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
		if err := r.hotInbound(in); err != nil {
			return fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
	}
	return nil
}

// hotInbound changes the users of one running inbound.
func (r *Runtime) hotInbound(in spec.Inbound) error {
	st := r.slots[in.Tag]
	if st == nil {
		return errors.New("this inbound cannot change users live")
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
	for name, slot := range ch.added {
		if err := h.write(host, slot, byLabel[name], in); err != nil {
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
	service string                                                                 // name of the service field
	write   func(host reflect.Value, slot int, u spec.User, in spec.Inbound) error // fills one spare slot
	call    func(svc reflect.Value, slots []int, users []spec.User, in spec.Inbound) error
}

var hotProtocols = map[string]hotProtocol{
	spec.ProtoVLESS: {
		service: "service",
		write: func(h reflect.Value, slot int, u spec.User, in spec.Inbound) error {
			return fill(h, "users", slot, map[string]any{"Name": u.Name, "UUID": u.UUID, "Flow": singbox.FlowOf(in, u)})
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, in spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.UUID }), pick(users, func(u spec.User) string { return singbox.FlowOf(in, u) }))
		},
	},
	spec.ProtoTrojan: {
		service: "service",
		write: func(h reflect.Value, slot int, u spec.User, _ spec.Inbound) error {
			return fill(h, "users", slot, map[string]any{"Name": u.Name, "Password": u.Password})
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, _ spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.Password }))
		},
	},
	spec.ProtoHysteria2: {
		service: "service",
		write: func(h reflect.Value, slot int, u spec.User, _ spec.Inbound) error {
			return setName(h, "userNameList", slot, u.Name)
		},
		call: func(svc reflect.Value, slots []int, users []spec.User, _ spec.Inbound) error {
			return update(svc, slots, pick(users, func(u spec.User) string { return u.Password }))
		},
	},
	spec.ProtoTUIC: {
		service: "server",
		write: func(h reflect.Value, slot int, u spec.User, _ spec.Inbound) error {
			return setName(h, "userNameList", slot, u.Name)
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

// fill writes fields into one element of a private slice of user structs.
func fill(host reflect.Value, field string, slot int, values map[string]any) error {
	users, err := unexported(host, field)
	if err != nil {
		return err
	}
	if users.Kind() != reflect.Slice || slot >= users.Len() {
		return fmt.Errorf("slot %d does not exist", slot)
	}
	el := users.Index(slot)
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
func setName(host reflect.Value, field string, slot int, name string) error {
	list, err := unexported(host, field)
	if err != nil {
		return err
	}
	if list.Kind() != reflect.Slice || list.Type().Elem().Kind() != reflect.String || slot >= list.Len() {
		return fmt.Errorf("slot %d does not exist", slot)
	}
	list.Index(slot).SetString(name)
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
