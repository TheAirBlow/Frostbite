package singbox

import (
	"testing"

	"frostbite/internal/spec"
)

func TestPlanReusesUnchangedSlotsAndNeverRecycles(t *testing.T) {
	in := spec.Inbound{Protocol: spec.ProtoTrojan, Users: []spec.User{{Name: "u1", Password: "a"}, {Name: "u2", Password: "b"}}}
	st := &slotState{idx: map[string]int{"u1": 0, "u2": 1}, cred: map[string]string{"u1": credOf(in, in.Users[0]), "u2": credOf(in, in.Users[1])}, next: 2, size: 4}

	// u2 leaves, u3 arrives, u1 changes password
	next := spec.Inbound{Protocol: spec.ProtoTrojan, Users: []spec.User{{Name: "u1", Password: "changed"}, {Name: "u3", Password: "c"}}}
	ch, err := st.plan(next)
	if err != nil {
		t.Fatal(err)
	}
	if ch.idx["u1"] != 2 || ch.idx["u3"] != 3 {
		t.Fatalf("changed and new users must get fresh slots, got %v", ch.idx)
	}
	if len(ch.removed) != 2 || ch.removed[0] != "u1" || ch.removed[1] != "u2" {
		t.Fatalf("both the old credential and the departed user lose access: %v", ch.removed)
	}
	if st.next != 2 {
		t.Fatal("planning must not change state")
	}

	st.commit(ch)
	if _, err := st.plan(spec.Inbound{Protocol: spec.ProtoTrojan, Users: []spec.User{{Name: "u1", Password: "again"}}}); err != errNoSlots {
		t.Fatalf("running out of slots should ask for a restart, got %v", err)
	}
}
