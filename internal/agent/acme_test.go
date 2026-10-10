package agent

import (
	"os"
	"testing"
	"time"

	"frostbite/internal/spec"
)

func daemonWith(domain string) spec.Daemon {
	return spec.Daemon{Inbounds: []spec.Inbound{{
		Tag: "a", Protocol: spec.ProtoVLESS, Port: 443,
		Security: spec.Security{Type: spec.SecurityTLS, ACME: &spec.ACME{Domain: domain}},
	}}}
}

func TestStandInIsMarkedAndNotCountedAsReady(t *testing.T) {
	c := newCerts(t.TempDir(), "", 0, nil)
	c.Want(daemonWith("vpn.example.test"))

	_, _, marker := c.certPaths("vpn.example.test")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("a stand-in certificate should be marked as one")
	}
	st := c.inspect("vpn.example.test")
	if st.OK || !st.Placeholder || st.Expires.IsZero() {
		t.Fatalf("a stand-in is not a real certificate: %+v", st)
	}
}

func TestRealCertificateIsReady(t *testing.T) {
	c := newCerts(t.TempDir(), "", 0, nil)
	cert, key, marker := c.certPaths("ok.example.test")
	if err := selfSigned(cert, key, "ok.example.test"); err != nil {
		t.Fatal(err)
	}
	st := c.inspect("ok.example.test")
	if !st.OK || st.Placeholder || time.Until(st.Expires) < renewBefore {
		t.Fatalf("a valid certificate without a marker should be ready: %+v", st)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("no marker expected")
	}
}

func TestWantDropsDomainsThatLeftTheSpec(t *testing.T) {
	c := newCerts(t.TempDir(), "", 0, nil)
	c.Want(daemonWith("a.example.test"))
	c.set(c.inspect("a.example.test"))
	c.Want(daemonWith("b.example.test"))
	for _, s := range c.Statuses() {
		if s.Domain == "a.example.test" {
			t.Fatal("a domain nobody asks for any more should stop being reported")
		}
	}
}

func TestLocalizeMapsTheContainerPath(t *testing.T) {
	a := &Agent{cfg: Config{DataDir: "/var/lib/fb"}}
	d := daemonWith("vpn.example.test")
	a.localize(&d)
	if got := d.Inbounds[0].Security.CertPath; got != "/var/lib/fb/acme/vpn.example.test/fullchain.pem" {
		t.Fatalf("unexpected path %q", got)
	}
}
