package egress

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ruleSetServer serves a rule set that fails the first fails downloads.
func ruleSetServer(t *testing.T, fails int32) *httptest.Server {
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= fails {
			http.Error(w, "not yet", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"version":3,"rules":[{"domain":["blocked.test"]}]}`)
	}))
	t.Cleanup(s.Close)
	return s
}

// withRuleSet is an egress config that needs the rule set at url to start.
func withRuleSet(url string) []byte {
	return fmt.Appendf(nil, `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{
		"rule_set":[{"type":"remote","tag":"x","format":"source","url":%q}],
		"rules":[{"rule_set":["x"],"action":"reject"}]}}`, url)
}

func TestFailedStartIsRetried(t *testing.T) {
	firstRetry, lastRetry = 50*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { firstRetry, lastRetry = 5*time.Second, 5*time.Minute })
	e := New(func(string, string) {})
	t.Cleanup(func() { e.Close() })

	raw := withRuleSet(ruleSetServer(t, 2).URL)
	if err := e.Apply(raw); err == nil {
		t.Fatal("started without its rule set")
	}
	if e.Apply(raw) == nil {
		t.Fatal("applying the same config again forgot why it is not running")
	}
	deadline := time.Now().Add(10 * time.Second)
	for e.Err() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("never started: %v", e.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e.cur.Load() == nil || e.Apply(raw) != nil {
		t.Fatal("started but does not run")
	}
}

func TestFailedStartKeepsThePreviousConfig(t *testing.T) {
	e := New(func(string, string) {})
	t.Cleanup(func() { e.Close() })
	if err := e.Apply(Config(nil)); err != nil {
		t.Fatal(err)
	}
	before := e.cur.Load()
	if err := e.Apply(withRuleSet("http://127.0.0.1:1/x.json")); err == nil {
		t.Fatal("started without its rule set")
	}
	if e.cur.Load() != before {
		t.Fatal("the running config was dropped")
	}
}

func TestRejectedConfigIsNotRetried(t *testing.T) {
	e := New(func(string, string) {})
	t.Cleanup(func() { e.Close() })
	if err := e.Apply([]byte(`{"outbounds":[{"type":"no such type"}]}`)); err == nil {
		t.Fatal("accepted a bad config")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retry != nil {
		t.Fatal("retrying a config that can never start")
	}
}
