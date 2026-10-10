package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookSignsAndRetries(t *testing.T) {
	var calls int
	var gotSig, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		gotSig, gotBody = r.Header.Get("X-Frostbite-Signature"), string(b)
		if calls < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := New(nil, nil, nil)
	ev := Event{Kind: UserExpired, User: &UserInfo{Username: "alice"}}
	if err := s.postWebhook(context.Background(), Webhook{URL: srv.URL, Secret: "k", Enabled: true}, ev); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected a retry after the 502, got %d calls", calls)
	}
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write([]byte(gotBody))
	if gotSig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not match the body")
	}
}

func TestWebhookDoesNotRetryRejections(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if err := New(nil, nil, nil).postWebhook(context.Background(), Webhook{URL: srv.URL}, Event{Kind: Test}); err == nil || calls != 1 {
		t.Fatalf("a 403 should fail once, got err=%v calls=%d", err, calls)
	}
}

func TestEventFilter(t *testing.T) {
	if !wants(nil, UserExpired) || !wants([]string{UserExpired}, UserExpired) || wants([]string{NodeOffline}, UserExpired) {
		t.Fatal("empty list means everything, otherwise only what is listed")
	}
}

func TestTelegramSendUsesAPIBase(t *testing.T) {
	var path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()

	s := New(nil, nil, nil)
	if err := s.send(context.Background(), Telegram{Token: "123:abc", APIBase: srv.URL}, 42, "hi <b>"); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:abc/sendMessage" || body["chat_id"].(float64) != 42 {
		t.Fatalf("unexpected request: %s %v", path, body)
	}
}

func TestTelegramErrorsSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer srv.Close()
	err := New(nil, nil, nil).send(context.Background(), Telegram{Token: "x", APIBase: srv.URL}, 1, "hi")
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("want the Telegram description, got %v", err)
	}
}

func TestTextEscapesNames(t *testing.T) {
	got := Text(Event{Kind: UserExpired, User: &UserInfo{Username: "<script>"}, At: time.Now()})
	if strings.Contains(got, "<script>") {
		t.Fatal("usernames must be escaped for Telegram's html mode")
	}
}
