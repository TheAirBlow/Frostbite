// Package warp registers Cloudflare WARP accounts, which cores then use as a WireGuard exit.
package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"frostbite/internal/keys"
)

// apiBase is Cloudflare's client registration api.
const apiBase = "https://api.cloudflareclient.com/v0a2158"

// FallbackEndpoint is used when Cloudflare does not hand out a usable one.
const FallbackEndpoint = "162.159.192.1:2408"

// Account is a registered WARP identity.
type Account struct {
	ID          string    `json:"id"`
	Token       string    `json:"token"`
	License     string    `json:"license"`
	Type        string    `json:"type"` // free, limited or unlimited (WARP+)
	PrivateKey  string    `json:"private_key"`
	PublicKey   string    `json:"public_key"`
	PeerKey     string    `json:"peer_key"`
	AddressV4   string    `json:"address_v4"`
	AddressV6   string    `json:"address_v6"`
	Reserved    [3]int    `json:"reserved"`
	Endpoint    string    `json:"endpoint"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description,omitempty"`
}

// Client talks to Cloudflare. BaseURL can be swapped in tests.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client for the real api.
func New() *Client {
	return &Client{BaseURL: apiBase, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// response is the part of Cloudflare's answer we use.
type response struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License     string `json:"license"`
		AccountType string `json:"account_type"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// Register creates a fresh account with its own key pair.
func (c *Client) Register(ctx context.Context) (Account, error) {
	pair, err := keys.WireGuard()
	if err != nil {
		return Account{}, err
	}
	serial := make([]byte, 8)
	_, _ = rand.Read(serial)

	var resp response
	body := map[string]any{
		"key": pair.Public, "install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model": "PC", "serial_number": hex.EncodeToString(serial), "locale": "en_US",
	}
	if err := c.do(ctx, http.MethodPost, "/reg", "", body, &resp); err != nil {
		return Account{}, err
	}
	return fromResponse(resp, pair, ""), nil
}

// SetLicense attaches a WARP+ key to an account and refreshes what Cloudflare says about it.
func (c *Client) SetLicense(ctx context.Context, a Account, license string) (Account, error) {
	if err := c.do(ctx, http.MethodPut, "/reg/"+a.ID+"/account", a.Token, map[string]any{"license": license}, nil); err != nil {
		return a, err
	}
	var resp response
	if err := c.do(ctx, http.MethodGet, "/reg/"+a.ID, a.Token, nil, &resp); err != nil {
		return a, err
	}
	next := fromResponse(resp, keys.Pair{Private: a.PrivateKey, Public: a.PublicKey}, license)
	next.Token, next.CreatedAt = a.Token, a.CreatedAt
	return next, nil
}

// fromResponse builds an Account from Cloudflare's answer.
func fromResponse(r response, pair keys.Pair, license string) Account {
	a := Account{
		ID: r.ID, Token: r.Token, License: license, Type: r.Account.AccountType, PrivateKey: pair.Private, PublicKey: pair.Public,
		AddressV4: r.Config.Interface.Addresses.V4, AddressV6: r.Config.Interface.Addresses.V6, Endpoint: FallbackEndpoint, CreatedAt: time.Now().UTC(),
	}
	if a.License == "" {
		a.License = r.Account.License
	}
	if len(r.Config.Peers) > 0 {
		a.PeerKey = r.Config.Peers[0].PublicKey
	}
	if raw, err := base64.StdEncoding.DecodeString(r.Config.ClientID); err == nil && len(raw) >= 3 {
		a.Reserved = [3]int{int(raw[0]), int(raw[1]), int(raw[2])}
	}
	return a
}

// do performs one api call.
func (c *Client) do(ctx context.Context, method, path, token string, in, out any) error {
	var rd io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.3-1922")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach Cloudflare: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cloudflare answered %s: %s", resp.Status, trim(string(data), 200))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// trim shortens s for error messages.
func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
