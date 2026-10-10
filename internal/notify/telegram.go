package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"frostbite/internal/metrics"
)

// apiURL builds a Bot API url.
func (t Telegram) apiURL(method string) string {
	base := t.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	return fmt.Sprintf("%s/bot%s/%s", base, url.PathEscape(t.Token), method)
}

// call invokes a Bot API method and decodes its result.
func (s *Service) call(ctx context.Context, t Telegram, method string, body, out any) (err error) {
	start := time.Now()
	defer func() {
		// polling that simply timed out or was canceled by shutdown is not a failure of the API
		result := metrics.Result(err)
		if ctx.Err() != nil {
			result = "canceled"
		}
		metrics.TelegramCalls.WithLabelValues(method, result).Inc()
		metrics.TelegramSeconds.WithLabelValues(method).Observe(time.Since(start).Seconds())
	}()
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.apiURL(method), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// long polling needs more room than the default client allows
	client := *s.http
	client.Timeout = 40 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("telegram answered %s", resp.Status)
	}
	if !env.OK {
		return fmt.Errorf("telegram: %s", env.Description)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// send posts an html message to a chat.
func (s *Service) send(ctx context.Context, t Telegram, chat int64, text string) error {
	return s.call(ctx, t, "sendMessage", map[string]any{"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true}, nil)
}

// BotName asks Telegram for the bot's username, which the user page links to.
func (s *Service) BotName(ctx context.Context) string {
	t := s.Settings(ctx).Telegram
	if !t.Enabled || t.Token == "" {
		return ""
	}

	s.mu.Lock()
	if time.Since(s.botAt) < 10*time.Minute {
		defer s.mu.Unlock()
		return s.botName
	}
	s.mu.Unlock()

	var me struct {
		Username string `json:"username"`
	}
	name := ""
	if err := s.call(ctx, t, "getMe", map[string]any{}, &me); err == nil {
		name = me.Username
	}
	s.mu.Lock()
	s.botName, s.botAt = name, time.Now()
	s.mu.Unlock()
	return name
}
