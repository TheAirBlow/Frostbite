package notify

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/db"
	"frostbite/internal/metrics"
)

// SetBaseURL tells the bot how to write subscription links.
func (s *Service) SetBaseURL(base string) { s.base = strings.TrimRight(base, "/") }

// update is the part of a Telegram update the bot reads.
type update struct {
	ID      int64 `json:"update_id"`
	Message *struct {
		Text string `json:"text"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}

// RunBot answers commands until ctx ends. It follows the settings, so enabling or changing the token needs no restart.
func (s *Service) RunBot(ctx context.Context) {
	var offset int64
	var token string
	for ctx.Err() == nil {
		t := s.Settings(ctx).Telegram
		if !t.Enabled || t.Token == "" {
			offset = 0
			sleep(ctx, 10*time.Second)
			continue
		}
		if t.Token != token {
			token, offset = t.Token, 0
		}

		var updates []update
		err := s.call(ctx, t, "getUpdates", map[string]any{"offset": offset, "timeout": 25, "allowed_updates": []string{"message"}}, &updates)
		if err != nil {
			if ctx.Err() == nil {
				slog.Debug("notify: polling telegram failed", "err", err)
			}
			sleep(ctx, 5*time.Second)
			continue
		}
		for _, u := range updates {
			offset = u.ID + 1
			if u.Message == nil || u.Message.Text == "" {
				continue
			}
			metrics.BotUpdates.Inc()
			reply := s.command(ctx, t, u.Message.Chat.ID, u.Message.Text)
			if reply == "" {
				continue
			}
			if err := s.send(ctx, t, u.Message.Chat.ID, reply); err != nil {
				slog.Warn("notify: replying failed", "err", err)
			}
		}
	}
}

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// command works out the answer to one message.
func (s *Service) command(ctx context.Context, t Telegram, chat int64, text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return "Send /help to see what I can do."
	}
	cmd, args := strings.ToLower(strings.SplitN(fields[0], "@", 2)[0]), fields[1:]
	admin := slices.Contains(t.AdminIDs, chat)
	if admin {
		metrics.BotCommands.WithLabelValues("admin").Inc()
	} else {
		metrics.BotCommands.WithLabelValues("user").Inc()
	}

	if cmd == "/start" && len(args) == 1 {
		return s.linkAccount(ctx, chat, args[0])
	}

	user, err := s.q.GetUserByTelegram(ctx, &chat)
	linked := err == nil

	switch cmd {
	case "/start", "/help":
		return s.help(chat, admin, linked)
	case "/usage":
		if !linked {
			return notLinked
		}
		return usageText(user)
	case "/link":
		if !linked {
			return notLinked
		}
		if s.base == "" {
			return "The panel address is not set, ask your administrator."
		}
		return fmt.Sprintf("Your subscription:\n<code>%s/sub/%s</code>", s.base, user.SubToken)
	}

	if !admin {
		return "I don't know that one. /help lists what you can do."
	}
	return s.adminCommand(ctx, cmd, args)
}

const notLinked = "Your Telegram account is not linked to a subscription yet. Open the link from your subscription page to connect it."

// help lists the commands that apply to whoever asked.
func (s *Service) help(chat int64, admin, linked bool) string {
	var b strings.Builder
	b.WriteString("<b>Frostbite</b>\n")
	if linked {
		b.WriteString("/usage - traffic and validity\n/link - your subscription link\n")
	} else {
		b.WriteString("Open the Telegram link on your subscription page to connect your account.\n")
	}
	if admin {
		b.WriteString("\n<b>Admin</b>\n/stats - users and servers at a glance\n/nodes - daemon status\n/online - who is connected\n/user NAME\n/extend NAME DAYS\n/reset NAME - reset traffic\n/enable NAME, /disable NAME\n")
	}
	fmt.Fprintf(&b, "\nYour chat id: <code>%d</code>", chat)
	return b.String()
}

// linkAccount ties a chat to the user the subscription token belongs to.
func (s *Service) linkAccount(ctx context.Context, chat int64, token string) string {
	u, err := s.q.GetUserBySubToken(ctx, token)
	if err != nil {
		return "That link does not match a subscription."
	}
	if u.TelegramID != nil && *u.TelegramID != chat {
		return "That subscription is already linked to another Telegram account."
	}
	if err := s.q.SetUserTelegram(ctx, db.SetUserTelegramParams{ID: u.ID, TelegramID: &chat}); err != nil {
		return "Something went wrong, try again later."
	}
	u.TelegramID = &chat
	return "Linked! You will get a message before your subscription ends or your traffic runs out.\n\n" + usageText(u)
}

// usageText shows a user where they stand.
func usageText(u db.User) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b> · %s\n", esc(u.Username), u.Status)
	if u.TrafficLimit > 0 {
		fmt.Fprintf(&b, "Traffic: %s of %s\n", bytesText(u.TrafficUsed), bytesText(u.TrafficLimit))
	} else {
		fmt.Fprintf(&b, "Traffic: %s used, no limit\n", bytesText(u.TrafficUsed))
	}
	if u.ExpireAt != nil {
		days := int(math.Ceil(time.Until(*u.ExpireAt).Hours() / 24))
		fmt.Fprintf(&b, "Valid until %s (%d days)", u.ExpireAt.Format("2 Jan 2006"), max(days, 0))
	} else if u.Status == "on_hold" {
		b.WriteString("Starts counting at your first connection")
	} else {
		b.WriteString("No end date")
	}
	return b.String()
}

// adminCommand runs the commands only administrators may use.
func (s *Service) adminCommand(ctx context.Context, cmd string, args []string) string {
	switch cmd {
	case "/stats":
		counts, err := s.q.CountUsersByStatus(ctx)
		if err != nil {
			return "Could not read the stats."
		}
		var b strings.Builder
		for _, c := range counts {
			fmt.Fprintf(&b, "%s: %d\n", c.Status, c.Count)
		}
		online, _ := s.q.CountOnlineUsers(ctx)
		fmt.Fprintf(&b, "online (3 min): %d", online)
		return b.String()
	case "/nodes":
		daemons, _ := s.q.ListDaemons(ctx)
		nodes, _ := s.q.ListNodes(ctx)
		names := map[int64]string{}
		for _, n := range nodes {
			names[n.ID] = n.Name
		}
		var b strings.Builder
		for _, d := range daemons {
			mark := "🔴"
			if s.online(d.ID) {
				mark = "🟢"
			}
			fmt.Fprintf(&b, "%s %s · %s (%s)\n", mark, esc(names[d.NodeID]), esc(d.Name), d.Kind)
		}
		if b.Len() == 0 {
			return "No daemons."
		}
		return b.String()
	case "/online":
		n, _ := s.q.CountOnlineUsers(ctx)
		return fmt.Sprintf("%d users were active in the last 3 minutes.", n)
	}

	if len(args) == 0 {
		return "Which user? For example: " + cmd + " alice"
	}
	u, err := s.q.GetUserByUsername(ctx, args[0])
	if err == pgx.ErrNoRows {
		return "No user called " + esc(args[0]) + "."
	}
	if err != nil {
		return "Something went wrong."
	}
	ids := []int64{u.ID}

	switch cmd {
	case "/user":
		return usageText(u)
	case "/extend":
		days := 30
		if len(args) > 1 {
			if n, err := strconv.Atoi(args[1]); err == nil {
				days = n
			}
		}
		if err := s.q.ExtendUsers(ctx, db.ExtendUsersParams{Ids: ids, Days: int32(days)}); err != nil {
			return "Could not extend."
		}
		_ = s.q.RefreshUsersStatus(ctx, ids)
	case "/reset":
		if err := s.q.ResetUsersTraffic(ctx, ids); err != nil {
			return "Could not reset."
		}
	case "/enable":
		_, _ = s.q.SetUsersStatus(ctx, db.SetUsersStatusParams{Ids: ids, Status: "active"})
		_ = s.q.RefreshUsersStatus(ctx, ids)
	case "/disable":
		_, _ = s.q.SetUsersStatus(ctx, db.SetUsersStatusParams{Ids: ids, Status: "disabled"})
	default:
		return "I don't know that command. /help lists them."
	}
	if s.dirty != nil {
		s.dirty()
	}
	u, _ = s.q.GetUser(ctx, u.ID)
	return "Done.\n" + usageText(u)
}

// bytesText formats a size for chat.
func bytesText(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
