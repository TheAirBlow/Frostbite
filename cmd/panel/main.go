package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"

	"frostbite/internal/api"
	"frostbite/internal/backup"
	"frostbite/internal/common"
	"frostbite/internal/compose"
	_ "frostbite/internal/core/all"
	"frostbite/internal/db"
	"frostbite/internal/frontend"
	"frostbite/internal/hub"
	"frostbite/internal/keys"
	"frostbite/internal/metrics"
	"frostbite/internal/notify"
	"frostbite/internal/quota"
)

// shutdownTimeout bounds how long graceful shutdown waits for in-flight requests.
const shutdownTimeout = 15 * time.Second

// main runs the panel and logs a fatal error on failure.
func main() {
	if err := run(); err != nil {
		common.Fatal("frostbite exited", "err", err)
	}
}

// run initializes everything, serves HTTP until a shutdown signal arrives, then drains cleanly.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := common.Load(common.DataDir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	common.Init(cfg.Server.Debug, cfg.Server.Trace)
	slog.Info("starting Frostbite panel")

	sqlDB, err := sql.Open("pgx", cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("db: open: %w", err)
	}
	defer sqlDB.Close()
	if err := db.Migrate(sqlDB); err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("db: config: %w", err)
	}
	poolCfg.ConnConfig.Tracer = metrics.Tracer{}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("db: pool: %w", err)
	}
	defer pool.Close()
	queries := db.New(pool)

	if err := bootstrap(ctx, queries, cfg.Auth); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	h := hub.New(queries, cfg.Link)
	go h.Run(ctx)

	notifier := notify.New(queries, func(id int64) bool { return h.Status(id).Online }, h.MarkDirty)
	notifier.SetBaseURL(cfg.Server.PublicURL)
	h.OnBlock = func(userID int64, ips int) {
		if u, err := queries.GetUser(ctx, userID); err == nil {
			notifier.Emit(notify.Event{Kind: notify.UserBlocked, User: notify.UserOf(u), Data: map[string]any{"ips": ips}})
		}
	}
	go notifier.Run(ctx)
	go notifier.RunBot(ctx)
	go quota.Run(ctx, queries, quota.Hooks{
		Dirty:   h.MarkDirty,
		Expired: func(ids []int64) { notifier.StateChanged(ctx, notify.UserExpired, ids) },
		Limited: func(ids []int64) { notifier.StateChanged(ctx, notify.UserLimited, ids) },
	}, cfg.Quota.Interval)

	server := &api.Server{Queries: queries, Config: cfg, Hub: h, Pool: pool, Notify: notifier}
	go backup.Run(ctx, pool, common.DataDir, server.LoadSchedule)

	if cfg.Metrics.Enabled {
		metrics.NewCollector(metrics.Options{
			Pool: pool, Live: h, DataDir: common.DataDir, PerUser: cfg.Metrics.PerUser, NotifyQueue: notifier.QueueLen,
		})
		go serveMetrics(ctx, cfg.Metrics)
	}

	mux := http.NewServeMux()
	server.Register(mux)
	if frontend.Available() {
		mux.Handle("/", frontend.Handler())
	} else {
		slog.Info("this build serves the api only, the web interface is a separate service")
	}

	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.BindAddr, strconv.Itoa(cfg.Server.Port)),
		Handler:           metrics.HTTP(recoverer(mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("web server is now running", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			common.Fatal("server error", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// bootstrap creates the first owner and the panel secret when they are missing.
func bootstrap(ctx context.Context, q *db.Queries, cfg common.AuthConfig) error {
	if _, err := q.GetSetting(ctx, compose.SecretKey); errors.Is(err, pgx.ErrNoRows) {
		secret, err := keys.Token(32)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(secret)
		if err := q.SetSetting(ctx, db.SetSettingParams{Key: compose.SecretKey, Value: raw}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	n, err := q.CountAdmins(ctx)
	if err != nil || n > 0 {
		return err
	}

	pass := cfg.BootstrapPass
	generated := pass == ""
	if generated {
		b := make([]byte, 9)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		pass = fmt.Sprintf("%x", b)
	}
	hash, err := api.HashPassword(pass)
	if err != nil {
		return err
	}
	if _, err := q.CreateAdmin(ctx, db.CreateAdminParams{Username: cfg.BootstrapUser, PasswordHash: hash, Role: api.RoleOwner}); err != nil {
		return err
	}
	if generated {
		slog.Warn("created the first owner account, change this password after signing in", "username", cfg.BootstrapUser, "password", pass)
	} else {
		slog.Info("created the first owner account", "username", cfg.BootstrapUser)
	}
	return nil
}

// recoverer turns a panicking handler into a 500 instead of a dead connection.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil && v != http.ErrAbortHandler {
				metrics.HTTPPanics.WithLabelValues(metrics.PatternRoute(r.Pattern)).Inc()
				slog.Error("http: handler panicked", "path", r.URL.Path, "panic", v)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// serveMetrics exposes Prometheus metrics on a listener of their own, so they never share the public port.
func serveMetrics(ctx context.Context, cfg common.MetricsConfig) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler(cfg.Token))
	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	slog.Info("metrics are being served", "addr", cfg.Addr, "token", cfg.Token != "")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("metrics listener failed", "err", err)
	}
}
