package common

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved panel configuration.
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Auth     AuthConfig     `json:"auth"`
	Link     LinkConfig     `json:"link"`
	Quota    QuotaConfig    `json:"quota"`
	Metrics  MetricsConfig  `json:"metrics"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	BindAddr  string `json:"bind_addr"  env:"FROSTBITE_SERVER_BIND_ADDR"`
	Port      int    `json:"port"       env:"FROSTBITE_SERVER_PORT" min:"1" max:"65535"`
	PublicURL string `json:"public_url" env:"FROSTBITE_SERVER_PUBLIC_URL"`
	Debug     bool   `json:"debug"      env:"FROSTBITE_SERVER_DEBUG"`
	Trace     bool   `json:"trace"      env:"FROSTBITE_SERVER_TRACE"`
}

// DatabaseConfig points at the Postgres instance.
type DatabaseConfig struct {
	URL string `json:"url" env:"FROSTBITE_DATABASE_URL"`
}

// AuthConfig controls sessions and the first admin account.
type AuthConfig struct {
	SessionTTL    time.Duration `json:"session_ttl"     env:"FROSTBITE_AUTH_SESSION_TTL" min:"1m"`
	CookieName    string        `json:"cookie_name"     env:"FROSTBITE_AUTH_COOKIE_NAME"`
	CookieSecure  bool          `json:"cookie_secure"   env:"FROSTBITE_AUTH_COOKIE_SECURE"`
	BootstrapUser string        `json:"bootstrap_user"  env:"FROSTBITE_AUTH_BOOTSTRAP_USER"`
	BootstrapPass string        `json:"bootstrap_pass"  env:"FROSTBITE_AUTH_BOOTSTRAP_PASS"`
}

// LinkConfig controls the daemon websocket link.
type LinkConfig struct {
	PingInterval time.Duration `json:"ping_interval" env:"FROSTBITE_LINK_PING_INTERVAL" min:"1s"`
	StaleAfter   time.Duration `json:"stale_after"   env:"FROSTBITE_LINK_STALE_AFTER" min:"5s"`
	PushDebounce time.Duration `json:"push_debounce" env:"FROSTBITE_LINK_PUSH_DEBOUNCE" min:"10ms"`
}

// QuotaConfig controls the background limit enforcement loop.
type QuotaConfig struct {
	Interval time.Duration `json:"interval" env:"FROSTBITE_QUOTA_INTERVAL" min:"1s"`
}

// MetricsConfig controls the Prometheus endpoint, which has its own listener so it never shares the public port.
type MetricsConfig struct {
	Enabled bool   `json:"enabled"  env:"FROSTBITE_METRICS_ENABLED"`
	Addr    string `json:"addr"     env:"FROSTBITE_METRICS_ADDR"`
	Token   string `json:"token"    env:"FROSTBITE_METRICS_TOKEN"`
	// PerUser adds a handful of series for every user, labelled with the username.
	PerUser bool `json:"per_user" env:"FROSTBITE_METRICS_PER_USER"`
}

// DataDir is where the data volume is mounted.
const DataDir = "./data"

// DataDir returns where the panel keeps files such as backups.
func (Config) DataDir() string { return DataDir }

// defaults returns the hard-coded fallback configuration.
func defaults() Config {
	return Config{
		Server: ServerConfig{
			BindAddr: "0.0.0.0",
			Port:     8080,
		},
		Database: DatabaseConfig{
			URL: "postgres://frostbite:frostbite@127.0.0.1:5432/frostbite?sslmode=disable",
		},
		Auth: AuthConfig{
			SessionTTL:    30 * 24 * time.Hour,
			CookieName:    "frostbite_session",
			CookieSecure:  false,
			BootstrapUser: "admin",
			BootstrapPass: "",
		},
		Link: LinkConfig{
			PingInterval: 20 * time.Second,
			StaleAfter:   60 * time.Second,
			PushDebounce: 300 * time.Millisecond,
		},
		Quota: QuotaConfig{
			Interval: 10 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Addr:    "127.0.0.1:9091",
			PerUser: true,
		},
	}
}

// Load loads Config from config.json or environment variables.
func Load(dataDir string) (Config, error) {
	cfg := defaults()
	fallback := cfg

	configFile := envString("FROSTBITE_CONFIG_FILE", filepath.Join(dataDir, "config.json"))
	if data, err := os.ReadFile(configFile); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("config: parse %s: %w", configFile, err)
		}
	} else if !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("config: read %s: %w", configFile, err)
	}

	applyEnvTags(reflect.ValueOf(&cfg).Elem())
	clampRangeTags(reflect.ValueOf(&cfg).Elem(), reflect.ValueOf(fallback))

	return cfg, nil
}

// durationType is reflection identity for time.Duration.
var durationType = reflect.TypeOf(time.Duration(0))

// applyEnvTags applies configuration from environment variables or files that they point to.
func applyEnvTags(v reflect.Value) {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			applyEnvTags(fv)
			continue
		}

		key := field.Tag.Get("env")
		if key == "" {
			continue
		}

		if raw, ok := lookupEnv(key); ok {
			setFieldFromEnv(fv, key, raw)
		}
	}
}

// setFieldFromEnv parses raw value and assigns it to the appropriate configuration field.
func setFieldFromEnv(fv reflect.Value, key, raw string) {
	switch {
	case fv.Type() == durationType:
		d, err := time.ParseDuration(raw)
		if err != nil {
			slog.Warn("config: invalid duration env value, ignoring", "key", key, "value", raw)
			return
		}
		fv.SetInt(int64(d))
	case fv.Kind() == reflect.String:
		fv.SetString(raw)
	case fv.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			slog.Warn("config: invalid bool env value, ignoring", "key", key, "value", raw)
			return
		}
		fv.SetBool(b)
	case fv.Kind() == reflect.Int || fv.Kind() == reflect.Int32 || fv.Kind() == reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			slog.Warn("config: invalid int env value, ignoring", "key", key, "value", raw)
			return
		}
		fv.SetInt(n)
	default:
		slog.Warn("config: env tag on unsupported field type, ignoring", "key", key, "type", fv.Type())
	}
}

// clampRangeTags walks the configuration and resets any invalid values to their defaults.
func clampRangeTags(v, fallback reflect.Value) {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			clampRangeTags(fv, fallback.Field(i))
			continue
		}

		minTag, hasMin := field.Tag.Lookup("min")
		maxTag, hasMax := field.Tag.Lookup("max")
		if !hasMin && !hasMax {
			continue
		}
		if inRange(fv, minTag, hasMin, maxTag, hasMax) {
			continue
		}

		key := field.Tag.Get("env")
		def := fallback.Field(i)
		slog.Warn("config: value out of range, using default", "key", key, "value", fv.Interface(), "default", def.Interface())
		fv.Set(def)
	}
}

// inRange checks whether the numeric value or duration satisfies the given min/max tag bounds.
func inRange(fv reflect.Value, minTag string, hasMin bool, maxTag string, hasMax bool) bool {
	if fv.Type() == durationType {
		d := time.Duration(fv.Int())
		if hasMin {
			if m, err := time.ParseDuration(minTag); err == nil && d < m {
				return false
			}
		}
		if hasMax {
			if m, err := time.ParseDuration(maxTag); err == nil && d > m {
				return false
			}
		}
		return true
	}

	if fv.Kind() == reflect.Int || fv.Kind() == reflect.Int32 || fv.Kind() == reflect.Int64 {
		n := fv.Int()
		if hasMin {
			if m, err := strconv.ParseInt(minTag, 10, 64); err == nil && n < m {
				return false
			}
		}
		if hasMax {
			if m, err := strconv.ParseInt(maxTag, 10, 64); err == nil && n > m {
				return false
			}
		}
	}
	return true
}

// envString reads key falling back to def.
func envString(key, def string) string {
	if v, ok := lookupEnv(key); ok {
		return v
	}
	return def
}

// lookupEnv reads an environment value directly, or the contents of the file it points to.
func lookupEnv(key string) (string, bool) {
	if v, ok := os.LookupEnv(key); ok {
		return v, true
	}

	if path, ok := os.LookupEnv(key + "_FILE"); ok {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimRight(string(data), "\r\n"), true
		}
	}

	return "", false
}
