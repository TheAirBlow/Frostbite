package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"frostbite/internal/db"
	"frostbite/internal/metrics"
)

// Roles an admin account can have.
const (
	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleReseller = "reseller"
)

// ctxKey is an unexported type to avoid context key collisions across packages.
type ctxKey int

// adminCtxKey is the context key the auth middleware stores the authenticated admin under.
const adminCtxKey ctxKey = iota

// ContextWithAdmin returns a copy of ctx carrying admin.
func ContextWithAdmin(ctx context.Context, admin db.Admin) context.Context {
	return context.WithValue(ctx, adminCtxKey, admin)
}

// AdminFromContext returns the authenticated admin stored on ctx, if any.
func AdminFromContext(ctx context.Context) (db.Admin, bool) {
	admin, ok := ctx.Value(adminCtxKey).(db.Admin)
	return admin, ok
}

// HashPassword bcrypt-hashes a plaintext password for storage.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// VerifyPassword reports whether password matches hash.
func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// randomToken returns n random bytes, url-safe encoded.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken hashes a token for storage and lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// apiTokenPrefix marks panel API tokens so they are easy to spot in logs and configs.
const apiTokenPrefix = "fbt_"

// usernamePattern is what an admin username may look like.
var usernamePattern = regexp.MustCompile(`^[a-z0-9_.-]{2,32}$`)

// errUnauthenticated is the auth-layer failure authenticate reports as a 401.
var errUnauthenticated = errors.New("not signed in")

// authenticate resolves a request's session cookie or bearer token into an admin.
func (s *Server) authenticate(r *http.Request) (db.Admin, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer "+apiTokenPrefix) {
		hash := HashToken(strings.TrimPrefix(h, "Bearer "))
		admin, err := s.Queries.GetAPITokenAdmin(r.Context(), hash)
		if errors.Is(err, pgx.ErrNoRows) {
			metrics.AuthRejected.WithLabelValues("api_token").Inc()
			return db.Admin{}, errUnauthenticated
		}
		if err != nil {
			return db.Admin{}, err
		}
		if err := s.Queries.TouchAPIToken(r.Context(), hash); err != nil {
			slog.Warn("api: touching token failed", "err", err)
		}
		metrics.AuthTokenUsed.Inc()
		return admin, nil
	}

	cookie, err := r.Cookie(s.Config.Auth.CookieName)
	if err != nil {
		metrics.AuthRejected.WithLabelValues("none").Inc()
		return db.Admin{}, errUnauthenticated
	}
	admin, err := s.Queries.GetSessionAdmin(r.Context(), HashToken(cookie.Value))
	if errors.Is(err, pgx.ErrNoRows) {
		metrics.AuthRejected.WithLabelValues("session").Inc()
		return db.Admin{}, errUnauthenticated
	}
	return admin, err
}

// authMux extends http.ServeMux with registration methods that check who is calling.
type authMux struct {
	*http.ServeMux
	server *Server
}

// Handle registers handler on pattern and records its requests under that pattern.
func (m authMux) Handle(pattern string, handler http.Handler) {
	m.ServeMux.Handle(pattern, metrics.Route("/api"+metrics.PatternRoute(pattern), handler))
}

// HandleFunc is Handle for a function.
func (m authMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(handler))
}

// Auth registers handler on pattern for any signed in admin, resellers included.
func (m authMux) Auth(pattern string, handler http.HandlerFunc) {
	m.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admin, err := m.server.authenticate(r)
		if err != nil {
			if errors.Is(err, errUnauthenticated) {
				unauthorized(w, err.Error())
			} else {
				internalError(w, err)
			}
			return
		}
		handler.ServeHTTP(w, r.WithContext(ContextWithAdmin(r.Context(), admin)))
	}))
}

// Admin registers handler on pattern for owners and admins.
func (m authMux) Admin(pattern string, handler http.HandlerFunc) {
	m.Auth(pattern, func(w http.ResponseWriter, r *http.Request) {
		admin, _ := AdminFromContext(r.Context())
		if admin.Role == RoleReseller {
			forbidden(w, "admin access required")
			return
		}
		handler(w, r)
	})
}

// Owner registers handler on pattern for owners only.
func (m authMux) Owner(pattern string, handler http.HandlerFunc) {
	m.Auth(pattern, func(w http.ResponseWriter, r *http.Request) {
		admin, _ := AdminFromContext(r.Context())
		if admin.Role != RoleOwner {
			forbidden(w, "owner access required")
			return
		}
		handler(w, r)
	})
}

// registerAuth registers sign in, sign out and self service endpoints.
func (s *Server) registerAuth(mux authMux) {
	mux.HandleFunc("POST /auth/login", s.login)
	mux.Auth("POST /auth/logout", s.logout)
	mux.Auth("GET /auth/me", s.me)
	mux.Auth("PUT /auth/password", s.changePassword)
	mux.Auth("GET /auth/tokens", s.listTokens)
	mux.Auth("POST /auth/tokens", s.createToken)
	mux.Auth("DELETE /auth/tokens/{id}", s.deleteToken)
}

// adminResponse is the public shape of an admin account.
type adminResponse struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	Enabled      bool      `json:"enabled"`
	UserQuota    *int32    `json:"user_quota"`
	TrafficQuota *int64    `json:"traffic_quota"`
	Note         string    `json:"note"`
	CreatedAt    time.Time `json:"created_at"`
}

// newAdminResponse builds an adminResponse from a db.Admin.
func newAdminResponse(a db.Admin) adminResponse {
	return adminResponse{
		ID: a.ID, Username: a.Username, Role: a.Role, Enabled: a.Enabled,
		UserQuota: a.UserQuota, TrafficQuota: a.TrafficQuota, Note: a.Note, CreatedAt: a.CreatedAt,
	}
}

// loginRequest is the JSON body for signing in.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// dummyHash keeps login timing the same whether or not the account exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("frostbite"), bcrypt.DefaultCost)

// login checks credentials and starts a session.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}

	admin, err := s.Queries.GetAdminByUsername(r.Context(), strings.ToLower(strings.TrimSpace(req.Username)))
	hash := string(dummyHash)
	if err == nil {
		hash = admin.PasswordHash
	} else if !errors.Is(err, pgx.ErrNoRows) {
		metrics.AuthLogins.WithLabelValues("error").Inc()
		internalError(w, err)
		return
	}
	if !VerifyPassword(hash, req.Password) || err != nil || !admin.Enabled {
		switch {
		case err == nil && !admin.Enabled && VerifyPassword(hash, req.Password):
			metrics.AuthLogins.WithLabelValues("disabled").Inc()
		case err != nil:
			metrics.AuthLogins.WithLabelValues("unknown_user").Inc()
		default:
			metrics.AuthLogins.WithLabelValues("wrong_password").Inc()
		}
		unauthorized(w, "wrong username or password")
		return
	}

	token, err := randomToken(32)
	if err != nil {
		internalError(w, err)
		return
	}
	ttl := s.Config.Auth.SessionTTL
	err = s.Queries.CreateSession(r.Context(), db.CreateSessionParams{
		AdminID: admin.ID, TokenHash: HashToken(token), UserAgent: r.UserAgent(), Ip: clientIP(r), ExpiresAt: time.Now().Add(ttl),
	})
	if err != nil {
		internalError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: s.Config.Auth.CookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.Config.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
	})
	metrics.AuthLogins.WithLabelValues("success").Inc()
	slog.Info("auth: signed in", "admin", admin.Username)
	ok(w, newAdminResponse(admin))
}

// logout ends the current session.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.Config.Auth.CookieName); err == nil {
		_ = s.Queries.DeleteSession(r.Context(), HashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: s.Config.Auth.CookieName, Path: "/", MaxAge: -1})
	noContent(w)
}

// me returns the signed in admin.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	ok(w, newAdminResponse(admin))
}

// passwordRequest is the JSON body for changing a password.
type passwordRequest struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// changePassword changes the caller's own password.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	var req passwordRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if !VerifyPassword(admin.PasswordHash, req.Old) {
		failField(w, http.StatusForbidden, "forbidden", "old", "the current password is wrong")
		return
	}
	if len(req.New) < 8 {
		invalid(w, "new", "the new password must be at least 8 characters")
		return
	}
	hash, err := HashPassword(req.New)
	if err != nil {
		internalError(w, err)
		return
	}
	if err := s.Queries.UpdateAdminPassword(r.Context(), db.UpdateAdminPasswordParams{ID: admin.ID, PasswordHash: hash}); err != nil {
		internalError(w, err)
		return
	}
	s.audit(r, "admin.password", admin.Username, nil)
	noContent(w)
}

// tokenResponse is an API token without its secret.
type tokenResponse struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
	Token      string     `json:"token,omitempty"` // only set right after creation
}

// listTokens lists the caller's API tokens.
func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	rows, err := s.Queries.ListAPITokens(r.Context(), admin.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]tokenResponse, len(rows))
	for i, t := range rows {
		out[i] = tokenResponse{ID: t.ID, Name: t.Name, LastUsedAt: t.LastUsedAt, CreatedAt: t.CreatedAt}
	}
	ok(w, out)
}

// createToken mints an API token, shown once.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		invalid(w, "name", "name is required")
		return
	}
	raw, err := randomToken(32)
	if err != nil {
		internalError(w, err)
		return
	}
	token := apiTokenPrefix + raw
	row, err := s.Queries.CreateAPIToken(r.Context(), db.CreateAPITokenParams{AdminID: admin.ID, Name: strings.TrimSpace(req.Name), TokenHash: HashToken(token)})
	if err != nil {
		internalError(w, err)
		return
	}
	s.audit(r, "token.create", req.Name, nil)
	created(w, tokenResponse{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt, Token: token})
}

// deleteToken revokes one of the caller's tokens.
func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteAPIToken(r.Context(), db.DeleteAPITokenParams{ID: id, AdminID: admin.ID})
	if err != nil {
		internalError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	noContent(w)
}

// clientIP guesses the caller's address, trusting the proxy header the frontend sets.
func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		first, _, _ := strings.Cut(f, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// audit records an admin action.
func (s *Server) audit(r *http.Request, action, target string, detail any) {
	admin, _ := AdminFromContext(r.Context())
	metrics.AuditEvents.WithLabelValues(action).Inc()
	raw := []byte("{}")
	if detail != nil {
		if b, err := jsonMarshal(detail); err == nil {
			raw = b
		}
	}
	err := s.Queries.InsertAudit(r.Context(), db.InsertAuditParams{AdminID: &admin.ID, AdminName: admin.Username, Action: action, Target: target, Detail: raw})
	if err != nil {
		slog.Warn("api: audit write failed", "err", err)
	}
}
