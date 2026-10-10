package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"frostbite/internal/db"
)

// ok sends an HTTP 200 response with value JSON-encoded.
func ok(w http.ResponseWriter, value any) {
	write(w, http.StatusOK, value)
}

// created sends an HTTP 201 response with value JSON-encoded.
func created(w http.ResponseWriter, value any) {
	write(w, http.StatusCreated, value)
}

// noContent sends an empty HTTP 204 response.
func noContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// badRequest sends an HTTP 400 error response.
func badRequest(w http.ResponseWriter, detail string) {
	fail(w, http.StatusBadRequest, "bad request", detail)
}

// unauthorized sends an HTTP 401 error response.
func unauthorized(w http.ResponseWriter, detail string) {
	fail(w, http.StatusUnauthorized, "unauthorized", detail)
}

// forbidden sends an HTTP 403 error response.
func forbidden(w http.ResponseWriter, detail string) {
	fail(w, http.StatusForbidden, "forbidden", detail)
}

// notFound sends a JSON HTTP 404 error response.
func notFound(w http.ResponseWriter, detail string) {
	fail(w, http.StatusNotFound, "not found", detail)
}

// conflict sends an HTTP 409 error response.
func conflict(w http.ResponseWriter, detail string) {
	fail(w, http.StatusConflict, "conflict", detail)
}

// internalError logs err server-side and sends a generic HTTP 500 response, keeping driver/SQL detail off the wire.
func internalError(w http.ResponseWriter, err error) {
	slog.Error("api: internal error", "err", err)
	fail(w, http.StatusInternalServerError, "internal error", "an internal error occurred")
}

// fail sends a JSON error response with the given status, title, and detail.
func fail(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"title": title, "detail": detail})
}

// write sends value JSON-encoded with the given status.
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// decode JSON-decodes the request body into v.
func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 4<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

// pathID parses the {id} path value.
func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// dbError maps the database errors a handler can reasonably explain, and falls back to a 500.
func dbError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		notFound(w, "not found")
		return
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			conflict(w, "something with the same name already exists")
			return
		case "23503":
			conflict(w, "it is still referenced by something else, or points at something that does not exist")
			return
		case "23514":
			badRequest(w, "a value is outside of what is allowed")
			return
		}
	}
	internalError(w, err)
}

// orEmpty swaps a nil slice for an empty one so it encodes as [] instead of null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

// jsonMarshal is json.Marshal, kept here so handlers need one fewer import.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// paging reads limit and offset query params, clamped to sane bounds.
func paging(r *http.Request, def, maxLimit int32) (limit, offset int32) {
	limit = def
	if n, err := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 32); err == nil && n > 0 {
		limit = int32(min(n, int64(maxLimit)))
	}
	if n, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 32); err == nil && n > 0 {
		offset = int32(n)
	}
	return limit, offset
}

// dbSetSetting builds params for storing a setting.
func dbSetSetting(key string, raw []byte) db.SetSettingParams {
	return db.SetSettingParams{Key: key, Value: raw}
}

// dbListAudit builds params for a single audit page.
func dbListAudit(limit int32) db.ListAuditParams { return db.ListAuditParams{Limit: limit} }

// slogErr logs a non-fatal error from a handler that has already started writing.
func slogErr(msg string, err error) { slog.Warn(msg, "err", err) }
