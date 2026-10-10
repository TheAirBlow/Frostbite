package metrics

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Tracer times every query a pgx connection runs. sqlc starts each statement with "-- name: Foo :one", which names it.
type Tracer struct{}

type traceKey struct{}

type traceState struct {
	name  string
	start time.Time
}

// TraceQueryStart implements pgx.QueryTracer.
func (Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, traceKey{}, traceState{name: queryName(data.SQL), start: time.Now()})
}

// TraceQueryEnd implements pgx.QueryTracer.
func (Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	st, ok := ctx.Value(traceKey{}).(traceState)
	if !ok {
		return
	}
	result := "ok"
	switch {
	case errors.Is(data.Err, pgx.ErrNoRows):
		result = "no_rows"
	case data.Err != nil:
		result = "error"
	}
	DBQueries.WithLabelValues(st.name, result).Inc()
	DBSeconds.WithLabelValues(st.name).Observe(time.Since(st.start).Seconds())
}

// queryName pulls "Foo" out of a sqlc header, and calls everything else "other".
func queryName(sql string) string {
	rest, ok := strings.CutPrefix(sql, "-- name: ")
	if !ok {
		return "other"
	}
	name, _, _ := strings.Cut(rest, " ")
	if name == "" || len(name) > 64 {
		return "other"
	}
	return name
}
