package metrics

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type routeKey struct{}

// routeHolder lets a handler deep inside the router tell the outer middleware which pattern matched.
type routeHolder struct{ route string }

// SetRoute names the matched route pattern for the request in flight, so labels stay bounded.
func SetRoute(r *http.Request, route string) {
	if h, ok := r.Context().Value(routeKey{}).(*routeHolder); ok {
		h.route = route
	}
}

// PatternRoute drops the method from a ServeMux pattern, since the method is a label of its own.
func PatternRoute(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return path
	}
	return pattern
}

// Route wraps a handler so the request is recorded under pattern.
func Route(pattern string, next http.Handler) http.Handler {
	pattern = PatternRoute(pattern)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r, pattern)
		next.ServeHTTP(w, r)
	})
}

// recorder remembers what a handler wrote.
type recorder struct {
	http.ResponseWriter
	code     int
	bytes    int64
	hijacked bool
}

func (w *recorder) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *recorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := hj.Hijack()
	if err == nil {
		w.hijacked = true
		w.code = http.StatusSwitchingProtocols
	}
	return c, rw, err
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// HTTP records every request that passes through next.
func HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		holder := &routeHolder{}
		r = r.WithContext(context.WithValue(r.Context(), routeKey{}, holder))
		rec := &recorder{ResponseWriter: w}
		HTTPInflight.Inc()
		start := time.Now()
		panicked := true
		defer func() {
			HTTPInflight.Dec()
			route := holder.route
			if route == "" {
				route = PatternRoute(r.Pattern)
			}
			if route == "" {
				route = "unmatched"
			}
			if panicked {
				HTTPPanics.WithLabelValues(route).Inc()
				rec.code = http.StatusInternalServerError
			}
			if rec.code == 0 {
				rec.code = http.StatusOK
			}
			HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.code)).Inc()
			if !rec.hijacked {
				HTTPSeconds.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
			}
			HTTPRespBytes.WithLabelValues(route).Add(float64(rec.bytes))
			if r.ContentLength > 0 {
				HTTPReqBytes.WithLabelValues(route).Add(float64(r.ContentLength))
			}
		}()
		next.ServeHTTP(rec, r)
		panicked = false
	})
}
