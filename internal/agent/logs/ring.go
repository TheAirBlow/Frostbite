// Package logs keeps the tail of a process's output for the panel to read.
package logs

import (
	"strings"
	"sync"
)

// Ring holds the last lines written to it.
type Ring struct {
	mu    sync.Mutex
	lines []string
	max   int
	part  string
}

// NewRing creates a ring holding up to max lines.
func NewRing(max int) *Ring { return &Ring{max: max} }

// Write splits output into lines.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data := r.part + string(p)
	parts := strings.Split(data, "\n")
	r.part = parts[len(parts)-1]
	r.lines = append(r.lines, parts[:len(parts)-1]...)
	if over := len(r.lines) - r.max; over > 0 {
		r.lines = r.lines[over:]
	}
	return len(p), nil
}

// Tail returns the last n lines.
func (r *Ring) Tail(n int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	lines := r.lines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
