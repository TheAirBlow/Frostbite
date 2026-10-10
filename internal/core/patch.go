package core

import (
	"encoding/json"
	"fmt"
)

// ApplyPatch merges a raw JSON patch into base following RFC 7386: objects merge, null deletes, everything else replaces.
func ApplyPatch(base map[string]any, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var patch map[string]any
	if err := json.Unmarshal(raw, &patch); err != nil {
		return fmt.Errorf("raw patch is not a json object: %w", err)
	}
	merge(base, patch)
	return nil
}

// merge applies patch onto dst in place.
func merge(dst, patch map[string]any) {
	for k, v := range patch {
		if v == nil {
			delete(dst, k)
			continue
		}
		pm, pok := v.(map[string]any)
		dm, dok := dst[k].(map[string]any)
		if pok && dok {
			merge(dm, pm)
			continue
		}
		dst[k] = v
	}
}

// Ordered puts the final outbound first, which is how xray picks its default.
func Ordered[T any](items []T, tagOf func(T) string, final string) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		if tagOf(it) == final {
			out = append(out, it)
		}
	}
	for _, it := range items {
		if tagOf(it) != final {
			out = append(out, it)
		}
	}
	return out
}

// Prune drops empty strings, empty slices and empty maps from a generated config so the output stays readable.
func Prune(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			x = Prune(x)
			if isEmpty(x) {
				delete(t, k)
				continue
			}
			t[k] = x
		}
		return t
	case []any:
		for i := range t {
			t[i] = Prune(t[i])
		}
		return t
	}
	return v
}

// isEmpty reports whether v carries no information.
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []string:
		return len(t) == 0
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}
