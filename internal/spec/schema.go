package spec

import (
	"reflect"
	"strings"
)

// Field describes one editable setting for the frontend form builder.
type Field struct {
	Path     string              `json:"path"`
	Label    string              `json:"label"`
	Type     string              `json:"type"` // string, number, bool, list, map
	Hint     string              `json:"hint,omitempty"`
	Options  []string            `json:"options,omitempty"`
	Show     map[string][]string `json:"show,omitempty"`
	Advanced bool                `json:"advanced,omitempty"`
}

// uiKeys are the keys a ui tag may contain.
var uiKeys = []string{"label", "hint", "options", "show", "advanced"}

// Schema returns the form fields for every editable section of an inbound.
func Schema() map[string][]Field {
	return map[string][]Field{
		"transport": fieldsOf(reflect.TypeOf(Transport{}), ""),
		"security":  fieldsOf(reflect.TypeOf(Security{}), ""),
		"options":   fieldsOf(reflect.TypeOf(Options{}), ""),
		"sniffing":  fieldsOf(reflect.TypeOf(Sniffing{}), ""),
		"forward":   fieldsOf(reflect.TypeOf(Forward{}), ""),
		"dns":       fieldsOf(reflect.TypeOf(DNS{}), ""),
	}
}

// fieldsOf walks t and collects every field carrying a ui tag, descending into nested structs.
func fieldsOf(t reflect.Type, prefix string) []Field {
	var out []Field
	for i := range t.NumField() {
		sf := t.Field(i)
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}

		ft := sf.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			out = append(out, fieldsOf(ft, prefix+name+".")...)
			continue
		}

		raw := sf.Tag.Get("ui")
		if raw == "" {
			continue
		}
		f := Field{Path: prefix + name, Type: kindName(ft)}
		for key, val := range parseUI(raw) {
			switch key {
			case "label":
				f.Label = val
			case "hint":
				f.Hint = val
			case "options":
				f.Options = strings.Split(val, "|")
			case "show":
				f.Show = parseShow(val)
			case "advanced":
				f.Advanced = true
			}
		}
		out = append(out, f)
	}
	return out
}

// kindName maps a Go type to the small set of widgets the frontend knows.
func kindName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Float64:
		return "number"
	case reflect.Slice:
		return "list"
	case reflect.Map:
		return "map"
	}
	return "string"
}

// parseUI splits a ui tag on commas, but only where the next segment starts a known key.
// Values may therefore contain commas themselves.
func parseUI(raw string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(raw, ",")
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		key, val, _ := strings.Cut(strings.Join(cur, ","), "=")
		out[key] = val
		cur = nil
	}
	for _, p := range parts {
		if isUIKey(p) {
			flush()
		}
		cur = append(cur, p)
	}
	flush()
	return out
}

// isUIKey reports whether p begins a new key in a ui tag.
func isUIKey(p string) bool {
	for _, k := range uiKeys {
		if p == k || strings.HasPrefix(p, k+"=") {
			return true
		}
	}
	return false
}

// parseShow turns "type:ws|grpc" into a map of field -> accepted values.
func parseShow(v string) map[string][]string {
	field, vals, ok := strings.Cut(v, ":")
	if !ok {
		return nil
	}
	return map[string][]string{field: strings.Split(vals, "|")}
}
