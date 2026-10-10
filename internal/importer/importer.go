// Package importer reads user lists exported from other panels or spreadsheets.
package importer

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Row is one user as the importer understood it.
type Row struct {
	Line       int        `json:"line"`
	Username   string     `json:"username"`
	UUID       string     `json:"uuid,omitempty"`
	Password   string     `json:"password,omitempty"`
	Limit      int64      `json:"traffic_limit"`
	Used       int64      `json:"traffic_used"`
	ExpireAt   *time.Time `json:"expire_at"`
	Note       string     `json:"note"`
	Tags       []string   `json:"tags"`
	TelegramID *int64     `json:"telegram_id"`
	Disabled   bool       `json:"disabled"`
	Reset      string     `json:"reset_strategy,omitempty"`
	OnHoldDays int        `json:"on_hold_days,omitempty"` // the clock starts at the first connection
	IPLimit    int        `json:"ip_limit,omitempty"`
}

// aliases maps the many names panels give the same thing onto one key.
var aliases = map[string][]string{
	"username": {"username", "name", "email", "remark", "user"},
	"uuid":     {"uuid", "id", "uuid_v4", "clientid"},
	"password": {"password", "pass", "trojanpassword"},
	"note":     {"note", "comment", "description", "notes"},
	"tags":     {"tags", "labels", "groups"},
	"telegram": {"telegram_id", "telegramid", "tgid", "tg_id", "telegram"},
	"enable":   {"enable", "enabled", "active"},
	"reset":    {"reset_strategy", "data_limit_reset_strategy", "mode", "reset"},

	// sizes in bytes
	"limit_bytes": {"traffic_limit", "trafficlimitbytes", "data_limit", "totalgb", "total", "limit", "limit_bytes"},
	"used_bytes":  {"traffic_used", "usedtrafficbytes", "used_traffic", "used", "used_bytes"},
	// sizes in gigabytes
	"limit_gb": {"usage_limit_gb", "traffic_gb", "limit_gb", "quota_gb", "gb"},
	"used_gb":  {"current_usage_gb", "used_gb"},

	// moments
	"expire":  {"expire_at", "expireat", "expire", "expiry", "expirytime", "expiration", "expires", "valid_until"},
	"days":    {"package_days", "days", "duration_days"},
	"started": {"start_date", "started_at"},
}

// Parse reads json or csv, deciding by the first character.
func Parse(data []byte) ([]Row, []string, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("there is nothing to import")
	}
	var records []map[string]any
	var err error
	if data[0] == '[' || data[0] == '{' {
		records, err = parseJSON(data)
	} else {
		records, err = parseCSV(data)
	}
	if err != nil {
		return nil, nil, err
	}

	var rows []Row
	var problems []string
	for i, rec := range records {
		row, err := convert(rec)
		row.Line = i + 1
		if err != nil {
			problems = append(problems, fmt.Sprintf("row %d: %v", i+1, err))
			continue
		}
		rows = append(rows, row)
	}
	return rows, problems, nil
}

// parseJSON accepts an array of users, or an object wrapping one under users, clients or data.
func parseJSON(data []byte) ([]map[string]any, error) {
	var list []map[string]any
	if data[0] == '[' {
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("the json is not a list of users: %w", err)
		}
		return list, nil
	}
	var wrap map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrap); err != nil {
		return nil, fmt.Errorf("the json could not be read: %w", err)
	}
	for _, key := range []string{"users", "clients", "data", "items"} {
		if raw, ok := wrap[key]; ok {
			return parseJSON(bytes.TrimSpace(raw))
		}
	}
	return []map[string]any{toAny(wrap)}, nil
}

// toAny converts raw json values to plain ones.
func toAny(m map[string]json.RawMessage) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		var x any
		_ = json.Unmarshal(v, &x)
		out[k] = x
	}
	return out
}

// parseCSV reads a header row followed by users.
func parseCSV(data []byte) ([]map[string]any, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	if first, _, _ := strings.Cut(string(data), "\n"); strings.Count(first, ";") > strings.Count(first, ",") {
		r.Comma = ';'
	}
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("the csv has no header: %w", err)
	}
	var out []map[string]any
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("the csv could not be read: %w", err)
		}
		m := map[string]any{}
		for i, h := range header {
			if i < len(rec) && strings.TrimSpace(rec[i]) != "" {
				m[strings.TrimSpace(h)] = strings.TrimSpace(rec[i])
			}
		}
		out = append(out, m)
	}
}

// lookup finds the first present value among a field's aliases, ignoring case and punctuation.
func lookup(rec map[string]any, field string) (any, bool) {
	norm := make(map[string]any, len(rec))
	for k, v := range rec {
		norm[strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(k))] = v
	}
	for _, a := range aliases[field] {
		if v, ok := norm[strings.ReplaceAll(a, "_", "")]; ok && v != nil && v != "" {
			return v, true
		}
		if v, ok := norm[a]; ok && v != nil && v != "" {
			return v, true
		}
	}
	return nil, false
}

// Convert maps one loosely named record onto a Row. Other readers use it after shaping their data into a record.
func Convert(rec map[string]any) (Row, error) { return convert(rec) }

// convert maps one record onto a Row.
func convert(rec map[string]any) (Row, error) {
	var row Row
	if v, ok := lookup(rec, "username"); ok {
		row.Username = strings.TrimSpace(fmt.Sprint(v))
	}
	if row.Username == "" {
		return row, fmt.Errorf("no username")
	}
	if v, ok := lookup(rec, "uuid"); ok {
		row.UUID = strings.TrimSpace(fmt.Sprint(v))
	}
	if v, ok := lookup(rec, "password"); ok {
		row.Password = fmt.Sprint(v)
	}
	if v, ok := lookup(rec, "note"); ok {
		row.Note = fmt.Sprint(v)
	}
	if v, ok := lookup(rec, "tags"); ok {
		row.Tags = splitList(v)
	}
	if v, ok := lookup(rec, "telegram"); ok {
		if n, ok := number(v); ok && n > 0 {
			id := int64(n)
			row.TelegramID = &id
		}
	}
	if v, ok := lookup(rec, "enable"); ok {
		row.Disabled = !truthy(v)
	}
	if v, ok := lookup(rec, "reset"); ok {
		row.Reset = resetOf(fmt.Sprint(v))
	}

	if v, ok := lookup(rec, "limit_gb"); ok {
		if n, ok := number(v); ok {
			row.Limit = int64(n * (1 << 30))
		}
	} else if v, ok := lookup(rec, "limit_bytes"); ok {
		if n, ok := number(v); ok {
			row.Limit = int64(n)
		}
	}
	if v, ok := lookup(rec, "used_gb"); ok {
		if n, ok := number(v); ok {
			row.Used = int64(n * (1 << 30))
		}
	} else if v, ok := lookup(rec, "used_bytes"); ok {
		if n, ok := number(v); ok {
			row.Used = int64(n)
		}
	} else {
		// 3x-ui keeps up and down apart
		up, _ := number(rec["up"])
		down, _ := number(rec["down"])
		row.Used = int64(up + down)
	}

	if v, ok := lookup(rec, "expire"); ok {
		if t, ok := moment(v); ok {
			row.ExpireAt = &t
		}
	} else if v, ok := lookup(rec, "days"); ok {
		if n, ok := number(v); ok && n > 0 {
			start := time.Now()
			if s, ok := lookup(rec, "started"); ok {
				if t, ok := moment(s); ok {
					start = t
				}
			}
			t := start.Add(time.Duration(n) * 24 * time.Hour)
			row.ExpireAt = &t
		}
	}
	if row.Tags == nil {
		row.Tags = []string{}
	}
	return row, nil
}

// number reads numbers that may arrive as strings.
func number(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return n, err == nil && !math.IsNaN(n)
	}
	return 0, false
}

// truthy reads the many spellings of yes.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "false", "0", "no", "off", "disabled", "n":
			return false
		}
	}
	return true
}

// splitList reads a list given as an array or as a delimited string.
func splitList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			out = append(out, strings.TrimSpace(fmt.Sprint(x)))
		}
	case string:
		for _, p := range strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ';' || r == '|' }) {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}

// moment reads unix seconds, unix milliseconds or a date.
func moment(v any) (time.Time, bool) {
	if n, ok := number(v); ok {
		switch {
		case n <= 0:
			return time.Time{}, false
		case n > 1e12:
			return time.UnixMilli(int64(n)), true
		case n > 1e9:
			return time.Unix(int64(n), 0), true
		}
		return time.Time{}, false
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02", "02.01.2006", "02/01/2006"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			if layout == "2006-01-02" || layout == "02.01.2006" || layout == "02/01/2006" {
				t = t.Add(24*time.Hour - time.Second)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// resetOf maps other panels' reset names onto ours.
func resetOf(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "daily", "day":
		return "day"
	case "weekly", "week":
		return "week"
	case "monthly", "month":
		return "month"
	case "yearly", "year", "annually":
		return "year"
	}
	return "none"
}
