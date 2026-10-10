package importer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// maxRows keeps a hostile or huge file from exhausting memory.
const maxRows = 200_000

// Panel names the kinds of database the importer recognises.
const (
	PanelXUI     = "3x-ui"
	PanelMarzban = "marzban"
	PanelHiddify = "hiddify"
)

// FromSQLite reads the users out of another panel's sqlite database and says which panel it recognised.
func FromSQLite(path string) (string, []Row, []string, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return "", nil, nil, err
	}
	defer db.Close()

	tables, err := tableNames(db)
	if err != nil {
		return "", nil, nil, fmt.Errorf("this is not a readable sqlite database: %w", err)
	}

	var panel string
	var records []map[string]any
	switch {
	case tables["inbounds"] && tables["client_traffics"]:
		panel = PanelXUI
		records, err = xuiRecords(db)
	case tables["users"] && tables["proxies"]:
		panel = PanelMarzban
		records, err = marzbanRecords(db)
	case tables["user"]:
		panel = PanelHiddify
		records, err = hiddifyRecords(db)
	default:
		return "", nil, nil, fmt.Errorf("this database does not look like 3x-ui, Marzban or Hiddify (tables: %s)", listTables(tables))
	}
	if err != nil {
		return panel, nil, nil, fmt.Errorf("reading the %s database: %w", panel, err)
	}

	var rows []Row
	var problems []string
	for i, rec := range records {
		row, err := convertFor(rec)
		row.Line = i + 1
		if err != nil {
			problems = append(problems, fmt.Sprintf("row %d: %v", i+1, err))
			continue
		}
		rows = append(rows, row)
	}
	return panel, rows, problems, nil
}

// convertFor maps a record and then applies what only one panel means.
func convertFor(rec map[string]any) (Row, error) {
	row, err := convert(rec)
	if err != nil {
		return row, err
	}
	if v, ok := rec["_on_hold_days"]; ok {
		if n, ok := number(v); ok && n > 0 {
			row.OnHoldDays, row.ExpireAt = int(n), nil
		}
	}
	if v, ok := rec["_ip_limit"]; ok {
		if n, ok := number(v); ok && n > 0 {
			row.IPLimit = int(n)
		}
	}
	if v, ok := rec["_disabled"]; ok {
		row.Disabled = truthy(v)
	}
	return row, nil
}

// tableNames lists the tables in a database.
func tableNames(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[strings.ToLower(n)] = true
	}
	return out, rows.Err()
}

// listTables prints table names for an error message.
func listTables(t map[string]bool) string {
	var names []string
	for n := range t {
		names = append(names, n)
	}
	if len(names) > 12 {
		names = append(names[:12], "…")
	}
	return strings.Join(names, ", ")
}

// scanMaps reads every row of a query into maps keyed by lowercase column name.
func scanMaps(db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		if len(out) >= maxRows {
			return nil, fmt.Errorf("more than %d rows", maxRows)
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				m[strings.ToLower(c)] = string(b)
			} else {
				m[strings.ToLower(c)] = vals[i]
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// xuiRecords turns 3x-ui inbounds into one record per client, joined with their traffic.
func xuiRecords(db *sql.DB) ([]map[string]any, error) {
	traffic := map[string]float64{}
	ts, err := scanMaps(db, `SELECT email, up, down FROM client_traffics`)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		up, _ := number(t["up"])
		down, _ := number(t["down"])
		traffic[fmt.Sprint(t["email"])] += up + down
	}

	inbounds, err := scanMaps(db, `SELECT settings, protocol FROM inbounds`)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	seen := map[string]bool{}
	for _, ib := range inbounds {
		var settings struct {
			Clients []map[string]any `json:"clients"`
		}
		if json.Unmarshal([]byte(fmt.Sprint(ib["settings"])), &settings) != nil {
			continue
		}
		for _, c := range settings.Clients {
			email := strings.TrimSpace(fmt.Sprint(c["email"]))
			if email == "" || email == "<nil>" || seen[email] {
				continue
			}
			seen[email] = true

			rec := map[string]any{"username": email, "used_bytes": traffic[email], "note": c["comment"]}
			if id, ok := c["id"]; ok {
				rec["uuid"] = id
			}
			if pw, ok := c["password"]; ok {
				rec["password"] = pw
			}
			if n, ok := number(c["totalGB"]); ok && n > 0 {
				rec["limit_bytes"] = n
			}
			if n, ok := number(c["expiryTime"]); ok {
				switch {
				case n > 0:
					rec["expire"] = n
				case n < 0:
					// a negative value means "this many milliseconds after the first connection"
					rec["_on_hold_days"] = -n / 86400000
				}
			}
			if v, ok := c["enable"]; ok {
				rec["_disabled"] = !truthy(v)
			}
			if v, ok := c["tgId"]; ok && fmt.Sprint(v) != "" && fmt.Sprint(v) != "0" {
				rec["telegram_id"] = v
			}
			if n, ok := number(c["limitIp"]); ok {
				rec["_ip_limit"] = n
			}
			if n, ok := number(c["reset"]); ok {
				rec["reset_strategy"] = resetFromDays(int(n))
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

// resetFromDays maps 3x-ui's "reset every N days" onto the nearest schedule we have.
func resetFromDays(n int) string {
	switch {
	case n <= 0:
		return "none"
	case n == 1:
		return "day"
	case n <= 7:
		return "week"
	case n <= 31:
		return "month"
	}
	return "year"
}

// marzbanRecords turns Marzban users and their proxy credentials into records.
func marzbanRecords(db *sql.DB) ([]map[string]any, error) {
	creds := map[int64]map[string]any{}
	ps, err := scanMaps(db, `SELECT user_id, type, settings FROM proxies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		uid, ok := number(p["user_id"])
		if !ok {
			continue
		}
		var settings map[string]any
		if json.Unmarshal([]byte(fmt.Sprint(p["settings"])), &settings) != nil {
			continue
		}
		c := creds[int64(uid)]
		if c == nil {
			c = map[string]any{}
			creds[int64(uid)] = c
		}
		// the uuid of vless/vmess is what people's apps hold, so it wins over a trojan or shadowsocks password
		if id, ok := settings["id"]; ok && c["uuid"] == nil {
			c["uuid"] = id
		}
		if pw, ok := settings["password"]; ok && c["password"] == nil && fmt.Sprint(p["type"]) != "shadowsocks" {
			c["password"] = pw
		}
	}

	users, err := scanMaps(db, `SELECT * FROM users`)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, u := range users {
		rec := map[string]any{"username": u["username"], "used_bytes": u["used_traffic"], "note": u["note"]}
		if n, ok := number(u["data_limit"]); ok && n > 0 {
			rec["limit_bytes"] = n
		}
		if n, ok := number(u["expire"]); ok && n > 0 {
			rec["expire"] = n
		}
		if s, ok := u["data_limit_reset_strategy"]; ok {
			rec["reset_strategy"] = strings.TrimPrefix(strings.ToLower(fmt.Sprint(s)), "userdatalimitresetstrategy.")
		}
		switch strings.ToLower(strings.TrimPrefix(fmt.Sprint(u["status"]), "UserStatus.")) {
		case "disabled":
			rec["_disabled"] = true
		case "on_hold":
			if n, ok := number(u["on_hold_expire_duration"]); ok && n > 0 {
				rec["_on_hold_days"] = n / 86400
			}
		}
		if uid, ok := number(u["id"]); ok {
			for k, v := range creds[int64(uid)] {
				rec[k] = v
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

// hiddifyRecords reads Hiddify's user table, whose column names the importer already knows.
func hiddifyRecords(db *sql.DB) ([]map[string]any, error) {
	users, err := scanMaps(db, `SELECT * FROM user`)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		// a package with days but no start date has not been started yet
		start := strings.TrimSpace(fmt.Sprint(u["start_date"]))
		if days, ok := number(u["package_days"]); ok && days > 0 && (start == "" || start == "<nil>") {
			u["_on_hold_days"] = days
			delete(u, "package_days")
		}
		if n, ok := number(u["max_ips"]); ok {
			u["_ip_limit"] = n
		}
		if v, ok := u["enable"]; ok {
			u["_disabled"] = !truthy(v)
		}
		if ts, ok := u["expiry_time"].(string); ok {
			if _, parsed := moment(ts); !parsed {
				delete(u, "expiry_time")
			}
		}
		u["mode"] = fmt.Sprint(u["mode"])
	}
	return users, nil
}
