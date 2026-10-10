package importer

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// fixture builds a sqlite file from statements.
func fixture(t *testing.T, stmts ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	return path
}

func byName(rows []Row) map[string]Row {
	m := map[string]Row{}
	for _, r := range rows {
		m[r.Username] = r
	}
	return m
}

func TestThreeXUI(t *testing.T) {
	path := fixture(t,
		`CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, settings TEXT)`,
		`CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, email TEXT, up INTEGER, down INTEGER)`,
		`INSERT INTO inbounds (protocol, settings) VALUES ('vless', '{"clients":[
			{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","email":"alice","totalGB":10737418240,"expiryTime":1893456000000,"enable":true,"tgId":"777","limitIp":3,"comment":"vip","reset":30},
			{"id":"11111111-2222-4333-8444-555555555555","email":"trial","totalGB":0,"expiryTime":-259200000,"enable":false}]}')`,
		`INSERT INTO inbounds (protocol, settings) VALUES ('trojan', '{"clients":[{"password":"s3cret","email":"alice"},{"password":"p2","email":"carol"}]}')`,
		`INSERT INTO client_traffics (email, up, down) VALUES ('alice', 100, 200), ('carol', 5, 5)`,
	)
	panel, rows, problems, err := FromSQLite(path)
	if err != nil || len(problems) != 0 {
		t.Fatalf("err=%v problems=%v", err, problems)
	}
	if panel != PanelXUI || len(rows) != 3 {
		t.Fatalf("panel=%s rows=%d (a client in two inbounds is one user)", panel, len(rows))
	}
	m := byName(rows)
	a := m["alice"]
	if a.UUID != "5783a3e7-e373-51cd-8642-c83782b807c5" || a.Limit != 10<<30 || a.Used != 300 || a.IPLimit != 3 || a.Note != "vip" || a.Reset != "month" ||
		a.TelegramID == nil || *a.TelegramID != 777 || a.ExpireAt == nil || a.ExpireAt.Unix() != 1893456000 {
		t.Fatalf("alice misread: %+v", a)
	}
	tr := m["trial"]
	if tr.OnHoldDays != 3 || tr.ExpireAt != nil || !tr.Disabled {
		t.Fatalf("a negative expiry means days after first use: %+v", tr)
	}
	if m["carol"].Password != "p2" || m["carol"].Used != 10 {
		t.Fatalf("carol misread: %+v", m["carol"])
	}
}

func TestMarzban(t *testing.T) {
	path := fixture(t,
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INTEGER, data_limit INTEGER, expire INTEGER, note TEXT, data_limit_reset_strategy TEXT, on_hold_expire_duration INTEGER)`,
		`CREATE TABLE proxies (id INTEGER PRIMARY KEY, user_id INTEGER, type TEXT, settings TEXT)`,
		`INSERT INTO users VALUES (1,'alice','active',500,1073741824,1893456000,'hi','month',NULL)`,
		`INSERT INTO users VALUES (2,'bob','disabled',0,NULL,NULL,NULL,'no_reset',NULL)`,
		`INSERT INTO users VALUES (3,'newbie','on_hold',0,5368709120,NULL,NULL,'no_reset',604800)`,
		`INSERT INTO proxies (user_id,type,settings) VALUES (1,'vless','{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","flow":""}'),(1,'trojan','{"password":"tp"}'),(2,'trojan','{"password":"only-trojan"}')`,
	)
	panel, rows, _, err := FromSQLite(path)
	if err != nil || panel != PanelMarzban || len(rows) != 3 {
		t.Fatalf("panel=%s rows=%d err=%v", panel, len(rows), err)
	}
	m := byName(rows)
	if a := m["alice"]; a.UUID == "" || a.Password != "tp" || a.Limit != 1<<30 || a.Used != 500 || a.Reset != "month" || a.ExpireAt == nil {
		t.Fatalf("alice misread: %+v", a)
	}
	if b := m["bob"]; !b.Disabled || b.Password != "only-trojan" || b.UUID != "" {
		t.Fatalf("bob misread: %+v", b)
	}
	if n := m["newbie"]; n.OnHoldDays != 7 || n.Limit != 5<<30 {
		t.Fatalf("newbie misread: %+v", n)
	}
}

func TestHiddify(t *testing.T) {
	path := fixture(t,
		`CREATE TABLE user (id INTEGER PRIMARY KEY, uuid TEXT, name TEXT, usage_limit_GB REAL, current_usage_GB REAL, package_days INTEGER, start_date TEXT, mode TEXT, comment TEXT, telegram_id INTEGER, max_ips INTEGER, enable INTEGER)`,
		`INSERT INTO user (uuid,name,usage_limit_GB,current_usage_GB,package_days,start_date,mode,comment,telegram_id,max_ips,enable) VALUES ('5783a3e7-e373-51cd-8642-c83782b807c5','alice',50,12.5,30,'2026-10-01','monthly','vip',99,2,1)`,
		`INSERT INTO user (uuid,name,usage_limit_GB,current_usage_GB,package_days,start_date,mode,enable) VALUES ('11111111-2222-4333-8444-555555555555','fresh',10,0,30,NULL,'no_reset',1)`,
	)
	panel, rows, _, err := FromSQLite(path)
	if err != nil || panel != PanelHiddify || len(rows) != 2 {
		t.Fatalf("panel=%s rows=%d err=%v", panel, len(rows), err)
	}
	m := byName(rows)
	if a := m["alice"]; a.Limit != 50<<30 || a.Reset != "month" || a.IPLimit != 2 || a.ExpireAt == nil || a.ExpireAt.Format("2006-01-02") != "2026-10-31" {
		t.Fatalf("alice misread: %+v", a)
	}
	if f := m["fresh"]; f.OnHoldDays != 30 || f.ExpireAt != nil {
		t.Fatalf("a package that never started waits for the first connection: %+v", f)
	}
}

func TestUnknownDatabaseIsRefusedClearly(t *testing.T) {
	path := fixture(t, `CREATE TABLE things (id INTEGER)`)
	if _, _, _, err := FromSQLite(path); err == nil {
		t.Fatal("a database from no known panel should be refused")
	}
	if _, _, _, err := FromSQLite(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("a missing file should be an error")
	}
}
