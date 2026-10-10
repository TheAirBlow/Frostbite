package importer

import (
	"testing"
	"time"
)

func TestHiddifyStyleCSV(t *testing.T) {
	csv := "name,uuid,usage_limit_GB,current_usage_GB,package_days,start_date,comment,mode,enable\n" +
		"alice,5783a3e7-e373-51cd-8642-c83782b807c5,50,12.5,30,2026-10-01,vip,monthly,true\n" +
		"bob,,0,0,0,,,daily,false\n"
	rows, problems, err := Parse([]byte(csv))
	if err != nil || len(problems) != 0 || len(rows) != 2 {
		t.Fatalf("rows=%d problems=%v err=%v", len(rows), problems, err)
	}
	a := rows[0]
	if a.Limit != 50<<30 || a.Used != int64(12.5*(1<<30)) || a.UUID == "" || a.Reset != "month" || a.Note != "vip" {
		t.Fatalf("alice misread: %+v", a)
	}
	if a.ExpireAt == nil || a.ExpireAt.Format("2006-01-02") != "2026-10-31" {
		t.Fatalf("expiry should be start plus package days: %v", a.ExpireAt)
	}
	if !rows[1].Disabled || rows[1].Reset != "day" || rows[1].Limit != 0 {
		t.Fatalf("bob misread: %+v", rows[1])
	}
}

func TestMarzbanAndXUIStyleJSON(t *testing.T) {
	js := `{"users":[
	  {"username":"m1","status":"active","data_limit":1073741824,"used_traffic":1000,"expire":1893456000,"note":"x"},
	  {"email":"x1","id":"5783a3e7-e373-51cd-8642-c83782b807c5","totalGB":2147483648,"up":10,"down":20,"expiryTime":1893456000000,"enable":false,"tgId":"12345"}
	]}`
	rows, problems, err := Parse([]byte(js))
	if err != nil || len(problems) != 0 || len(rows) != 2 {
		t.Fatalf("rows=%d problems=%v err=%v", len(rows), problems, err)
	}
	if rows[0].Limit != 1<<30 || rows[0].Used != 1000 || rows[0].ExpireAt == nil || rows[0].ExpireAt.Unix() != 1893456000 {
		t.Fatalf("m1 misread: %+v", rows[0])
	}
	x := rows[1]
	if x.Limit != 2<<30 || x.Used != 30 || !x.Disabled || x.TelegramID == nil || *x.TelegramID != 12345 || x.ExpireAt.Unix() != 1893456000 {
		t.Fatalf("x1 misread: %+v", x)
	}
}

func TestRowWithoutNameIsReported(t *testing.T) {
	rows, problems, _ := Parse([]byte("traffic_gb,note\n5,hi\n"))
	if len(rows) != 0 || len(problems) != 1 {
		t.Fatalf("want one problem, got rows=%d problems=%v", len(rows), problems)
	}
}

func TestSemicolonCSVAndDates(t *testing.T) {
	rows, _, err := Parse([]byte("username;expire;tags\ncarol;15.03.2027;a|b\n"))
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	if rows[0].ExpireAt == nil || rows[0].ExpireAt.Year() != 2027 || len(rows[0].Tags) != 2 {
		t.Fatalf("misread: %+v", rows[0])
	}
	_ = time.Now
}
