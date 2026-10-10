// Package backup dumps and restores everything the panel owns, as one json document.
package backup

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// format is bumped when the document layout changes.
const format = 1

// tables lists what a backup holds, parents before children so inserts satisfy foreign keys.
var tables = []string{
	"admins", "settings", "nodes", "daemons", "inbounds", "hosts", "outbounds", "rules", "squads", "squad_inbounds",
	"plans", "users", "user_squads", "user_devices", "sub_templates", "sub_rules",
}

// historyTables only travel with a backup when asked for, since they can be large.
var historyTables = []string{"traffic_hourly"}

// Doc is the backup document.
type Doc struct {
	Format    int                        `json:"format"`
	App       string                     `json:"app"`
	Schema    int64                      `json:"schema"`
	CreatedAt time.Time                  `json:"created_at"`
	Tables    map[string]json.RawMessage `json:"tables"`
}

// schemaVersion is the latest applied migration.
func schemaVersion(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version`).Scan(&v)
	return v, err
}

// Dump reads every table into a document.
func Dump(ctx context.Context, pool *pgxpool.Pool, withHistory bool) (*Doc, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	schema, err := schemaVersion(ctx, tx)
	if err != nil {
		return nil, err
	}
	doc := &Doc{Format: format, App: "frostbite", Schema: schema, CreatedAt: time.Now().UTC(), Tables: map[string]json.RawMessage{}}

	names := tables
	if withHistory {
		names = append(append([]string{}, tables...), historyTables...)
	}
	for _, name := range names {
		var raw json.RawMessage
		// names come from the lists above, never from a request
		q := fmt.Sprintf(`SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM %s t`, name)
		if err := tx.QueryRow(ctx, q).Scan(&raw); err != nil {
			return nil, fmt.Errorf("dumping %s: %w", name, err)
		}
		doc.Tables[name] = raw
	}
	return doc, nil
}

// WriteGzip writes a document as gzipped json.
func WriteGzip(w io.Writer, doc *Doc) error {
	gz := gzip.NewWriter(w)
	if err := json.NewEncoder(gz).Encode(doc); err != nil {
		return err
	}
	return gz.Close()
}

// Read parses a document that may or may not be gzipped.
func Read(r io.Reader) (*Doc, error) {
	head := make([]byte, 2)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("empty backup file")
	}
	r = io.MultiReader(bytesReader(head[:n]), r)
	if n == 2 && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}

	var doc Doc
	if err := json.NewDecoder(io.LimitReader(r, 1<<30)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a Frostbite backup: %w", err)
	}
	if doc.App != "frostbite" || doc.Format != format {
		return nil, fmt.Errorf("not a Frostbite backup, or from an incompatible version")
	}
	return &doc, nil
}

// Restore replaces everything with the contents of doc. It all happens in one transaction, so a bad file changes nothing.
func Restore(ctx context.Context, pool *pgxpool.Pool, doc *Doc) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	have, err := schemaVersion(ctx, tx)
	if err != nil {
		return err
	}
	if doc.Schema != have {
		return fmt.Errorf("the backup is from database schema %d, this panel is on %d", doc.Schema, have)
	}

	all := append(append([]string{}, tables...), historyTables...)
	for i := len(all) - 1; i >= 0; i-- {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`TRUNCATE %s CASCADE`, all[i])); err != nil {
			return fmt.Errorf("clearing %s: %w", all[i], err)
		}
	}

	for _, name := range all {
		rows, ok := doc.Tables[name]
		if !ok || string(rows) == "[]" {
			continue
		}
		q := fmt.Sprintf(`INSERT INTO %s SELECT * FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)`, name, name)
		if _, err := tx.Exec(ctx, q, []byte(rows)); err != nil {
			return fmt.Errorf("restoring %s: %w", name, err)
		}
	}

	for _, name := range all {
		var has bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = 'id')`, name).Scan(&has); err != nil || !has {
			continue
		}
		q := fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('%s', 'id'), COALESCE((SELECT max(id) FROM %s), 0) + 1, false)`, name, name)
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("resetting ids of %s: %w", name, err)
		}
	}
	return tx.Commit(ctx)
}
