package backup

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"frostbite/internal/metrics"
)

// bytesReader wraps a byte slice as a reader.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// File is a backup kept on disk.
type File struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

// Dir is where scheduled backups live inside the data directory.
func Dir(dataDir string) string { return filepath.Join(dataDir, "backups") }

// List returns the backups on disk, newest first.
func List(dataDir string) ([]File, error) {
	entries, err := os.ReadDir(Dir(dataDir))
	if os.IsNotExist(err) {
		return []File{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []File{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, File{Name: e.Name(), Size: info.Size(), Created: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Path resolves a backup name to a path, refusing anything that is not a plain file name.
func Path(dataDir, name string) (string, bool) {
	if name != filepath.Base(name) || !strings.HasSuffix(name, ".json.gz") {
		return "", false
	}
	return filepath.Join(Dir(dataDir), name), true
}

// Create writes a new backup file and returns it.
func Create(ctx context.Context, pool *pgxpool.Pool, dataDir string, withHistory bool) (File, error) {
	doc, err := Dump(ctx, pool, withHistory)
	if err != nil {
		return File{}, err
	}
	if err := os.MkdirAll(Dir(dataDir), 0o700); err != nil {
		return File{}, err
	}
	name := "frostbite-" + doc.CreatedAt.Format("20060102-150405") + ".json.gz"
	path := filepath.Join(Dir(dataDir), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return File{}, err
	}
	if err := WriteGzip(f, doc); err != nil {
		f.Close()
		os.Remove(path)
		return File{}, err
	}
	if err := f.Close(); err != nil {
		return File{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return File{}, err
	}
	return File{Name: name, Size: info.Size(), Created: info.ModTime()}, nil
}

// Prune deletes all but the newest keep backups.
func Prune(dataDir string, keep int) {
	files, err := List(dataDir)
	if err != nil || keep < 1 || len(files) <= keep {
		return
	}
	for _, f := range files[keep:] {
		if p, ok := Path(dataDir, f.Name); ok {
			if err := os.Remove(p); err != nil {
				slog.Warn("backup: removing old file failed", "file", f.Name, "err", err)
			}
		}
	}
}

// Schedule says when automatic backups are made.
type Schedule struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"interval_hours"`
	Keep          int  `json:"keep"`
	History       bool `json:"history"` // include hourly traffic rows
}

// DefaultSchedule is what a fresh panel does: a daily backup, two weeks kept.
func DefaultSchedule() Schedule {
	return Schedule{Enabled: true, IntervalHours: 24, Keep: 14}
}

// Run makes a backup whenever the newest one is older than the schedule says, until ctx ends.
func Run(ctx context.Context, pool *pgxpool.Pool, dataDir string, load func(context.Context) (Schedule, error)) {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		s, err := load(ctx)
		if err != nil || !s.Enabled || s.IntervalHours < 1 {
			continue
		}
		files, _ := List(dataDir)
		if len(files) > 0 && time.Since(files[0].Created) < time.Duration(s.IntervalHours)*time.Hour {
			continue
		}
		start := time.Now()
		f, err := Create(ctx, pool, dataDir, s.History)
		metrics.BackupRuns.WithLabelValues("scheduled", metrics.Result(err)).Inc()
		metrics.BackupSeconds.WithLabelValues("scheduled").Observe(time.Since(start).Seconds())
		if err == nil {
			metrics.BackupBytes.Add(float64(f.Size))
		}
		if err != nil {
			slog.Error("backup: scheduled backup failed", "err", err)
			continue
		}
		slog.Info("backup: created", "file", f.Name, "size", f.Size)
		Prune(dataDir, s.Keep)
	}
}
