package api

import (
	"context"
	"net/http"
	"os"
	"time"

	"frostbite/internal/backup"
	"frostbite/internal/metrics"
)

// registerBackup registers backup and restore endpoints, all owner only.
func (s *Server) registerBackup(mux authMux) {
	mux.Owner("GET /backup/download", s.downloadBackup)
	mux.Owner("POST /backup/restore", s.restoreBackup)
	mux.Owner("GET /backup/files", s.listBackups)
	mux.Owner("POST /backup/files", s.createBackup)
	mux.Owner("GET /backup/files/{name}", s.getBackupFile)
	mux.Owner("DELETE /backup/files/{name}", s.deleteBackupFile)
	mux.Owner("GET /backup/schedule", s.getSchedule)
	mux.Owner("PUT /backup/schedule", s.putSchedule)
}

// LoadSchedule reads the backup schedule setting.
func (s *Server) LoadSchedule(ctx context.Context) (backup.Schedule, error) {
	sc := backup.DefaultSchedule()
	err := s.loadSetting(ctx, "backup", &sc)
	return sc, err
}

// downloadBackup streams a fresh backup to the browser.
func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	doc, err := backup.Dump(r.Context(), s.Pool, r.URL.Query().Get("history") == "1")
	metrics.BackupRuns.WithLabelValues("download", metrics.Result(err)).Inc()
	metrics.BackupSeconds.WithLabelValues("download").Observe(time.Since(start).Seconds())
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="frostbite-`+time.Now().Format("20060102-150405")+`.json.gz"`)
	if err := backup.WriteGzip(w, doc); err != nil {
		slogErr("backup: streaming failed", err)
	}
	s.audit(r, "backup.download", "", nil)
}

// restoreBackup replaces all data with an uploaded backup.
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
	doc, err := backup.Read(r.Body)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	start := time.Now()
	err = backup.Restore(r.Context(), s.Pool, doc)
	metrics.BackupRuns.WithLabelValues("restore", metrics.Result(err)).Inc()
	metrics.BackupSeconds.WithLabelValues("restore").Observe(time.Since(start).Seconds())
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	s.Hub.MarkDirty()
	// sessions are part of what got replaced, so this audit row may fall away with them
	s.audit(r, "backup.restore", doc.CreatedAt.Format(time.RFC3339), nil)
	ok(w, map[string]string{"status": "restored"})
}

// listBackups lists backups kept on disk.
func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) {
	files, err := backup.List(s.Config.DataDir())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, files)
}

// createBackup makes a backup file right now.
func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	sc, err := s.LoadSchedule(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	start := time.Now()
	f, err := backup.Create(r.Context(), s.Pool, s.Config.DataDir(), sc.History)
	metrics.BackupRuns.WithLabelValues("manual", metrics.Result(err)).Inc()
	metrics.BackupSeconds.WithLabelValues("manual").Observe(time.Since(start).Seconds())
	if err == nil {
		metrics.BackupBytes.Add(float64(f.Size))
	}
	if err != nil {
		internalError(w, err)
		return
	}
	backup.Prune(s.Config.DataDir(), sc.Keep)
	s.audit(r, "backup.create", f.Name, nil)
	created(w, f)
}

// getBackupFile serves a stored backup.
func (s *Server) getBackupFile(w http.ResponseWriter, r *http.Request) {
	path, good := backup.Path(s.Config.DataDir(), r.PathValue("name"))
	if !good {
		badRequest(w, "invalid file name")
		return
	}
	if _, err := os.Stat(path); err != nil {
		notFound(w, "not found")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("name")+`"`)
	http.ServeFile(w, r, path)
}

// deleteBackupFile removes a stored backup.
func (s *Server) deleteBackupFile(w http.ResponseWriter, r *http.Request) {
	path, good := backup.Path(s.Config.DataDir(), r.PathValue("name"))
	if !good {
		badRequest(w, "invalid file name")
		return
	}
	if err := os.Remove(path); err != nil {
		notFound(w, "not found")
		return
	}
	s.audit(r, "backup.delete", r.PathValue("name"), nil)
	noContent(w)
}

// getSchedule returns the backup schedule.
func (s *Server) getSchedule(w http.ResponseWriter, r *http.Request) {
	sc, err := s.LoadSchedule(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, sc)
}

// putSchedule saves the backup schedule.
func (s *Server) putSchedule(w http.ResponseWriter, r *http.Request) {
	sc := backup.DefaultSchedule()
	if err := decode(r, &sc); err != nil {
		badRequest(w, err.Error())
		return
	}
	if sc.IntervalHours < 1 || sc.Keep < 1 {
		badRequest(w, "interval and keep must be at least 1")
		return
	}
	if err := s.saveSetting(r.Context(), "backup", sc); err != nil {
		internalError(w, err)
		return
	}
	ok(w, sc)
}
