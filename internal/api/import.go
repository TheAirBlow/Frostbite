package api

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"frostbite/internal/db"
	"frostbite/internal/importer"
	"frostbite/internal/metrics"
)

// importRequest is the JSON body for importing users.
type importRequest struct {
	Data     string  `json:"data"` // csv or json text
	SquadIDs []int64 `json:"squad_ids"`
	PlanID   *int64  `json:"plan_id"`
	DryRun   bool    `json:"dry_run"`
}

// importProblem says why one row was not imported.
type importProblem struct {
	Line     int    `json:"line"`
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

// importUsers reads a user list exported from somewhere else and creates the users.
func (s *Server) importUsers(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	var req importRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	rows, parseProblems, err := importer.Parse([]byte(req.Data))
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	s.runImport(w, r, admin, rows, parseProblems, req, nil)
}

// importDatabase reads users straight from another panel's sqlite database, sent as the request body.
func (s *Server) importDatabase(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	f, err := os.CreateTemp("", "frostbite-import-*.db")
	if err != nil {
		internalError(w, err)
		return
	}
	defer os.Remove(f.Name())
	if _, err := io.Copy(f, http.MaxBytesReader(w, r.Body, 256<<20)); err != nil {
		f.Close()
		badRequest(w, "the file could not be read: "+err.Error())
		return
	}
	f.Close()

	panel, rows, parseProblems, err := importer.FromSQLite(f.Name())
	if err != nil {
		badRequest(w, err.Error())
		return
	}

	req := importRequest{DryRun: r.URL.Query().Get("dry_run") == "1"}
	for _, part := range strings.Split(r.URL.Query().Get("squads"), ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil {
			req.SquadIDs = append(req.SquadIDs, id)
		}
	}
	s.runImport(w, r, admin, rows, parseProblems, req, map[string]any{"panel": panel})
}

// runImport creates the users in rows and answers with what happened. extra is merged into the response.
func (s *Server) runImport(w http.ResponseWriter, r *http.Request, admin db.Admin, rows []importer.Row, parseProblems []string, req importRequest, extra map[string]any) {
	problems := []importProblem{}
	for _, p := range parseProblems {
		problems = append(problems, importProblem{Reason: p})
	}

	var total int64
	for _, row := range rows {
		total += row.Limit
	}
	if msg := s.checkReseller(r.Context(), admin, len(rows), total, 0); msg != "" {
		forbidden(w, msg)
		return
	}

	created := 0
	var sample []importer.Row
	for _, row := range rows {
		if reason := s.importOne(r, admin, row, req); reason != "" {
			problems = append(problems, importProblem{Line: row.Line, Username: row.Username, Reason: reason})
			continue
		}
		created++
		if len(sample) < 5 {
			sample = append(sample, row)
		}
	}

	source, result := "file", "ok"
	if extra != nil {
		source = "database"
	}
	if req.DryRun {
		result = "dry_run"
	} else {
		metrics.ImportedUsers.WithLabelValues("created").Add(float64(created))
		metrics.ImportedUsers.WithLabelValues("skipped").Add(float64(len(problems)))
	}
	metrics.ImportRuns.WithLabelValues(source, result).Inc()
	if !req.DryRun {
		s.Hub.MarkDirty()
		s.audit(r, "user.import", "", map[string]any{"created": created, "problems": len(problems)})
	}
	out := map[string]any{"created": created, "problems": problems, "dry_run": req.DryRun, "sample": sample}
	for k, v := range extra {
		out[k] = v
	}
	ok(w, out)
}

// importOne creates one user and returns why it could not, or an empty string.
func (s *Server) importOne(r *http.Request, admin db.Admin, row importer.Row, req importRequest) string {
	if !userNamePattern.MatchString(row.Username) {
		return "the name has characters usernames can't contain"
	}
	if row.UUID != "" {
		if _, err := uuid.Parse(row.UUID); err != nil {
			return "the uuid is not valid"
		}
	}
	if _, err := s.Queries.GetUserByUsername(r.Context(), row.Username); err == nil {
		return "a user with this name already exists"
	}
	if req.DryRun {
		return ""
	}

	ur := userRequest{
		TrafficLimit: row.Limit, ResetStrategy: row.Reset, ExpireAt: row.ExpireAt, Tags: row.Tags, Note: row.Note, TelegramID: row.TelegramID,
		PlanID: req.PlanID, SquadIDs: req.SquadIDs, IPLimit: int32(row.IPLimit),
	}
	if row.OnHoldDays > 0 {
		ur.StartOnFirstUse, ur.DurationDays = true, int32(row.OnHoldDays)
	}
	if req.PlanID != nil {
		// a plan only fills what the file left empty
		if err := s.applyPlan(r.Context(), &ur); err != nil {
			return err.Error()
		}
		ur.DurationDays = 0
	}
	p, err := newUserParams(ur, row.Username, &admin.ID)
	if err != nil {
		return "could not prepare the user"
	}
	if row.UUID != "" {
		p.Uuid = strings.ToLower(row.UUID)
	}
	if row.Password != "" {
		p.Password = row.Password
	}
	if row.Disabled {
		p.Status = "disabled"
	}

	u, err := s.Queries.CreateUser(r.Context(), p)
	if err != nil {
		return "the database refused it, most likely a duplicate uuid"
	}
	if row.Used > 0 {
		_ = s.Queries.SetUserUsed(r.Context(), db.SetUserUsedParams{ID: u.ID, TrafficUsed: row.Used})
	}
	if len(ur.SquadIDs) > 0 {
		_ = s.Queries.AddUserSquads(r.Context(), db.AddUserSquadsParams{Ids: []int64{u.ID}, SquadIds: ur.SquadIDs})
	}
	return ""
}
