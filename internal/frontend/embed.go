//go:build frontend

package frontend

import (
	"embed"
	"io/fs"
)

// distFS holds the built frontend
//
//go:embed all:dist
var distFS embed.FS

// embedded returns the embedded frontend build, if any.
func embedded() (fs.FS, bool) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, false
	}
	if entries, err := fs.ReadDir(sub, "."); err != nil || len(entries) == 0 {
		return nil, false
	}
	return sub, true
}
