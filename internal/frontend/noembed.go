//go:build !frontend

package frontend

import "io/fs"

// embedded returns the embedded frontend build, if any.
func embedded() (fs.FS, bool) {
	return nil, false
}
