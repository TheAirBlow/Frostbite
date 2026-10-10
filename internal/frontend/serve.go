package frontend

import (
	"io/fs"
	"net/http"
)

// Available reports whether a frontend build exists to serve.
func Available() bool {
	_, ok := embedded()
	return ok
}

// Handler serves the frontend single page application.
func Handler() http.Handler {
	files, _ := embedded()
	return spaHandler(files)
}

// shellName returns the SPA shell, preferring the nuxt fallback over the prerendered index.
func shellName(files fs.FS) string {
	if _, err := fs.Stat(files, "200.html"); err == nil {
		return "200.html"
	}
	return "index.html"
}

// spaHandler serves filesystem, falling back to the SPA shell for unknown paths.
func spaHandler(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	shell := shellName(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path
		for len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}
		info, err := fs.Stat(files, name)
		if name == "" || err != nil || info.IsDir() {
			http.ServeFileFS(w, r, files, shell)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
