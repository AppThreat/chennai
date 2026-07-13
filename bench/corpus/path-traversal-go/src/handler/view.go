package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// ViewHandler serves static files based on a user-supplied path parameter.
// Vulnerable: no validation that the resolved path stays within the base directory.
func ViewHandler(baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userPath := r.URL.Query().Get("path")

		// Construct the full file path. This is vulnerable to directory traversal
		// because userPath is not validated.
		fullPath := filepath.Join(baseDir, userPath) // line 28

		data, err := os.ReadFile(fullPath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s", data)
	}
}
