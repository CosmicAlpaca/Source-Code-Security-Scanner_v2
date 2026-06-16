package main

import (
	"net/http"
	"os"
)

// ruleid: go-path-traversal
func bad(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	os.ReadFile("/uploads/" + name)
}

// ok: go-path-traversal
func good(w http.ResponseWriter, r *http.Request) {
	os.ReadFile("/uploads/safe-file.txt")
}
