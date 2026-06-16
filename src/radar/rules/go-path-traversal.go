package main

import (
	"net/http"
	"os"
)

func bad(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: go-path-traversal
	os.ReadFile("/uploads/" + name)
}

func good(w http.ResponseWriter, r *http.Request) {
	// ok: go-path-traversal
	os.ReadFile("/uploads/safe-file.txt")
}
