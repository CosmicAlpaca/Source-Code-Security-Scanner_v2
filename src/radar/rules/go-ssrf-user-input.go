package main

import (
	"net/http"
)

// ruleid: go-ssrf-user-input
func bad(r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Get(target)
}

// ok: go-ssrf-user-input
func good() {
	http.Get("https://trusted-api.example.com/data")
}
