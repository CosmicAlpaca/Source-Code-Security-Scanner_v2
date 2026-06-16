package main

import (
	"net/http"
)

func bad(r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: go-ssrf-user-input
	http.Get(target)
}

func good() {
	// ok: go-ssrf-user-input
	http.Get("https://trusted-api.example.com/data")
}
