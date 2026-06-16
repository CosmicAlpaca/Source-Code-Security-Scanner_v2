package main

import (
	"fmt"
	"net/http"
)

func bad(r *http.Request) {
	// ruleid: go-ssrf-user-input
	target := r.URL.Query().Get("url")
	// ruleid: go-ssrf-user-input
	http.Get(target)
}

func bad2(r *http.Request) {
	endpoint := r.FormValue("endpoint")
	// ruleid: go-ssrf-user-input
	resp, _ := http.Post(endpoint, "application/json", nil)
	fmt.Println(resp)
}

func good() {
	// ok: go-ssrf-user-input
	http.Get("https://internal-api.local/data")
}