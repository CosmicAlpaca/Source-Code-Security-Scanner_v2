package main

import (
	"fmt"
	"net/http"
)

func bad(r *http.Request) {
	// ruleid: go-ssrf-user-input
	target := r.URL.Query().Get("url")
	http.Get(target)
}

func bad2(r *http.Request) {
	// ruleid: go-ssrf-user-input
	endpoint := r.FormValue("endpoint")
	resp, _ := http.Post(endpoint, "application/json", nil)
	fmt.Println(resp)
}

func good() {
	// ok: go-ssrf-user-input
	http.Get("https://internal-api.local/data")
}
