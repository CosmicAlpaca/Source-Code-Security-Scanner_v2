package main

import (
	"fmt"
	"net/http"
)

func bad(r *http.Request) {
	url := r.FormValue("url")
	// ruleid: go-ssrf-user-input
	http.Get(url)
}

func bad2(r *http.Request) {
	endpoint := r.PostFormValue("endpoint")
	// ruleid: go-ssrf-user-input
	resp, _ := http.Post(endpoint, "application/json", nil)
	fmt.Println(resp)
}

func good() {
	// ok: go-ssrf-user-input
	http.Get("https://internal-api.local/data")
}
