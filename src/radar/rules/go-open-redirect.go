package main

import "net/http"

func bad(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	// ruleid: go-open-redirect
	http.Redirect(w, r, target, http.StatusFound)
}

func good(w http.ResponseWriter, r *http.Request) {
	// ok: go-open-redirect
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
