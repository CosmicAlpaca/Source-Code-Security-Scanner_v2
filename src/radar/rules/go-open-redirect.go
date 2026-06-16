package main

import "net/http"

// ruleid: go-open-redirect
func bad(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	http.Redirect(w, r, target, http.StatusFound)
}
