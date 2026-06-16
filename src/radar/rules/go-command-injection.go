package main

import (
	"net/http"
	"os/exec"
)

// ruleid: go-command-injection
func bad(r *http.Request) {
	name := r.URL.Query().Get("file")
	exec.Command("ls", name).Run()
}

// ok: go-command-injection
func good(r *http.Request) {
	exec.Command("ls", "-la", "/safe/path").Run()
}
