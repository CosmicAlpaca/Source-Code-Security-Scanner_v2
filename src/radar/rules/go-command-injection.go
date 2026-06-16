package main

import (
	"net/http"
	"os/exec"
)

func bad(r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: go-command-injection
	exec.Command("ls", name).Run()
}

func good(r *http.Request) {
	// ok: go-command-injection
	exec.Command("ls", "-la", "/safe/path").Run()
}
