package main

import (
	"net/http"
	"os/exec"
)

func bad(r *http.Request) {
	name := r.URL.Query().Get("file")
	exec.Command("ls", name).Run() // ruleid: go-command-injection
}

func good(r *http.Request) {
	exec.Command("ls", "-la", "/safe/path").Run() // ok: go-command-injection
}
