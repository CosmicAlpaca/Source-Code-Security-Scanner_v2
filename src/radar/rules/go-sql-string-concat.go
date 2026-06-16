package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func bad1(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ruleid: go-sql-string-concat
	db.Query("SELECT * FROM users WHERE id = " + id)
}

func bad2(db *sql.DB, r *http.Request) {
	name := r.FormValue("name")
	// ruleid: go-sql-string-concat
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE name = '%s'", name))
}

func good(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ok: go-sql-string-concat
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
