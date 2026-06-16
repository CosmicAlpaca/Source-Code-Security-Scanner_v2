package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// ruleid: go-sql-string-concat
func bad1(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}

// ruleid: go-sql-string-concat
func bad2(db *sql.DB, r *http.Request) {
	name := r.FormValue("name")
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE name = '%s'", name))
}

// ok: go-sql-string-concat
func good(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
