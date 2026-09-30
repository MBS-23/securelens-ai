package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"io"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	rows, _ := db.Query(q)
	_ = rows
	safe, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
	_ = safe
	name := r.FormValue("name")
	out, _ := exec.Command("sh", "-c", "ls "+name).Output()
	w.Write([]byte("<p>" + name + "</p>"))
	data, _ := os.ReadFile("/srv/files/" + r.URL.Query().Get("file"))
	_ = data
	resp, _ := http.Get(r.FormValue("url"))
	_ = resp
	body, _ := io.ReadAll(r.Body)
	_ = body
	_ = out
	http.Redirect(w, r, r.FormValue("next"), 302)
}

func weak() {
	cfg := &tls.Config{InsecureSkipVerify: true}
	_ = cfg
	h := md5.Sum([]byte("x"))
	_ = h
	sessionToken := rand.Intn(1000000)
	_ = sessionToken
	counter := 0
	go func() { counter++ }()
}

func main() {
	http.HandleFunc("/u", handler)
	http.ListenAndServe(":8080", nil)
}
