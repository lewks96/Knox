package util

import (
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
)


func InitializeDB(db *sql.DB) {
	combinedQuery := "create table if not exists sso_tokens (id integer primary key, token text, client_id text, created_at datetime, updated_at datetime);"
	combinedQuery += "drop table if exists sso_clients;"
	combinedQuery += "create table if not exists sso_clients (id integer primary key, client_id text, client_secret text, created_at datetime, updated_at datetime)"
	_, err := db.Exec(combinedQuery)
	if err != nil {
		panic("")
	}
    initializeTestData(db)
}

func initializeTestData(db *sql.DB) {

	_, err := db.Exec("insert into sso_clients (client_id, client_secret, created_at, updated_at) values ('knox', 'd660753593bdcc212709822a2d157ec85f0ac8eeae3103828af6c06174b6e347', datetime('now'), datetime('now'))")
	if err != nil {
		panic(err)
	}

	// add a client with id mobileapp and secret mobileapp
	_, err = db.Exec("insert into sso_clients (client_id, client_secret, created_at, updated_at) values ('mobileapp', '67e39aa95663921fdbd05f18414bebeb2cc1b8a037e929357aa74fbf234e8bc2', datetime('now'), datetime('now'))")
	if err != nil {
		panic(err)
	}
}

