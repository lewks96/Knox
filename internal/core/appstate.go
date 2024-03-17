package core

import (
	"database/sql"
	"github.com/lewks96/knox-am/internal/oauth"
	_ "github.com/mattn/go-sqlite3"
)

type AppState struct {
	DB            *sql.DB
	OAuthProvider *oauth.OAuthProvider
}

func (a *AppState) Initialize() {
	//	db, errd := sql.Open("sqlite3", "file::memory:?cache=shared")
	//	if errd != nil {
	//		panic(errd)
	//	}
	//	a.DB = db
	//	combinedQuery := "create table if not exists sso_tokens (id integer primary key, token text, client_id text, created_at datetime, updated_at datetime);"
	//	combinedQuery += "drop table if exists sso_clients;"
	//	combinedQuery += "create table if not exists sso_clients (id integer primary key, client_id text, client_secret text, created_at datetime, updated_at datetime)"
	//
	//	_, err2 := a.DB.Exec(combinedQuery)
	//	if err2 != nil {
	//		panic("")
	//	}
	//
	oauthProvider := &oauth.OAuthProvider{}
	err := oauthProvider.Initialize()
	if err != nil {
		panic(err)
	}
	a.OAuthProvider = oauthProvider
}

func (a *AppState) Close() {
	//	a.DB.Close()
	a.OAuthProvider.Close()
}
