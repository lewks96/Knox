package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type OAuthClient struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AppState struct {
	DB      *sql.DB
	Clients []OAuthClient
}

func generateRandomAlphaNumericString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateSha256Hash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

func (a *AppState) Initialize() {
	db, errd := sql.Open("sqlite3", "file::memory:?cache=shared")
	if errd != nil {
		panic(errd)
	}
	a.DB = db
	combinedQuery := "create table if not exists sso_tokens (id integer primary key, token text, client_id text, created_at datetime, updated_at datetime);"
	combinedQuery += "drop table if exists sso_clients;"
	combinedQuery += "create table if not exists sso_clients (id integer primary key, client_id text, client_secret text, created_at datetime, updated_at datetime)"

	_, err2 := a.DB.Exec(combinedQuery)
	if err2 != nil {
		panic("")
	}
}

func (a *AppState) Close() {
	a.DB.Close()
}

func (a *AppState) GetClientsFromDB() {
    stmt, err := a.DB.Query("select client_id, client_secret from sso_clients")
    if err != nil {
        panic(err)
    }
    defer stmt.Close()
    
    for stmt.Next() {
        client := OAuthClient{}
        stmt.Scan(&client.ClientId, &client.ClientSecret)
        fmt.Println("Got client_id: ", client.ClientId)
        a.Clients = append(a.Clients, client)
    }
}

func (a *AppState) ClientExists(clientId string) bool {
	for _, client := range a.Clients {
		if client.ClientId == clientId {
			return true
		}
	}
	return false

	//stmt, err := a.DB.Query("select count(*) from sso_clients where client_id = ?", clientId)
	//if err != nil {
	//	panic(err)
	//}
	//defer stmt.Close()
	//
	//for stmt.Next() {
	//    var count int
	//    stmt.Scan(&count)
	//    return count > 0
	//}
	//return false
}

func (a *AppState) AuthenticateClient(clientId string, clientSecret string) bool {
	client := OAuthClient{}
	for _, c := range a.Clients {
		if c.ClientId == clientId {
			client = c
		}
	}
	if client.ClientId == "" {
		panic("clientid bad")
	}

	s := fmt.Sprintf("%s|%s|%s", clientId, clientId, clientSecret)
    dbClientSecret := client.ClientSecret
	sum := generateSha256Hash(s)
	return dbClientSecret == sum

	//stmt, err := a.DB.Query("select client_secret from sso_clients where client_id = ?", clientId)
	//if err != nil {
	//	panic(err)
	//}
	//defer stmt.Close()

	//for stmt.Next() {
	//	s := fmt.Sprintf("%s|%s|%s", clientId, clientId, clientSecret)
	//	var dbClientSecret string
	//	stmt.Scan(&dbClientSecret)
	//    sum := generateSha256Hash(s)
	//	return dbClientSecret == sum
	//}
	return false
}

func (a *AppState) GenerateSsoToken(clientId string) string {
	randomSt := generateRandomAlphaNumericString(16)
	userRand := generateRandomAlphaNumericString(16)
	token := fmt.Sprintf("%s:%s", randomSt, generateSha256Hash(clientId+userRand))

	stmt, err := a.DB.Query("insert into sso_tokens (token, client_id, created_at, updated_at) values (?, ?, datetime('now'), datetime('now'))", token, clientId)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	return token
}
