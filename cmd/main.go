package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lewks96/knox-am/internal/util"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"math/rand"
	"net/http"
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

func (a *AppState) InitializeTestData() {

	_, err := a.DB.Exec("insert into sso_clients (client_id, client_secret, created_at, updated_at) values ('knox', 'd660753593bdcc212709822a2d157ec85f0ac8eeae3103828af6c06174b6e347', datetime('now'), datetime('now'))")
	if err != nil {
		panic(err)
	}

	// add a client with id mobileapp and secret mobileapp
	_, err = a.DB.Exec("insert into sso_clients (client_id, client_secret, created_at, updated_at) values ('mobileapp', '67e39aa95663921fdbd05f18414bebeb2cc1b8a037e929357aa74fbf234e8bc2', datetime('now'), datetime('now'))")
	if err != nil {
		panic(err)
	}

	// add a clients to app statjj
	a.Clients = append(a.Clients, OAuthClient{ClientId: "knox", ClientSecret: "d660753593bdcc212709822a2d157ec85f0ac8eeae3103828af6c06174b6e347"})
	a.Clients = append(a.Clients, OAuthClient{ClientId: "mobileapp", ClientSecret: "67e39aa95663921fdbd05f18414bebeb2cc1b8a037e929357aa74fbf234e8bc2"})
}

func (a *AppState) Close() {
	a.DB.Close()
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

func GetClientCredentials(r *http.Request) (string, string) {
	err := r.ParseForm()

	if err != nil {
		panic(err)
	}

	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	return clientId, clientSecret
}

func main() {
	app := &AppState{}
	app.Initialize()
	defer app.Close()
	app.InitializeTestData()

	logger, er := zap.NewProduction()
	if er != nil {
		panic(er)
	}
	defer logger.Sync()

	e := echo.New()
	e.Use(util.ZapRequestLogger(logger))
	e.Use(middleware.Recover())

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.POST("/oauth2/authorize", func(c echo.Context) error {
		clientId, clientSecret := GetClientCredentials(c.Request())

		if clientId == "" {
			return c.String(http.StatusBadRequest, "client_id is required")
		}

		if !app.ClientExists(clientId) {
			return c.String(http.StatusUnauthorized, "client_id is invalid")
		}

		if !app.AuthenticateClient(clientId, clientSecret) {
			return c.String(http.StatusUnauthorized, "client credentials are invalid")
		}

		token := app.GenerateSsoToken(clientId)
		return c.String(http.StatusOK, token)
	})

	e.Logger.Fatal(e.Start(":1323"))
}
