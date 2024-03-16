package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lewks96/knox-am/internal/core"
	"github.com/lewks96/knox-am/internal/oauth"
	"github.com/lewks96/knox-am/internal/util"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"net/http"
)

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
	app := &core.AppState{}
	app.Initialize()
	defer app.Close()
    util.InitializeDB(app.DB)

    oauthProvider := &oauth.OAuthProvider{}
    err := oauthProvider.Initialize()
    if err != nil {
        panic(err)
    }
    defer oauthProvider.Close()

    app.GetClientsFromDB() 

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

	e.POST("/oauth/token", func(c echo.Context) error {
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

	e.Logger.Fatal(e.Start(":9000"))
}
