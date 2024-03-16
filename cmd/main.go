package main

import (
	"net/http"
	"os"
	"os/signal"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lewks96/knox-am/internal/core"
	"github.com/lewks96/knox-am/internal/util"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

func main() {
	app := &core.AppState{}
	app.Initialize()
	defer app.Close()
    
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    go func() {
        <-c
        app.Close()
        os.Exit(1)
    }()

    util.InitializeDB(app.DB)
    
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
        clientId := c.FormValue("client_id")
        clientSecret := c.FormValue("client_secret")
        grantType := c.FormValue("grant_type")
        scope := c.FormValue("scope")
        //redirectUri := c.FormValue("redirect_uri")

		if clientId  == "" {
            errorResponse := map[string]string{"error": "client_id is required"}
			return c.JSON(http.StatusBadRequest, errorResponse)
		}
        if clientSecret == "" {
            errorResponse := map[string]string{"error": "client_secret is required"}
            return c.JSON(http.StatusBadRequest, errorResponse)
        }
        if grantType == "" {
            errorResponse := map[string]string{"error": "grant_type is required"}
            return c.JSON(http.StatusBadRequest, errorResponse)
        }

        switch grantType {
        case "client_credentials":
            token, err := app.OAuthProvider.AuthorizeForGrantClientCredentials(clientId, clientSecret, scope)
            if err != nil {
                respJson := map[string]string{"error": err.Error()}
                return c.JSON(http.StatusUnauthorized, respJson)
            }
            return c.JSON(http.StatusOK, token)
        default:
            respJson := map[string]string{"error": "unsupported_grant_type"}
            return c.JSON(http.StatusBadRequest, respJson)
        }
    })

	e.Logger.Fatal(e.Start(":9000"))
}
