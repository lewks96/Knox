package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lewks96/knox-am/internal/core"
	"github.com/lewks96/knox-am/internal/util"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
)

func createDefaultEnvFile() {
	envFile := `
    # Server Config
    HOSTNAME=localhost
    PORT=9000
    
    # Database Config
    DB_HOST=127.0.0.1
    DB_PORT=3306
    DB_USER=
    DB_PASSWORD=
    
    #DSS_PROVIDER=redis
    DSS_PROVIDER=memcache
    DSS_CLEANUP_INTERVAL_SECONDS=60
    
    # Memcache Config
    DSS_MEMCACHE_PREALLOCATE=1000
    
    # Redis Config
    DSS_REDIS_HOST=127.0.0.1
    DSS_REDIS_PORT=6379
    DSS_REDIS_PASSWORD=
    DSS_REDIS_DB=0
    DSS_REDIS_USE_TLS=false
    `
	err := os.WriteFile(".env", []byte(envFile), 0644)
	if err != nil {
		panic(err)
	}
}

func main() {
	Logger, _ := zap.NewProduction()
	defer Logger.Sync()
	Logger.Info("KnoxAM server starting")

	_, err := os.Stat(".env")
	if os.IsNotExist(err) {
		Logger.Info("No .env file found, creating default .env file")
		createDefaultEnvFile()
	}

	err = godotenv.Load()
	if err != nil {
		panic(err)
	}
	Logger.Info("Loaded .env file")

	app := &core.AppState{}
	app.Initialize()
	defer app.Close()

	Logger.Info("Application initialized")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		Logger, _ := zap.NewProduction()
		<-c
		Logger.Info("Received interrupt signal, closing application")
		app.Close()
		os.Exit(1)
	}()

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(util.ZapRequestLogger(Logger))

	e.POST("/oauth/token", func(c echo.Context) error {
		// read body to string
		body, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		}

		slice := strings.Split(string(body), "&")
		data := make(map[string]string)
		for _, s := range slice {
			pair := strings.Split(s, "=")
			data[pair[0]], _ = url.QueryUnescape(pair[1])
		}

		grantType := data["grant_type"]
		scope := data["scope"]
		//redirectUri := data["redirect_uri"]

		authHeader := c.Request().Header.Get("Authorization")
		clientId := ""
		clientSecret := ""

		if authHeader != "" {
			authHeader = strings.TrimPrefix(authHeader, "Basic ")
			res, err := base64.StdEncoding.DecodeString(authHeader)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			}
			decodedString := string(res)
			slice := strings.Split(decodedString, ":")
			clientId = slice[0]
			clientSecret = slice[1]
		} else {
			clientId = data["client_id"]
			clientSecret = data["client_secret"]
			if clientId == "" {
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
		}

		Logger.Info("Client ID", zap.String("client_id", clientId))
		Logger.Info("Client Secret", zap.String("client_secret", clientSecret))

		switch grantType {
		case "client_credentials":
			token, err := app.OAuthProvider.AuthorizeForGrantClientCredentials(clientId, clientSecret, scope)
			if err != nil {
				respJson := map[string]string{"error": err.Error()}
				return c.JSON(http.StatusUnauthorized, respJson)
			}
			c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			c.Response().WriteHeader(http.StatusOK)
			json.NewEncoder(c.Response()).Encode(token)
			return nil
		default:
			respJson := map[string]string{"error": "unsupported_grant_type"}
			return c.JSON(http.StatusBadRequest, respJson)
		}
	})

	e.GET("/oauth/tokeninfo", func(c echo.Context) error {

		accessToken := c.QueryParam("access_token")
		if accessToken == "" {
			errorResponse := map[string]string{"error": "access_token is required"}
			return c.JSON(http.StatusBadRequest, errorResponse)
		}

		tokenInfo, err := app.OAuthProvider.GetTokenInfo(accessToken)
		if err != nil {
			respJson := map[string]string{"error": "invalid access token"}
			return c.JSON(http.StatusUnauthorized, respJson)
		}
		return c.JSON(http.StatusOK, tokenInfo)
	})

	e.DELETE("/sessions/revoke", func(c echo.Context) error {
		count, err := app.OAuthProvider.RevokeAllSessions()
		if err != nil {
			respJson := map[string]string{"error": "invalid access token"}
			return c.JSON(http.StatusUnauthorized, respJson)
		}
		respJson := map[string]string{"error": fmt.Sprintf("deleted %d sessions", count)}
		return c.JSON(http.StatusOK, respJson)
	})

	e.DELETE("/oauth/revoke", func(c echo.Context) error {
		accessToken := c.QueryParam("access_token")
		if accessToken == "" {
			errorResponse := map[string]string{"error": "access_token is required"}
			return c.JSON(http.StatusBadRequest, errorResponse)
		}

		err := app.OAuthProvider.DeleteSession(accessToken)
		if err != nil {
			respJson := map[string]string{"error": "invalid access token"}
			return c.JSON(http.StatusUnauthorized, respJson)
		}
		respJson := map[string]string{"error": "session deleted"}
		return c.JSON(http.StatusOK, respJson)
	})

	hostname := os.Getenv("HOSTNAME")
	port := os.Getenv("PORT")
	if hostname == "" {
		Logger.Info("HOSTNAME environment variable not set, defaulting to localhost")
		hostname = "localhost"
	}
	if port == "" {
		Logger.Info("PORT environment variable not set, defaulting to 9000")
		port = "9000"
	}
	e.Logger.Fatal(e.Start(hostname + ":" + port))
}
