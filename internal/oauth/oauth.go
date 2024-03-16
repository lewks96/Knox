package oauth

import (
    "time"
    "github.com/google/uuid"
	"strings"
	"context"
    "errors"
	"encoding/json"
	"github.com/lewks96/knox-am/internal/util"
	"github.com/lewks96/knox-am/internal/oauth/internal"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

/*
 * @title OAuthProvider
 * @description Contains configuration and methods to provide OAuth services
 */
type OAuthProvider struct {
	Clients       map[string]oauth.OAuthClientConfiguration
	RedisClient   *redis.Client
	Context       context.Context
	Logger        *zap.Logger
	IsPrimaryNode bool
}

type AccessToken struct {
    AccessToken string `json:"access_token"`
    TokenType string `json:"token_type"`
    ExpiresIn int `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    Scope string `json:"scope"`
}

func (p *OAuthProvider) pullClientsFromRedis() error {
	clients := p.RedisClient.Keys(p.Context, "oauth2*")
    p.Clients = make(map[string]oauth.OAuthClientConfiguration)
	for _, client := range clients.Val() {
		clientConfig := p.RedisClient.Get(p.Context, client)
		var c oauth.OAuthClientConfiguration
		err := json.Unmarshal([]byte(clientConfig.Val()), &clientConfig)
		if err != nil {
			p.Logger.Error("Failed to unmarshal client from Redis", zap.Error(err))
			return err
		}
		p.Clients[c.ClientId] = c
	}
	return nil
}

func (p *OAuthProvider) Initialize() error {
	p.Logger, _ = zap.NewProduction()
	p.Context = context.Background()
	p.RedisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	err := p.RedisClient.Ping(p.Context).Err()
	if err != nil {
		p.Logger.Error("Failed to connect to Redis", zap.Error(err))
		return err
	}

    // this is probably really bad but all good for now
	isRunning := p.RedisClient.Get(p.Context, "global-running")
	if isRunning.Val() == "true" {
		p.Logger.Debug("Another node is running, we're not the primary node")
		p.IsPrimaryNode = false
		err := p.pullClientsFromRedis()
		if err != nil {
			return err
		}
	} else {
		p.Logger.Debug("We're the primary node, flushing and setting global-running to true")
		p.RedisClient.FlushDB(p.Context)
		p.RedisClient.Set(p.Context, "global-running", "true", 0)
		p.IsPrimaryNode = true

		clients, err := oauth.LoadClientsFromConfigFile()
		if err != nil {
			p.Logger.Error("Failed to load clients from config file", zap.Error(err))
            p.Close()
			return err
		}
		p.Clients = make(map[string]oauth.OAuthClientConfiguration)
		for _, client := range clients {
			p.Clients[client.ClientId] = client
		}

		p.Logger.Debug("OAuthProvider initialized from clients.json")
		p.Logger.Debug("Number of clients loaded: ", zap.Int("count", len(p.Clients)))

		for _, client := range clients {
			serialazedClient, _ := json.Marshal(client)
			p.RedisClient.Set(p.Context, "oauth2"+client.ClientId, serialazedClient, 0)
			p.Logger.Debug("Client added to Redis", zap.String("clientId", client.ClientId))
		}
	}

	return nil
}

func (p *OAuthProvider) Close() {
	p.Logger.Debug("Closing OAuthProvider")
    if p.IsPrimaryNode {
        p.Logger.Debug("We're the primary node, flushing Redis")
		//p.RedisClient.FlushDB(p.Context)
    }
	p.RedisClient.Close()
}


func (p *OAuthProvider) AuthenticateClient(client oauth.OAuthClientConfiguration,  clientSecret string) bool {
    secretStr := clientSecret + client.ClientSecretSalt
    secret := util.GenerateSha256HashString(secretStr)
    return secret == client.ClientSecret
}

func (p *OAuthProvider) ValidateScopes(client oauth.OAuthClientConfiguration, scopes string) bool {
    if scopes == "" {
        p.Logger.Debug("No scopes requested, seeing if client allows empty scopes")
        for _, allowedScope := range client.Scopes {
            if allowedScope == "" {
                return true
            }
        }
        return false
    }

    scopeSplit := strings.Split(scopes, " ")
    if len(scopeSplit) == 0 {
        return false
    }

    p.Logger.Debug("Requested scopes", zap.Strings("scopes", scopeSplit))
    p.Logger.Debug("Client allowed scopes", zap.Strings("scopes", client.Scopes))

    // make sure ALL the requested scopes are present in the client's allowed scopes
    for _, scope := range scopeSplit{
        found := false
        for _, allowedScope := range client.Scopes {
            if scope == allowedScope {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }
    return true
}

type redisAccessSession struct {
    token string `json:"token"`  
    clientId string `json:"clientId"`
    scopes string `json:"scopes"`
    issuedAt int64 `json:"issuedAt"`
}

func (p *OAuthProvider) GenerateAccessToken(client oauth.OAuthClientConfiguration, scopes string) string {
    sessionId := strings.ReplaceAll(uuid.New().String(), "-", "")
    random := util.GenerateRandomAlphaNumericString(32)
    token := strings.ToLower(sessionId + random)

    // generate timestap
    ts := time.Now().Unix()

    accessSession := redisAccessSession{
        token: token,
        clientId: client.ClientId,
        scopes: scopes,
        issuedAt: ts,
    }
    
    serialazedSession, _ := json.Marshal(accessSession)
    p.RedisClient.Set(p.Context, "session-" + token, serialazedSession, 0)
    return token
}

func (p *OAuthProvider) AuthorizeForGrantClientCredentials(clientId string, clientSecret string, scopes string) (*AccessToken, error) {
    client , ok := p.Clients[clientId]
    if !ok {
        p.Logger.Debug("Client does not exist", zap.String("clientId", clientId))
        return nil, errors.New("client_id does not exist")
    }

    if !p.AuthenticateClient(client, clientSecret) {
        p.Logger.Debug("Invalid client credentials", zap.String("clientId", clientId))
        return nil, errors.New("invalid credentials")
    }

    if !p.ValidateScopes(client, scopes) {
        p.Logger.Debug("Invalid scopes", zap.String("clientId", clientId))
        return nil, errors.New("invalid scopes")
    }

    return &AccessToken{
        AccessToken: p.GenerateAccessToken(client, scopes),
        TokenType: "Bearer",
        ExpiresIn: client.AccessTokenExpiryTimeSeconds,
        RefreshToken: util.GenerateRandomAlphaNumericString(64),
        Scope: scopes,
    }, nil 
}

