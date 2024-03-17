package oauth

import (
	"context"
	"encoding/json"
	"errors"
	//"github.com/google/uuid"
	"github.com/lewks96/knox-am/internal/oauth/internal"
	"github.com/lewks96/knox-am/internal/util"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"strings"
	"time"
)

/*
 * @title OAuthProvider
 * @description Contains configuration and methods to provide OAuth services
 */
type OAuthProvider struct {
	Clients            map[string]oauth.OAuthClientConfiguration
	RedisClient        *redis.Client
	Context            context.Context
	Logger             *zap.Logger
	IsPrimaryNode      bool
	RedisSubmitChannel chan redisAccessSession
}

type AccessToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type redisAccessSession struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ClientId     string `json:"clientId"`
	Scopes       string `json:"scopes"`
	IssuedAt     int64  `json:"issuedAt"`
}

func (p *OAuthProvider) pullClientsFromRedis() error {
	clients := p.RedisClient.Keys(p.Context, "oauth2*")
	p.Logger.Debug("Number of clients loaded from Redis", zap.Int("count", len(clients.Val())))
	p.Clients = make(map[string]oauth.OAuthClientConfiguration)
	for _, client := range clients.Val() {
		serialazedClient := p.RedisClient.Get(p.Context, client)
		var clientConfig oauth.OAuthClientConfiguration
		err := json.Unmarshal([]byte(serialazedClient.Val()), &clientConfig)
		if err != nil {
			p.Logger.Error("Failed to unmarshal client from Redis", zap.Error(err))
			return err
		}
		p.Clients[clientConfig.ClientId] = clientConfig
		p.Logger.Debug("Client added to OAuthProvider", zap.String("clientId", clientConfig.ClientId))
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

    p.RedisSubmitChannel = make(chan redisAccessSession)

    go func() {
        for {
            accessSession := <-p.RedisSubmitChannel
            serialazedSession, _ := json.Marshal(accessSession)
            p.RedisClient.Set(p.Context, "session-"+accessSession.AccessToken, serialazedSession, 0)
        }
    }()



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

func (p *OAuthProvider) AuthenticateClient(client oauth.OAuthClientConfiguration, clientSecret string) bool {
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
	for _, scope := range scopeSplit {
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

func (p *OAuthProvider) GenerateOpaqueToken() string {
	//sessionId := strings.ReplaceAll(uuid.New().String(), "-", "")
	//sessionId := util.GenerateRandomAlphaNumericString(32)
	//random := util.GenerateRandomAlphaNumericString(32)
	//token := strings.ToLower(sessionId + random)
	//token := sessionId + random
	return util.GenerateRandomAlphaNumericString(64)
}

func (p *OAuthProvider) generateSession(client oauth.OAuthClientConfiguration, scopes string) redisAccessSession {
	// generate timestap
	ts := time.Now().Unix()
    
	accessToken := p.GenerateOpaqueToken()
	refreshToken := p.GenerateOpaqueToken()
	accessSession := redisAccessSession{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientId:     client.ClientId,
		Scopes:       scopes,
		IssuedAt:     ts,
	}

	//serialazedSession, _ := json.Marshal(accessSession)
	//p.RedisClient.Set(p.Context, "session-"+accessToken, serialazedSession, 0)
	return accessSession
}

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IssuedAt     int64  `json:"issued_at"`
	ClientId     string `json:"client_id"`
}

func (p *OAuthProvider) GetTokenInfo(accessToken string) (TokenInfo, error) {
	session := p.RedisClient.Get(p.Context, "session-"+accessToken)
	if session.Val() == "" {
		p.Logger.Debug("Session does not exist", zap.String("accessToken", accessToken))
		return TokenInfo{}, errors.New("invalid access token")
	}

	var accessSession redisAccessSession
	err := json.Unmarshal([]byte(session.Val()), &accessSession)
	if err != nil {
		p.Logger.Error("Failed to unmarshal access session", zap.Error(err))
		return TokenInfo{}, err
	}

	client, ok := p.Clients[accessSession.ClientId]
	if !ok {
		p.Logger.Debug("Client does not exist", zap.String("clientId", accessSession.ClientId))
		return TokenInfo{}, errors.New("client does not exist")
	}

	return TokenInfo{
		AccessToken:  accessSession.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    client.AccessTokenExpiryTimeSeconds,
		RefreshToken: accessSession.RefreshToken,
		Scope:        accessSession.Scopes,
		IssuedAt:     accessSession.IssuedAt,
		ClientId:     accessSession.ClientId,
	}, nil
}

func (p *OAuthProvider) AuthorizeForGrantClientCredentials(clientId string, clientSecret string, scopes string) (*AccessToken, error) {
	client, ok := p.Clients[clientId]
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

	accessSession := p.generateSession(client, scopes)
    go func() {
        p.RedisSubmitChannel <- accessSession
    }()

	return &AccessToken{
		AccessToken:  accessSession.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    client.AccessTokenExpiryTimeSeconds,
		RefreshToken: accessSession.RefreshToken,
		Scope:        scopes,
	}, nil
}
