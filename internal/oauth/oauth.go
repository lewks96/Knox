package oauth

import (
	"errors"
	"fmt"
	"github.com/lewks96/knox-am/internal/oauth/internal"
	"github.com/lewks96/knox-am/internal/util"
	"go.uber.org/zap"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
 * @title OAuthProvider
 * @description Contains configuration and methods to provide OAuth services
 */
type OAuthProvider struct {
	Clients               map[string]oauth.OAuthClientConfiguration
	Logger                *zap.Logger
	IsPrimaryNode         bool
	DSSProvider           SessionProvider
	ExpiredTokenTicker    *time.Ticker
	OldSessionCleanerDone chan bool
}

type AccessToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (p *OAuthProvider) Initialize() error {
	p.Logger, _ = zap.NewProduction()
	p.Logger.Debug("We're the primary node, flushing and setting global-running to true")
	providerType := os.Getenv("DSS_PROVIDER")

	switch providerType {
	case "redis":
		p.Logger.Info("Using RedisDSSProvider")
		provider, err := NewRedisDSSProvider(0)
		if err != nil {
			p.Logger.Error("Failed to create RedisDSSProvider", zap.Error(err))
			return err
		}
		err = provider.AttachToStore()
		if err != nil {
			p.Logger.Error("Failed to attach to Redis store", zap.Error(err))
			return err
		}
		p.DSSProvider = provider
	case "memcache":
		p.Logger.Info("Using MemcacheDSSProvider")
		provider, err := NewMemcacheDSSProvider(0)
		if err != nil {
			p.Logger.Error("Failed to create RedisDSSProvider", zap.Error(err))
			return err
		}
		err = provider.AttachToStore()
		if err != nil {
			p.Logger.Error("Failed to attach to Redis store", zap.Error(err))
			return err
		}
		p.DSSProvider = provider
	default:
		p.Logger.Error("Invalid DSS provider type", zap.String("type", providerType))
		return errors.New("invalid DSS provider type")
	}

	err := p.DSSProvider.Ping()
	if err != nil {
		p.Logger.Error("Failed to ping DSS provider", zap.Error(err))
		return err
	}

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

	cleanupIntervalStr := os.Getenv("DSS_CLEANUP_INTERVAL_SECONDS")
	cleanupIntervalSeconds := int64(5 * 60)
	if cleanupIntervalStr != "" {
		cleanupIntervalSeconds, err = strconv.ParseInt(cleanupIntervalStr, 10, 64)
		if err != nil {
			p.Logger.Error("Failed to parse DSS_CLEANUP_INTERVAL_SECONDS, Using 5 minutes as fallback", zap.Error(err))
		}
	}

	p.Logger.Info(fmt.Sprintf("Scheduled cleanup interval: %d seconds", cleanupIntervalSeconds))
	p.Logger.Info("OAuthProvider initialized from clients.json")
	p.Logger.Info("Number of clients loaded: ", zap.Int("count", len(p.Clients)))

	p.ExpiredTokenTicker = time.NewTicker(time.Duration(cleanupIntervalSeconds) * time.Second)
	p.OldSessionCleanerDone = make(chan bool)

	go func() {
		for {
			select {
			case <-p.OldSessionCleanerDone:
				p.Logger.Info("Stopping expired token ticker")
				return
			case <-p.ExpiredTokenTicker.C:
				p.Logger.Info("Cleaning old tokens")
				p.DSSProvider.CleanOldTokens(p.Clients)
				p.Logger.Info("Finished cleaning old tokens")
			}
		}
	}()

	return nil
}

// Dev function to revoke all sessions
func (p *OAuthProvider) RevokeAllSessions() (int, error) {
	return p.DSSProvider.Flush()
}

func (p *OAuthProvider) Close() {
	p.Logger.Debug("Closing OAuthProvider")
	if p.IsPrimaryNode {
		p.Logger.Debug("We're the primary node, flushing Redis")
	}
	err := p.DSSProvider.DetachFromStore()
	if err != nil {
		p.Logger.Error("Failed to detach from DSS provider", zap.Error(err))
	}
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

func (p *OAuthProvider) generateSession(client oauth.OAuthClientConfiguration, scopes string) oauth.StoredSession {
	// generate timestap
	ts := time.Now().Unix()

	accessToken := p.GenerateOpaqueToken()
	refreshToken := p.GenerateOpaqueToken()
	accessSession := oauth.StoredSession{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientId:     client.ClientId,
		Scopes:       scopes,
		IssuedAt:     ts,
	}
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

func (p *OAuthProvider) DeleteSession(accessToken string) error {
	err := p.DSSProvider.DeleteSession(accessToken)
	return err
}

func (p *OAuthProvider) GetTokenInfo(accessToken string) (TokenInfo, error) {
	session, err := p.DSSProvider.GetSession(accessToken)
	if err != nil {
		p.Logger.Error("Failed to get session from DSS provider", zap.Error(err))
		return TokenInfo{}, err
	}

	client, ok := p.Clients[session.ClientId]
	if !ok {
		p.Logger.Debug("Client does not exist", zap.String("clientId", session.ClientId))
		return TokenInfo{}, errors.New("client does not exist")
	}

	expiration := session.IssuedAt + int64(client.AccessTokenExpiryTimeSeconds)
	exp := int(expiration - time.Now().Unix())
	if exp <= 0 {
		p.Logger.Info("Access token has expired", zap.String("accessToken", accessToken))
		p.DeleteSession(accessToken)
		return TokenInfo{}, errors.New("access token has expired or been revoked")
	}

	return TokenInfo{
		AccessToken:  session.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(expiration - time.Now().Unix()),
		RefreshToken: session.RefreshToken,
		Scope:        session.Scopes,
		IssuedAt:     session.IssuedAt,
		ClientId:     session.ClientId,
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
	p.DSSProvider.SaveSession(accessSession)

	return &AccessToken{
		AccessToken:  accessSession.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    client.AccessTokenExpiryTimeSeconds,
		RefreshToken: accessSession.RefreshToken,
		Scope:        scopes,
	}, nil
}
