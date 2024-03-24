package oauth

import (
	"errors"
	"github.com/lewks96/knox-am/internal/oauth/internal"
	"go.uber.org/zap"
	"os"
	"strconv"
	"sync"
	"time"
)

type MemcacheDSSProvider struct {
	Sessions map[string]oauth.StoredSession
	mu       sync.Mutex
	Logger   *zap.Logger
}

func NewMemcacheDSSProvider(nodeId int) (*MemcacheDSSProvider, error) {
	preallocateSize := os.Getenv("DSS_MEMCACHE_PREALLOCATE")
	preallocateSizeInt := 0

	if preallocateSize != "" {
		parsed, err := strconv.ParseInt(preallocateSize, 10, 32)
		if err != nil {
			preallocateSizeInt = 0
		}
		preallocateSizeInt = int(parsed)
	}

	provider := &MemcacheDSSProvider{
		Sessions: make(map[string]oauth.StoredSession, preallocateSizeInt),
	}
	return provider, nil
}

func (p *MemcacheDSSProvider) AttachToStore() error {
	p.Logger, _ = zap.NewProduction()
	p.Logger.Info("Attached to Memcache store")
	return nil
}

func (p *MemcacheDSSProvider) DetachFromStore() error {
	p.Logger.Info("Detached from Memcache store")
	return nil
}

func (p *MemcacheDSSProvider) GetSession(accessToken string) (oauth.StoredSession, error) {
	p.Logger.Debug("Getting session", zap.String("accessToken", accessToken))
	p.mu.Lock()
	session, ok := p.Sessions[accessToken]
	p.mu.Unlock()
	if !ok {
		return session, errors.New("session does not exist in store")
	}
	return session, nil
}

func (p *MemcacheDSSProvider) SaveSession(session oauth.StoredSession) error {
	p.Logger.Debug("Saving session", zap.String("accessToken", session.AccessToken))
	p.mu.Lock()
	p.Sessions[session.AccessToken] = session
	p.mu.Unlock()
	return nil
}

func (p *MemcacheDSSProvider) DeleteSession(accessToken string) error {
	p.Logger.Debug("Deleting session", zap.String("accessToken", accessToken))
	_, e := p.GetSession(accessToken)
	if e != nil {
		p.Logger.Error("Failed to get session", zap.Error(e))
		return errors.New("session does not exist in store")
	}
	p.mu.Lock()
	delete(p.Sessions, accessToken)
	p.mu.Unlock()
	return nil
}

func (p *MemcacheDSSProvider) Flush() (int, error) {
	p.mu.Lock()
	len := len(p.Sessions)
	p.Logger.Debug("Flushing Memcache store", zap.Int("numSessions", len))
	p.Sessions = make(map[string]oauth.StoredSession)
	p.mu.Unlock()
	return len, nil
}

func (p *MemcacheDSSProvider) Ping() error {
	return nil
}

func (p *MemcacheDSSProvider) CleanOldTokens(clients map[string]oauth.OAuthClientConfiguration) {
	p.Logger.Debug("Cleaning old tokens")
	p.mu.Lock()
	for token, session := range p.Sessions {
		clientExpiryTime := clients[session.ClientId].AccessTokenExpiryTimeSeconds
		if session.IssuedAt+int64(clientExpiryTime) < time.Now().Unix() {
			p.Logger.Debug("Cleaning old token", zap.String("token", token))
			delete(p.Sessions, token)
		}
	}
	p.mu.Unlock()
}
