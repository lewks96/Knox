package oauth

import (
	"os"
	"strconv"
    "errors"
	"github.com/lewks96/knox-am/internal/oauth/internal"
	"go.uber.org/zap"
)

type MemcacheDSSProvider struct {
	Sessions map[string]oauth.StoredSession
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
    session, ok := p.Sessions[accessToken]
    if !ok {
        return session, errors.New("session does not exist in store")
    }
    return session, nil
}

func (p *MemcacheDSSProvider) SaveSession(session oauth.StoredSession) error {

    p.Sessions[session.AccessToken] = session
    return nil
}

func (p *MemcacheDSSProvider) DeleteSession(accessToken string) error {
    p.Logger.Debug("Deleting session", zap.String("accessToken", accessToken))
    _, e := p.GetSession(accessToken)
    if e != nil {
        p.Logger.Error("Failed to get session", zap.Error(e))
        return errors.New("session does not exist in store")
    }

    delete(p.Sessions, accessToken)
    return nil
}

func (p *MemcacheDSSProvider) Flush() (int, error) {
    p.Sessions = make(map[string]oauth.StoredSession)
    return 0, nil
}

func (p *MemcacheDSSProvider) Ping() error {

    return nil
}


