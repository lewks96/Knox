package oauth

import (
	"github.com/lewks96/knox-am/internal/oauth/internal"
)

type SessionProvider interface {
	AttachToStore() error
	DetachFromStore() error
	GetSession(accessToken string) (oauth.StoredSession, error)
	SaveSession(session oauth.StoredSession) error
	DeleteSession(accessToken string) error
	Flush() (int, error)
	Ping() error
	CleanOldTokens()
}
