package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
	"github.com/lewks96/knox-am/internal/oauth/internal"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)


type RedisDSSProvider struct {
	RedisClient *redis.Client
	Context     context.Context
    Logger      *zap.Logger
    SubmitChannel chan oauth.StoredSession
    NodeId      int
    Done        chan bool
    PingTicker  *time.Ticker
    ExpiredTokenTicker  *time.Ticker
}

func NewRedisDSSProvider(nodeId int) (*RedisDSSProvider, error) {
	redisHost := os.Getenv("DSS_REDIS_HOST")
	redisPort := os.Getenv("DSS_REDIS_PORT")
	redisPassword := os.Getenv("DSS_REDIS_PASSWORD")
	redisDB := os.Getenv("DSS_REDIS_DB")
    redisUseTLS := os.Getenv("DSS_REDIS_USE_TLS")

	redisDBInt, err := strconv.Atoi(redisDB)
	if err != nil {
		redisDBInt = 0
	}

    tslConfig := tls.Config{
        MinVersion: tls.VersionTLS12,
    }

    opt := redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Password: redisPassword,
		DB:       redisDBInt,
	};
    if redisUseTLS == "true" {
        opt.TLSConfig = &tslConfig
    }

    Logger, _ := zap.NewProduction()
    Context := context.Background()
    RedisClient := redis.NewClient(&opt)

	err = RedisClient.Ping(Context).Err()
	if err != nil {
		Logger.Error("Failed to connect to Redis", zap.Error(err))
		return nil, err
	}

    Logger.Info("Connected to Redis")
    provider := &RedisDSSProvider{
        RedisClient: RedisClient,
        Context: Context,
        Logger: Logger,
        SubmitChannel: make(chan oauth.StoredSession, 1000),
        NodeId: nodeId,
        Done: make(chan bool),
        PingTicker: time.NewTicker(10 * time.Second),
        ExpiredTokenTicker: time.NewTicker(30 * time.Second),
    }
    return provider, nil
}

func (r *RedisDSSProvider) AttachToStore() error {
    r.Logger.Debug("Attaching to Redis store")
    err := r.Ping()
    if err != nil {
        r.Logger.Error("Failed to ping Redis server", zap.Error(err))
        return errors.New("failed to ping Redis server")
    }
   
    res := r.RedisClient.Get(r.Context, fmt.Sprintf("node-attached-%d", r.NodeId))
    if res.Val() == "true" {
        return errors.New("node with provided ID is already attached to Redis Store")
    }

    e := r.RedisClient.Set(r.Context, fmt.Sprintf("node-attached-%d", r.NodeId), "true", 0)
    if e.Err() != nil {
        r.Logger.Error("Failed to set node-attached key", zap.Error(e.Err()))
        return errors.New("failed to set node-attached key")
    }
    
    // goroutines to handle session submissions and redis pinging
	go func() {
		for {
			accessSession := <-r.SubmitChannel
			serialazedSession, _ := json.Marshal(accessSession)
			r.RedisClient.Set(r.Context, "session-"+accessSession.AccessToken, serialazedSession, 0)
		}
	}()

    go func() {
        for {
            select {
            case <-r.Done:
                r.Logger.Info("Stopping ping ticker")
                return
            case <-r.PingTicker.C:
                err := r.Ping()
                if err != nil {
                    r.Logger.Error("Failed to ping Redis server", zap.Error(err))
                }
                r.Logger.Debug("Pinged Redis server")
            }
        }
    }()

    go func() {
        for {
            select {
            case <-r.Done:
                r.Logger.Info("Stopping expired token ticker")
                return
            case <-r.ExpiredTokenTicker.C:
                r.CleanOldTokens()
            }
        }
    }()

    return nil
}

func (r *RedisDSSProvider) DetachFromStore() error {
    r.Done <- true
    r.Logger.Info("Detaching from Redis store")
    res := r.RedisClient.Get(r.Context, fmt.Sprintf("node-attached-%d", r.NodeId))
    if res.Val() == "false" {
        return errors.New("node with provided ID is already detached from Redis Store")
    }

    e := r.RedisClient.Set(r.Context, fmt.Sprintf("node-attached-%d", r.NodeId), "false", 0)
    if e.Err() != nil {
        r.Logger.Error("Failed to set node-attached key", zap.Error(e.Err()))
        return errors.New("failed to set node-attached key")
    }

    return nil
}

func (r *RedisDSSProvider) GetSession(accessToken string) (oauth.StoredSession, error) {
    sessionKey := "session-" + accessToken
    r.Logger.Info("Getting session", zap.String("sessionKey", sessionKey))
    res := r.RedisClient.Get(r.Context, sessionKey)
    if res.Val() == "" {
        r.Logger.Error("Failed to get session", zap.String("accessToken", accessToken))
        return oauth.StoredSession{}, errors.New("session does not exist in store")
    }

    var storedSession oauth.StoredSession
    err := json.Unmarshal([]byte(res.Val()), &storedSession)
    if err != nil {
        r.Logger.Error("Failed to unmarshal session", zap.Error(err))
        return oauth.StoredSession{}, err
    }

    return storedSession, nil
}

func (r *RedisDSSProvider) SaveSession(session oauth.StoredSession) error {
    r.SubmitChannel <- session
    return nil
}

func (r *RedisDSSProvider) DeleteSession(accessToken string) error {
    r.Logger.Debug("Deleting session", zap.String("accessToken", accessToken))
    _, e := r.GetSession(accessToken)
    if e != nil {
        r.Logger.Error("Failed to get session", zap.Error(e))
        return errors.New("session does not exist in store")
    }

    sessionKey := "session-" + accessToken
    err := r.RedisClient.Del(r.Context, sessionKey)
    if err.Err() != nil {
        r.Logger.Error("Failed to delete session", zap.Error(err.Err()))
        return err.Err()
    }
	return nil
}

func (r *RedisDSSProvider) Flush() (int, error) {
    if r.NodeId != 0 {
        return 0, errors.New("only the master node can flush the database")
    }
     
    keys, err := r.RedisClient.Keys(r.Context, "session-*").Result()
    if err != nil {
        r.Logger.Error("Failed to get keys from Redis", zap.Error(err))
        return 0, err
    }

    // delete all keys in the database starting with "session-"
    for _, key := range keys {
        err := r.RedisClient.Del(r.Context, key)
        if err.Err() != nil {
            r.Logger.Error("Failed to delete key from Redis", zap.Error(err.Err()))
            return 0, err.Err()
        }
    }
    return len(keys), nil
}

func (r *RedisDSSProvider) Ping() error {
    err := r.RedisClient.Ping(r.Context).Err()
    if err != nil {
        r.Logger.Error("Failed to ping Redis server", zap.Error(err))
        return err
    }
    return nil
}

func (r *RedisDSSProvider) CleanOldTokens() {
    // rely on redis expiry to clean up old tokens 
    keys, err := r.RedisClient.Keys(r.Context, "session-*").Result()
    if err != nil {
        r.Logger.Error("Failed to get keys from Redis", zap.Error(err))
        return
    }
    r.Logger.Debug("Cleaning old expired tokens", zap.Int("count", len(keys)))
}


