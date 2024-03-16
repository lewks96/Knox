package oauth

import (
	"context"
	"encoding/json"
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
		p.Logger.Info("Another node is running, we're not the primary node")
		p.IsPrimaryNode = false
		err := p.pullClientsFromRedis()
		if err != nil {
			return err
		}
	} else {
		p.Logger.Info("We're the primary node, flushing and setting global-running to true")
		p.RedisClient.FlushDB(p.Context)
		p.RedisClient.Set(p.Context, "global-running", "true", 0)
		p.IsPrimaryNode = true

		clients, err := oauth.LoadClientsFromConfigFile()
		if err != nil {
			p.Logger.Error("Failed to load clients from config file", zap.Error(err))
			return err
		}
		p.Clients = make(map[string]oauth.OAuthClientConfiguration)
		for _, client := range clients {
			p.Clients[client.ClientId] = client
		}

		p.Logger.Info("OAuthProvider initialized from clients.json")
		p.Logger.Info("Number of clients loaded: ", zap.Int("count", len(p.Clients)))

		for _, client := range clients {
			serialazedClient, _ := json.Marshal(client)
			p.RedisClient.Set(p.Context, "oauth2"+client.ClientId, serialazedClient, 0)
			p.Logger.Info("Client added to Redis", zap.String("clientId", client.ClientId))
		}
	}

	return nil
}

func (p *OAuthProvider) Close() {
	p.Logger.Info("Closing OAuthProvider")
    if p.IsPrimaryNode {
        p.Logger.Info("We're the primary node, deleting global-running key")
        p.RedisClient.Del(p.Context, "global-running")
    }
	p.RedisClient.Close()
}
