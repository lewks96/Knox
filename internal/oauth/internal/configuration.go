package oauth

import (
    "encoding/json"
    "io"
    "os"
)

/*
 * @title OAuthClientConfiguration
 * @description Configuration for an OAuth client
 */
type OAuthClientConfiguration struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
    AllowedGrants []string `json:"allowedGrants"`
    IssueRefreshToken bool `json:"issueRefreshToken"`
    TokenType string `json:"tokenType"`
    AccessTokenExpiryTimeSeconds int `json:"accessTokenExpiryTimeSeconds"`
    RefreshTokenExpiryTimeSeconds int `json:"refreshTokenExpiryTimeSeconds"`
    RedirectUris []string `json:"redirectUris"`
    Scopes []string `json:"scopes"`
}

func LoadClientsFromConfigFile() ([]OAuthClientConfiguration, error) {
    file, err := os.Open("./config/clients.json")
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    contents, err := io.ReadAll(file)
    if err != nil {
        return nil, err
    }

    var clients []OAuthClientConfiguration
    err = json.Unmarshal(contents, &clients)
    if err != nil {
        return nil, err
    }
    return clients, nil 
}
