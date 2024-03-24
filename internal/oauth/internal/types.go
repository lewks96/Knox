package oauth

type StoredSession struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ClientId     string `json:"clientId"`
	Scopes       string `json:"scopes"`
	IssuedAt     int64  `json:"issuedAt"`
}
