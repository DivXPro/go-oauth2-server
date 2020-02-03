package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/models"
)

// AccessTokenResponse ...
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// IntrospectResponse ...
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Name      string `json:"name,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresAt int    `json:"exp,omitempty"`
}

// NewAccessTokenResponse ...
func NewAccessTokenResponse(accessToken *models.OauthAccessToken, refreshToken *models.OauthRefreshToken, lifetime int, theTokenType string, jwt string) (*AccessTokenResponse, error) {
	response := &AccessTokenResponse{
		AccessToken: accessToken.Token,
		ExpiresIn:   lifetime,
		TokenType:   theTokenType,
		Scope:       accessToken.Scope,
	}
	if jwt != "" {
		response.IDToken = jwt
	}
	if refreshToken != nil {
		response.RefreshToken = refreshToken.Token
	}
	return response, nil
}

func NewJWTResponse(jwk string, lifetime int, theTokenType string, scope string) *AccessTokenResponse {
	response := &AccessTokenResponse{
		AccessToken: jwk,
	}
	return response
}
