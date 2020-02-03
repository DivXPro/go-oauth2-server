package oauth

import (
	"errors"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

const (
	// AccessTokenHint ...
	AccessTokenHint = "access_token"
	// RefreshTokenHint ...
	RefreshTokenHint = "refresh_token"
	// Jwt
	JwtHint = "jwt"
)

var (
	// ErrTokenMissing ...
	ErrTokenMissing = errors.New("Token missing")
	// ErrTokenHintInvalid ...
	ErrTokenHintInvalid = errors.New("Invalid token hint")
)

func (s *Service) introspectToken(r *http.Request, client *models.OauthClient) (*IntrospectResponse, error) {
	// Parse the form so r.Form becomes available
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	// Get token from the query
	token := r.Form.Get("token")
	if token == "" {
		return nil, ErrTokenMissing
	}

	// Get token type hint from the query
	tokenTypeHint := r.Form.Get("token_type_hint")

	// Default to access token hint
	if tokenTypeHint == "" {
		tokenTypeHint = AccessTokenHint
	}

	switch tokenTypeHint {
	case AccessTokenHint:
		accessToken, err := s.Authenticate(token)
		if err != nil {
			return nil, err
		}
		return s.NewIntrospectResponseFromAccessToken(accessToken)
	case RefreshTokenHint:
		refreshToken, err := s.GetValidRefreshToken(token, client)
		if err != nil {
			return nil, err
		}
		return s.NewIntrospectResponseFromRefreshToken(refreshToken)
	case JwtHint:
		jwt, err := jwt.ParseSigned(token)
		if err != nil {
			return nil, err
		}
		publicKey, err := s.getJWKPublicKey()
		if err != nil {
			return nil, err
		}
		jsonWebToken := make(map[string]interface{})
		if err := jwt.Claims(publicKey, &jsonWebToken); err != nil {
			return nil, err
		}
		accessToken, err := s.Authenticate(jsonWebToken["jti"].(string))
		if err != nil {
			return nil, err
		}
		return s.NewIntrospectResponseFromAccessToken(accessToken)
	default:
		return nil, ErrTokenHintInvalid
	}
}

// NewIntrospectResponseFromAccessToken ...
func (s *Service) NewIntrospectResponseFromAccessToken(accessToken *models.OauthAccessToken) (*IntrospectResponse, error) {
	var introspectResponse = &IntrospectResponse{
		Active:    true,
		Scope:     accessToken.Scope,
		TokenType: tokentypes.Bearer,
		ExpiresAt: int(accessToken.ExpiresAt.Unix()),
	}

	if accessToken.ClientID.Valid {
		client := new(models.OauthClient)
		notFound := s.db.Select("key").First(client, accessToken.ClientID.String).
			RecordNotFound()
		if notFound {
			return nil, ErrClientNotFound
		}
		introspectResponse.ClientID = client.Key
	}

	if accessToken.UserID.Valid {
		user := new(models.OauthUser)
		notFound := s.db.Select("username").Where("id = ?", accessToken.UserID.String).
			First(user, accessToken.UserID.String).RecordNotFound()
		if notFound {
			return nil, ErrUserNotFound
		}
		introspectResponse.Name = user.Name
		introspectResponse.UserID = user.ID
		introspectResponse.TenantID = user.TenantID
	}

	return introspectResponse, nil
}

// NewIntrospectResponseFromRefreshToken ...
func (s *Service) NewIntrospectResponseFromRefreshToken(refreshToken *models.OauthRefreshToken) (*IntrospectResponse, error) {
	var introspectResponse = &IntrospectResponse{
		Active:    true,
		Scope:     refreshToken.Scope,
		TokenType: tokentypes.Bearer,
		ExpiresAt: int(refreshToken.ExpiresAt.Unix()),
	}

	if refreshToken.ClientID.Valid {
		client := new(models.OauthClient)
		notFound := s.db.Select("key").First(client, refreshToken.ClientID.String).
			RecordNotFound()
		if notFound {
			return nil, ErrClientNotFound
		}
		introspectResponse.ClientID = client.Key
	}

	if refreshToken.UserID.Valid {
		user := new(models.OauthUser)
		notFound := s.db.Select("username").Where("id = ?", refreshToken.UserID.String).
			First(user, refreshToken.UserID.String).RecordNotFound()
		if notFound {
			return nil, ErrUserNotFound
		}
		introspectResponse.Name = user.Name
		introspectResponse.UserID = user.ID
		introspectResponse.TenantID = user.TenantID
	}

	return introspectResponse, nil
}
