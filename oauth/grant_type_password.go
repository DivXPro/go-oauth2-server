package oauth

import (
	"errors"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

var (
	// ErrInvalidUsernameOrPassword ...
	ErrInvalidUsernameOrPassword = errors.New("Invalid username or password")
)

func (s *Service) passwordGrant(grantDTO *GrantDTO, client *models.OauthClient) (*AccessTokenResponse, error) {
	// Get the scope string
	scope, err := s.GetScope(grantDTO.Scope)
	if err != nil {
		return nil, err
	}

	// Authenticate the user
	// username is account or phone
	user, err := s.AuthUser(grantDTO.Username, grantDTO.Password, grantDTO.TenantID)
	if err != nil {
		// For security reasons, return a general error message
		return nil, ErrInvalidUsernameOrPassword
	}

	// Log in the user
	// oauth access token
	accessToken, refreshToken, err := s.Login(client, user, scope)
	if err != nil {
		return nil, err
	}

	var jwt string
	if s.cnf.Oauth.Jwt {
		jwt, err = s.GrantJWT(user, s.cnf.Oauth.AccessTokenLifetime, scope, accessToken.Token)
		if err != nil {
			return nil, err
		}
	}

	// Create response
	accessTokenResponse, err := NewAccessTokenResponse(
		accessToken,
		refreshToken,
		s.cnf.Oauth.AccessTokenLifetime,
		tokentypes.Bearer,
		jwt,
	)
	if err != nil {
		return nil, err
	}
	return accessTokenResponse, nil
}
