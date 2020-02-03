package oauth

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

var (
	// ErrInvalidGrantType ...
	ErrInvalidGrantType = errors.New("Invalid grant type")
	// ErrInvalidClientIDOrSecret ...
	ErrInvalidClientIDOrSecret = errors.New("Invalid client ID or secret")
)

type GrantDTO struct {
	GrantType    string `json:"grant_type"`
	Password     string
	Username     string
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	Secret       string
	Scope        string
	Code         string
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token"`
}

// tokensHandler handles all OAuth 2.0 grant types
// (POST /v1/oauth/tokens)
func (s *Service) tokensHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the form so r.Form becomes available
	//if err := r.ParseForm(); err != nil {
	//	response.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}
	var grantDTO GrantDTO
	if err = json.Unmarshal(body, &grantDTO); err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	grantType := grantDTO.GrantType

	// Map of grant types against handler functions
	grantTypes := map[string]func(grantDTO *GrantDTO, client *models.OauthClient) (*AccessTokenResponse, error){
		"authorization_code": s.authorizationCodeGrant,
		"password":           s.passwordGrant,
		"client_credentials": s.clientCredentialsGrant,
		"refresh_token":      s.refreshTokenGrant,
	}

	// Check the grant type
	grantHandler, ok := grantTypes[grantType]
	if !ok {
		response.Error(w, ErrInvalidGrantType.Error(), http.StatusBadRequest)
		return
	}

	// Client auth
	client, err := s.GetClient(grantDTO.ClientID)
	if err != nil {
		response.UnauthorizedError(w, err.Error())
		return
	}

	// Grant processing
	resp, err := grantHandler(&grantDTO, client)
	if err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	// Write response to json
	response.WriteJSON(w, resp, 200)
}

// introspectHandler handles OAuth 2.0 introspect request
// (POST /v1/oauth/introspect)
func (s *Service) introspectHandler(w http.ResponseWriter, r *http.Request) {
	// Client auth
	client, err := s.basicAuthClient(r)
	if err != nil {
		response.UnauthorizedError(w, err.Error())
		return
	}

	// Introspect the token
	resp, err := s.introspectToken(r, client)
	if err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	// Write response to json
	response.WriteJSON(w, resp, 200)
}

// logout handles
// (POST /v1/oauth/revoke)
func (s *Service) revokeHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	token := r.PostFormValue("token")
	if err := s.revokeToken(token); err != nil {
		response.WriteJSON(w, err.Error(), getErrStatusCode(err))
	}
	response.WriteJSON(w, nil, 200)
}

// Get client credentials from basic auth and try to authenticate client
func (s *Service) basicAuthClient(r *http.Request) (*models.OauthClient, error) {
	// Get client credentials from basic auth
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		return nil, ErrInvalidClientIDOrSecret
	}

	// Authenticate the client
	client, err := s.AuthClient(clientID, secret)
	if err != nil {
		// For security reasons, return a general error message
		return nil, ErrInvalidClientIDOrSecret
	}

	return client, nil
}

func (s *Service) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if jwks, err := s.JWKs(); err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
	} else {
		response.WriteJSON(w, jwks, 200)
	}
}
