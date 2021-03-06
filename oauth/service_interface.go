package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/session"
	"github.com/RichardKnop/go-oauth2-server/util/routes"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"gopkg.in/square/go-jose.v2"
)

// ServiceInterface defines exported methods
type ServiceInterface interface {
	// Exported methods
	GetConfig() *config.Config
	GetRoutes() []routes.Route
	RegisterRoutes(router *mux.Router, prefix string)
	ClientExists(clientID string) bool
	FindClientByClientID(clientID string) (*models.OauthClient, error)
	CreateClient(clientID, secret, redirectURI string, tenantID string) (*models.OauthClient, error)
	CreateClientTx(tx *gorm.DB, clientID, secret, redirectURI string, tenantID string) (*models.OauthClient, error)
	AuthClient(clientID, secret string) (*models.OauthClient, error)
	UserExists(username string, tenantID string) bool
	FindUserByUsername(username string) (*models.OauthUser, error)
	FindUserByAccountAndTenantID(account string, tenantID string) (*models.OauthUser, error)
	FindUserByPhoneAndTenantID(phone string, tenantID string) (*models.OauthUser, error)
	AuthUser(username, thePassword string, tenantID string) (*models.OauthUser, error)
	GetScope(requestedScope string) (string, error)
	GetDefaultScope() string
	ScopeExists(requestedScope string) bool
	Login(client *models.OauthClient, user *models.OauthUser, scope string) (*models.OauthAccessToken, *models.OauthRefreshToken, error)
	GrantAuthorizationCode(client *models.OauthClient, user *models.OauthUser, expiresIn int, redirectURI, scope string) (*models.OauthAuthorizationCode, error)
	GrantAccessToken(client *models.OauthClient, user *models.OauthUser, expiresIn int, scope string) (*models.OauthAccessToken, error)
	GetOrCreateRefreshToken(client *models.OauthClient, user *models.OauthUser, expiresIn int, scope string) (*models.OauthRefreshToken, error)
	GetValidRefreshToken(token string, client *models.OauthClient) (*models.OauthRefreshToken, error)
	Authenticate(token string) (*models.OauthAccessToken, error)
	NewIntrospectResponseFromAccessToken(accessToken *models.OauthAccessToken) (*IntrospectResponse, error)
	NewIntrospectResponseFromRefreshToken(refreshToken *models.OauthRefreshToken) (*IntrospectResponse, error)
	ClearUserTokens(userSession *session.UserSession)
	Close()
	JWKs() (*jose.JSONWebKeySet, error)
}
