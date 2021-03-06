package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/util/routes"
	"github.com/gorilla/mux"
)

const (
	tokenResource     = "token"
	tokensPath         = "/" + tokenResource
	introspectResource = "introspect"
	introspectPath     = "/" + introspectResource
	revokePath         = "/revoke"
	jwksPath           = "/.well-known/jwks.json"
)

// RegisterRoutes registers route handlers for the oauth service
func (s *Service) RegisterRoutes(router *mux.Router, prefix string) {
	subRouter := router.PathPrefix(prefix).Subrouter()
	routes.AddRoutes(s.GetRoutes(), subRouter)
}

// GetRoutes returns []routes.Route slice for the oauth service
func (s *Service) GetRoutes() []routes.Route {
	return []routes.Route{
		{
			Name:        "oauth_token",
			Method:      "POST",
			Pattern:     tokensPath,
			HandlerFunc: s.tokensHandler,
		},
		{
			Name:        "oauth_introspect",
			Method:      "POST",
			Pattern:     introspectPath,
			HandlerFunc: s.introspectHandler,
		},
		{
			Name:        "revoke",
			Method:      "POST",
			Pattern:     revokePath,
			HandlerFunc: s.revokeHandler,
		},
		{
			Name:        "jwks",
			Method:      "GET",
			Pattern:     jwksPath,
			HandlerFunc: s.jwksHandler,
		},
	}
}
