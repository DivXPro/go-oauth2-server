package jwt

import (
	jwtgo "github.com/dgrijalva/jwt-go"
)

type Claims struct {
	jwtgo.StandardClaims
	Scope string `json:"scope,omitempty"`
	TenantID string `json:"tenantId, omitempty"`
}
