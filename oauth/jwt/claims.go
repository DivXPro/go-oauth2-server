package jwt

import (
	"gopkg.in/square/go-jose.v2/jwt"
)

type StandardClaims struct {
	jwt.Claims
	Scope string `json:"scope,omitempty"`
}
