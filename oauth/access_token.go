package oauth

import (
	"crypto/rsa"
	"github.com/RichardKnop/go-oauth2-server/oauth/jwt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
	"log"
	"time"

	"errors"
	"github.com/RichardKnop/go-oauth2-server/models"
)

var (
	// ErrJwkPrivateKeyNotFound ...
	ErrJwkPrivateKeyNotFound = errors.New("jwk private key not found")
	// ErrJwkPublicKeyNotFound ...
	ErrJwkPublicKeyNotFound = errors.New("jwk public key not found")
	// ErrInvalidToken ...
	ErrInvalidToken = errors.New("invalid token")
)

func (s *Service) GrantJWT(user *models.OauthUser, expiresIn int, scope string, accessToken string) (string, error) {
	if privateJwk, err := s.getJWKPrivateKey(); err != nil {
		return "", err
	} else {
		// get jwt private key
		privateKey := privateJwk.Key.(*rsa.PrivateKey)
		publicJwk := privateJwk.Public()
		issueAt := time.Now().Unix()
		notBefore := int64(0)
		expiry := time.Now().Add(time.Duration(expiresIn) * time.Second).Unix()

		var claims = &jwt.Claims{
			StandardClaims: jwtgo.StandardClaims{
				ExpiresAt: expiry,
				Id:        accessToken,
				IssuedAt:  issueAt,
				Issuer:    s.cnf.Oauth.Issuer,
				NotBefore: notBefore,
				Subject:   user.ID,
			},
			TenantID: user.TenantID,
			Scope: scope,
		}
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
		token.Header["kid"] = publicJwk.KeyID
		log.Println(publicJwk.KeyID)
		return token.SignedString(privateKey)
	}
}

func (s *Service) getJWKPrivateKey() (*jose.JSONWebKey, error) {
	var oauthJwks []models.OauthJwk
	notFound := s.db.Where("sid = ?", "oauth-jwk").Find(&oauthJwks).RecordNotFound()
	// Not found
	if notFound {
		return nil, ErrJwkPrivateKeyNotFound
	}
	for _, oauthJwk := range oauthJwks {
		if oauthJwk.KID[0:7] == "private" {
			data := []byte(oauthJwk.KeyData)
			var key = &jose.JSONWebKey{}
			if err := key.UnmarshalJSON(data); err != nil {
				return nil, err
			}
			return key, nil
		}
	}
	return nil, ErrJwkPrivateKeyNotFound
}

func (s *Service) JWKs() (*jose.JSONWebKeySet, error) {
	key, err := s.getJWKPublicKey()
	if err == nil {
		return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*key}}, nil
	}
	return nil, err
}

func (s *Service) getJWKPublicKey() (*jose.JSONWebKey, error) {
	var oauthJwks []models.OauthJwk
	notFound := s.db.Where("sid = ?", "oauth-jwk").Find(&oauthJwks).RecordNotFound()

	// Not found
	if notFound {
		return nil, ErrJwkPublicKeyNotFound
	}
	for _, oauthJwk := range oauthJwks {
		if oauthJwk.KID[0:6] == "public" {
			data := []byte(oauthJwk.KeyData)
			var key = &jose.JSONWebKey{}
			if err := key.UnmarshalJSON(data); err != nil {
				return nil, err
			}
			return key, nil
		}
	}
	return nil, ErrJwkPublicKeyNotFound
}

// GrantAccessToken deletes expired tokens and grants a new access token
func (s *Service) GrantAccessToken(client *models.OauthClient, user *models.OauthUser, expiresIn int, scope string) (*models.OauthAccessToken, error) {
	// Begin a transaction
	tx := s.db.Begin()

	// Delete expired access tokens
	query := tx.Unscoped().Where("client_id = ?", client.ID)
	if user != nil && len([]rune(user.ID)) > 0 {
		query = query.Where("user_id = ?", user.ID)
	} else {
		query = query.Where("user_id IS NULL")
	}

	if err := query.Where("expires_at <= ?", time.Now()).Delete(new(models.OauthAccessToken)).Error; err != nil {
		tx.Rollback() // rollback the transaction
		return nil, err
	}

	// Create a new access token
	accessToken := models.NewOauthAccessToken(client, user, expiresIn, scope)
	if err := tx.Create(accessToken).Error; err != nil {
		tx.Rollback() // rollback the transaction
		return nil, err
	}
	accessToken.Client = client
	accessToken.User = user

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		tx.Rollback() // rollback the transaction
		return nil, err
	}

	// store new token in redis
	s.GrantAccessTokenRedis(accessToken)

	return accessToken, nil
}

func (s *Service) GrantAccessTokenRedis(accessToken *models.OauthAccessToken) (*models.OauthAccessTokenRedis, error) {
	accessTokenRedis := &models.OauthAccessTokenRedis{
		TenantID:  accessToken.TenantID,
		ClientID:  accessToken.ID,
		Token:     accessToken.Token,
		ExpiresAt: accessToken.ExpiresAt,
		Scope:     accessToken.Scope,
		UserID:    accessToken.UserID.String,
	}
	if err := s.redis.Set(accessTokenRedis.Token, accessTokenRedis, time.Since(accessTokenRedis.ExpiresAt)).Err(); err != nil {
		return nil, err
	}
	return accessTokenRedis, nil
}

func (s *Service) revokeToken(token string) error {
	accessToken := &models.OauthAccessToken{}
	notFound := s.db.Where("id = ?", token).First(accessToken).RecordNotFound()
	if notFound {
		freshToken := &models.OauthRefreshToken{}
		notFound = s.db.Where("id = ?", token).First(accessToken).RecordNotFound()
		if notFound {
			return ErrInvalidToken
		}
		s.db.Where("id = ?", freshToken.ID).Delete(models.OauthRefreshToken{})
		return nil
	}
	if err := s.RemoveAccessTokenRedis(token); err != nil {
		return err
	}
	s.db.Where("id = ?", accessToken.ID).Delete(models.OauthAccessToken{})
	return nil
}

func (s *Service) RemoveAccessTokenRedis(token string) error {
	if err := s.redis.Del(token).Err(); err != nil {
		return err
	}
	return nil
}
