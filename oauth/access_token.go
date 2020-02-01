package oauth

import (
	"crypto/rsa"
	"github.com/RichardKnop/go-oauth2-server/oauth/jwt"
	"github.com/RichardKnop/uuid"
	"gopkg.in/square/go-jose.v2"
	jwt2 "gopkg.in/square/go-jose.v2/jwt"
	"time"

	"errors"
	"github.com/RichardKnop/go-oauth2-server/models"
)

var (
	// ErrJwkPrivateKeyNotFound ...
	ErrJwkPrivateKeyNotFound = errors.New("jwk private key not found")
	// ErrJwkPublicKeyNotFound ...
	ErrJwkPublicKeyNotFound = errors.New("jwk public key not found")
)

func (s *Service) GrantJWT(user *models.OauthUser, expiresIn int, scope string) (string, error) {
	if privateJwk, err := s.getJWKPrivateKey(); err != nil {
		return "", err
	} else {
		// get jwt private key
		privateKey := privateJwk.Key.(rsa.PrivateKey)

		issueAt := jwt2.NumericDate(time.Now().Unix())
		notBefore := jwt2.NumericDate(time.Now().Unix())
		expiry := jwt2.NumericDate(time.Now().Add(time.Duration(expiresIn) * time.Second).Unix())

		var claims = &jwt.StandardClaims{
			Claims: jwt2.Claims{
				Expiry:    &expiry,
				ID:        uuid.New(),
				IssuedAt:  &issueAt,
				Issuer:    "",
				NotBefore: &notBefore,
				Subject:   user.ID,
			},
			Scope: scope,
		}
		return jwt.MakeRSASignedJWT(claims, &privateKey)
	}
}

func (s *Service) getJWKPrivateKey() (*jose.JSONWebKey, error) {
	var oauthJwks []models.OauthJwk
	notFound := models.OauthJWKPreload(s.db).Where("sid = ?", "oauth-jwk").Find(&oauthJwks).RecordNotFound()
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
	notFound := models.OauthJWKPreload(s.db).Where("sid = ?", "oauth-jwk").Find(&oauthJwks).RecordNotFound()
	// Not found
	if notFound {
		return nil, ErrJwkPublicKeyNotFound
	}
	for _, oauthJwk := range oauthJwks {
		if oauthJwk.KID[0:7] == "public" {
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

func (s *Service) RemoveAccessTokenRedis(token string) error {
	if err := s.redis.Del(token).Err(); err != nil {
		return err
	}
	return nil
}
