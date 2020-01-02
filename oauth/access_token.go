package oauth

import (
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
)

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
	// 删除Redis缓存中的token

	tokens := make([]models.OauthAccessToken, 0)
	if err := query.Where("expires_at <= ?", time.Now()).Find(tokens).Error; err != nil {
		tx.Rollback() // rollback the transaction
		return nil, err
	}

	if len(tokens) > 0 {
		for _, t := range tokens {
			if err := s.RemoveAccessTokenRedis(t.Token); err != nil {
				tx.Rollback()
				return nil, err
			}
		}
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
