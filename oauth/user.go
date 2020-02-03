package oauth

import (
	"errors"
	"fmt"
	"github.com/RichardKnop/go-oauth2-server/models"
	pass "github.com/RichardKnop/go-oauth2-server/util/password"
)

var (
	// MinPasswordLength defines minimum password length
	MinPasswordLength = 6

	// ErrPasswordTooShort ...
	ErrPasswordTooShort = fmt.Errorf(
		"Password must be at least %d characters long",
		MinPasswordLength,
	)
	// ErrUserNotFound ...
	ErrUserNotFound = errors.New("User not found")
	// ErrInvalidUserPassword ...
	ErrInvalidUserPassword = errors.New("Invalid user password")
	// ErrCannotSetEmptyUsername ...
	ErrCannotSetEmptyUsername = errors.New("Cannot set empty username")
	// ErrUserPasswordNotSet ...
	ErrUserPasswordNotSet = errors.New("User password not set")
	// ErrUsernameTaken ...
	ErrUsernameTaken = errors.New("Username taken")
)

// UserExists returns true if user exists
func (s *Service) UserExists(username string, tenantID string) bool {
	_, err := s.FindUserByUsernameAndTenantID(username, tenantID)
	return err == nil
}

// FindUserByUsername looks up a user by username
func (s *Service) FindUserByUsername(username string) (*models.OauthUser, error) {
	// Usernames are case insensitive
	user := new(models.OauthUser)
	notFound := s.db.Where("username = LOWER(?)", username).
		First(user).RecordNotFound()

	// Not found
	if notFound {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// FindUserByUsernameAndTenantID looks up a user by username and tenantId
func (s *Service) FindUserByUsernameAndTenantID(username string, tenantID string) (*models.OauthUser, error) {
	// Username are case insensitive
	user := new(models.OauthUser)
	notFound := s.db.Where("username = LOWER(?) AND tenant_id = ?", username, tenantID).
		First(user).RecordNotFound()

	// Not found
	if notFound {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// FindUserByUsernameAndTenantID looks up a user by username and tenantId
func (s *Service) FindUserByAccountAndTenantID(account string, tenantID string) (*models.OauthUser, error) {
	// Username are case insensitive
	user := new(models.OauthUser)
	notFound := s.db.Where("account = ? AND tenant_id = ?", account, tenantID).
		First(user).RecordNotFound()

	// Not found
	if notFound {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// FindUserByUsernameAndTenantID looks up a user by username and tenantId
func (s *Service) FindUserByPhoneAndTenantID(phone string, tenantID string) (*models.OauthUser, error) {
	// Username are case insensitive
	user := new(models.OauthUser)
	notFound := s.db.Where("phone = ? AND tenant_id = ?", phone, tenantID).
		First(user).RecordNotFound()

	// Not found
	if notFound {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// AuthUser authenticates user
func (s *Service) AuthUser(username, password string, tenantID string) (*models.OauthUser, error) {
	// Fetch the user
	user, err := s.FindUserByAccountAndTenantID(username, tenantID)
	if err != nil {
		user, err = s.FindUserByPhoneAndTenantID(username, tenantID)
		if err != nil {
			return nil, err
		}
	}

	// Check that the password is set
	if !user.Password.Valid {
		return nil, ErrUserPasswordNotSet
	}

	// Verify the password
	if pass.VerifyPassword2(
		user.Password.String,
		password,
		user.ID,
		s.cnf.Oauth.PasswordSecret,
		s.cnf.Oauth.PasswordSalt,
	) {
		return nil, ErrInvalidUserPassword
	}

	return user, nil
}
