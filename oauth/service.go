package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/RichardKnop/go-oauth2-server/oauth/roles"
	"github.com/go-redis/redis/v7"
	"github.com/jinzhu/gorm"
)

// Service struct keeps objects to avoid passing them around
type Service struct {
	cnf          *config.Config
	db           *gorm.DB
	redis        *redis.Client
	allowedRoles []string
}

// NewService returns a new Service instance
func NewService(cnf *config.Config, db *gorm.DB, redisClient *redis.Client) *Service {
	return &Service{
		cnf:          cnf,
		db:           db,
		redis:        redisClient,
		allowedRoles: []string{roles.Superuser, roles.User},
	}
}

// GetConfig returns config.Config instance
func (s *Service) GetConfig() *config.Config {
	return s.cnf
}

// Close stops any running services
func (s *Service) Close() {}
