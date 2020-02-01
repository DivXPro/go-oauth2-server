package models

import (
	"github.com/jinzhu/gorm"
	"time"
)

type OauthJwk struct {
	ID        string    `gorm:"column:id; type:int(10); primary_key"`
	SID       string    `gorm:"column:sid; type:varchar(255)"`
	KID       string    `gorm:"column:kid; type:varchar(255)"`
	KeyData   string    `gorm:"column:key_data; type:text; not null"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (c *OauthJwk) TableName() string {
	return "oauth_jwk"
}

func OauthJWKPreload(db *gorm.DB) *gorm.DB {
	return OauthJWKPreloadWithPrefix(db, "")
}

func OauthJWKPreloadWithPrefix(db *gorm.DB, prefix string) *gorm.DB {
	return db.
		Preload(prefix + "Client").Preload(prefix + "User")
}
