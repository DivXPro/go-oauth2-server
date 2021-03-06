package config

import (
	"fmt"
	"gopkg.in/ini.v1"
	"os"
)

var (
	path = "init.ini"
)

type initFileBackend struct{}

func (b *initFileBackend) InitConfigBackend() {
	// Overwrite default values with environment variables if they are set
	if os.Getenv("INIT_PATH") != "" {
		path = os.Getenv("INIT_PATH")
	}
}

// LoadConfig gets the config data from INI file and unmarshal it to the config object
func (b *initFileBackend) LoadConfig() (*Config, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}

	// Unmarshal the config JSON into the cnf object
	newCnf := new(Config)

	newCnf.Database.Type = cfg.Section("database").Key("type").String()
	newCnf.Database.Host = cfg.Section("database").Key("host").String()
	newCnf.Database.Port, _ = cfg.Section("database").Key("port").Int()
	newCnf.Database.User = cfg.Section("database").Key("user").String()
	newCnf.Database.Password = cfg.Section("database").Key("password").String()
	newCnf.Database.DatabaseName = cfg.Section("database").Key("name").String()

	newCnf.IsDevelopment, _ = cfg.Section("option").Key("debug").Bool()
	newCnf.Port, _ = cfg.Section("option").Key("port").Int()

	newCnf.Oauth.Jwt, _ = cfg.Section("oauth").Key("jwt").Bool()
	newCnf.Oauth.Issuer = cfg.Section("oauth").Key("issuer").String()
	newCnf.Oauth.PasswordSalt = cfg.Section("oauth").Key("password_salt").String()
	newCnf.Oauth.PasswordSecret = cfg.Section("oauth").Key("password_secret").String()
	newCnf.Oauth.AccessTokenLifetime, _ = cfg.Section("oauth").Key("expires_in").Int()
	newCnf.Oauth.RefreshTokenLifetime = newCnf.Oauth.AccessTokenLifetime * 2
	return newCnf, nil
}

// RefreshConfig sets config through the pointer so config actually gets refreshed
func (b *initFileBackend) RefreshConfig(newCnf *Config) {
	*Cnf = *newCnf
}
