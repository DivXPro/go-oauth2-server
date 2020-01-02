package database

import (
	"fmt"
	"strconv"
	"time"

	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/go-redis/redis/v7"
	"github.com/jinzhu/gorm"

	// Drivers
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/lib/pq"
)

func init() {
	gorm.NowFunc = func() time.Time {
		return time.Now().UTC()
	}
}

// NewDatabase returns a gorm.DB struct, gorm.DB.DB() returns a database handle
// see http://golang.org/pkg/database/sql/#DB
func NewDatabase(cnf *config.Config) (*gorm.DB, error) {
	// Postgres
	if cnf.Database.Type == "postgres" {
		// Connection args
		// see https://godoc.org/github.com/lib/pq#hdr-Connection_String_Parameters
		args := fmt.Sprintf(
			"sslmode=disable host=%s port=%d user=%s password='%s' dbname=%s",
			cnf.Database.Host,
			cnf.Database.Port,
			cnf.Database.User,
			cnf.Database.Password,
			cnf.Database.DatabaseName,
		)

		db, err := gorm.Open(cnf.Database.Type, args)
		if err != nil {
			return db, err
		}

		// Max idle connections
		db.DB().SetMaxIdleConns(cnf.Database.MaxIdleConns)

		// Max open connections
		db.DB().SetMaxOpenConns(cnf.Database.MaxOpenConns)

		// Database logging
		db.LogMode(cnf.IsDevelopment)

		return db, nil
	} else if cnf.Database.Type == "mysql" {
		args := fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s?charset=utf8&parseTime=True&loc=Local",
			cnf.Database.User,
			cnf.Database.Password,
			cnf.Database.Host,
			cnf.Database.Port,
			cnf.Database.DatabaseName,
		)

		db, err := gorm.Open(cnf.Database.Type, args)

		if err != nil {
			return db, err
		}

		// Max idle connections
		db.DB().SetMaxIdleConns(cnf.Database.MaxIdleConns)

		// Max open connections
		db.DB().SetMaxOpenConns(cnf.Database.MaxOpenConns)

		// Database logging
		db.LogMode(cnf.IsDevelopment)
		return db, nil
	}

	// Database type not supported
	return nil, fmt.Errorf("Database type %s not suppported", cnf.Database.Type)
}

func NewRedisClient(cnf *config.Config) *redis.Client {
	redisConfig := cnf.Redis
	client := redis.NewClient(&redis.Options{
		Addr:     redisConfig.Host + ":" + strconv.Itoa(redisConfig.Port),
		Password: redisConfig.Password, // no password set
		DB:       redisConfig.DB,       // use default DB
	})
	return client
}
