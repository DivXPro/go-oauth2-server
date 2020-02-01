package cmd

import (
	"github.com/RichardKnop/go-fixtures"
)

// LoadData loads fixtures
func LoadData(paths []string, configBackend string) error {
	cnf, db, redis, err := initConfigDB(true, false, configBackend)
	if err != nil {
		return err
	}
	defer db.Close()
	defer redis.Close()
	return fixtures.LoadFiles(paths, db.DB(), cnf.Database.Type)
}
