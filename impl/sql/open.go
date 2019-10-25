package sql

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

// Open the mysql database specified by the dsn string.
func Open(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}

	// MySQL flags that affect storage logic.
	cfg.ClientFoundRows = true // Return number of matching rows instead of rows changed

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}
