package database

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

func InitDB(file string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		return nil, err
	}

	// SQL Tables
	queries := []string{
		`CREATE TABLE IF NOT EXISTS
      users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL);`,
		`CREATE TABLE IF NOT EXISTS 
        passwords (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          username TEXT NOT NULL,
          password TEXT NOT NULL,
          FOREIGN KEY (user_id)
          REFERENCES users (id)
        );`,
	}

	for _, query := range queries {
		_, err = db.Exec(query)
		if err != nil {
			return nil,
				fmt.Errorf("failed to create table: %v", err)
		}
	}
	return db, nil
}
