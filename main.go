package main

import (
	"backend/database"
	"backend/handlers"
	"log"
	"net/http"
)

func main() {
	db, err := database.InitDB("passwords.db")
	if err != nil {
		log.Fatalf("Failed to initialise database: %v", err)
	}
	defer db.Close()

	authHandler := handlers.NewAuthHandler(db)
	passwordHandler := handlers.NewPasswordHandler(db)

	http.HandleFunc("/register", authHandler.Register)
	http.HandleFunc("/login", authHandler.Login)
	http.HandleFunc("/passwords", passwordHandler.HandlePasswords)

	log.Println("Server has started on :8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
