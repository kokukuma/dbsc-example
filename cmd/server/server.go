package main

import (
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kouzoh/kokukuma-fido/internal/server"
)

func main() {
	// Simple server for client to connect to
	srv := server.NewServer(nil)

	r := mux.NewRouter()
	r.Use(handlers.CORS(
		handlers.AllowedMethods([]string{"POST", "GET"}),
		handlers.AllowedHeaders([]string{"content-type"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowCredentials(),
	))

	// Serve static files
	fs := http.FileServer(http.Dir("./cmd/client"))
	r.PathPrefix("/").Handler(fs)

	serverAddress := ":8080"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}
