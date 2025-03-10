package main

import (
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kokukuma/dbsc-example/internal/server"
)

func main() {
	// Create server
	srv := server.NewServer(nil)

	r := mux.NewRouter()
	r.Use(handlers.CORS(
		handlers.AllowedMethods([]string{"POST", "GET", "OPTIONS"}),
		handlers.AllowedHeaders([]string{
			"content-type",
			"sec-session-challenge",
			"sec-session-response",
			"sec-session-id",
		}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowCredentials(),
		handlers.ExposedHeaders([]string{
			"sec-session-registration",
			"sec-session-challenge",
		}),
	))

	// API routes
	r.HandleFunc("/", srv.HandleHome).Methods("GET")
	r.HandleFunc("/login", srv.HandleLogin).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/logout", srv.HandleLogout).Methods("GET")

	// DBSC endpoints
	r.HandleFunc("/securesession/startsession", srv.HandleDbscStartSession).Methods("POST", "OPTIONS")
	r.HandleFunc("/securesession/refresh", srv.HandleDbscRefreshSession).Methods("POST", "OPTIONS")

	// Serve static files
	fs := http.FileServer(http.Dir("./cmd/client"))
	r.PathPrefix("/").Handler(fs)

	serverAddress := ":8080"
	log.Println("Starting DBSC server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}