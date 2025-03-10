package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/kokukuma/dbsc-example/internal/dbsc"
)

// HandleLogin handles HTML form-based user login authentication
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Log the request method
	log.Printf("Login page request received with method: %s", r.Method)

	// Check for existing session
	if valid, username := s.validateAndExtendSession(r, w); valid {
		log.Printf("Valid session found for user: %s", username)
		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Handle GET requests to login page
	if r.Method == http.MethodGet {
		// Show the login form
		http.ServeFile(w, r, "./cmd/client/login.html")
		return
	}

	// Only proceed with POST for login
	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form submission
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("current-password")

	if username == "" || password == "" {
		log.Printf("Missing username or password")
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	// Authenticate the user
	authenticated, _ := s.authenticateUser(username, password)

	if !authenticated {
		log.Printf("Form authentication failed for user: %s", username)
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	// Start DBSC flow - Generate a challenge and set cookie
	// Use the DBSC package's session manager to create a challenge
	dbscMgr := s.dbscHandler.GetSessionManager()
	challengeId, challenge, err := dbscMgr.CreateChallenge(username)
	if err != nil {
		log.Printf("Error creating DBSC challenge: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set DBSC challenge cookie
	dbsc.SetChallengeCookie(w, r, challengeId)

	// Add the Sec-Session-Registration header
	dbsc.AddRegistrationHeader(w, challenge.Challenge)

	log.Printf("[DBSC] Login form initiating DBSC flow - User: %s, Challenge: %s, ChallengeId: %s",
		username, challenge.Challenge[:10]+"...", challengeId[:10]+"...")

	// Create a new login session
	loginSessionId, err := s.createSession(username)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	dbsc.SetCookie(w, r, "session_id", loginSessionId, sessionMaxAge, http.SameSiteStrictMode)

	// Redirect to home page after successful login
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleHome serves the home page, checking for user session according to DBSC protocol
func (s *Server) HandleHome(w http.ResponseWriter, r *http.Request) {
	var username string
	var loggedIn bool
	var hasDbscCookie bool
	var dbscCookieValid bool

	// First check for session_id to get the username reference
	valid, sessionUsername := s.validateAndExtendSession(r, w)
	if valid {
		// We have a valid session to identify the user - mark as logged in
		username = sessionUsername
		loggedIn = true

		// Check for DBSC auth_cookie (separate from login status)
		// Use the DBSC package's session manager to verify the auth cookie
		dbscMgr := s.dbscHandler.GetSessionManager()
		hasDbscCookie, dbscCookieValid = dbscMgr.VerifyAuthCookie(r, username, "auth_cookie")

		if !hasDbscCookie {
			log.Printf("No auth_cookie found but session_id is valid. Session not protected by DBSC.")
			// Browser with native DBSC support will automatically establish protection
		}
		// If hasDbscCookie is true, VerifyAuthCookie has already logged the appropriate messages
	}

	// Read the template file
	content, err := os.ReadFile("./cmd/client/index.html")
	if err != nil {
		log.Printf("Error reading index.html: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert to string
	htmlContent := string(content)

	// Replace the user data JSON with actual values
	userData := fmt.Sprintf(`{ "loggedIn": %t, "username": "%s", "hasDbscCookie": %t, "dbscCookieValid": %t }`,
		loggedIn, username, hasDbscCookie, dbscCookieValid)
	htmlContent = strings.Replace(
		htmlContent,
		`{ "loggedIn": false, "username": "" }`,
		userData,
		1,
	)

	// JavaScript auto-refresh removed - using browser's native DBSC implementation

	// Write the modified content
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

// HandleLogout handles user logout
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Check for session cookie
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		// Remove session from server
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()

		log.Printf("User logged out, session removed: %s", cookie.Value)
	}

	// Clear all cookies
	dbsc.ClearCookie(w, "session_id")
	dbsc.ClearCookie(w, "auth_cookie")
	dbsc.ClearCookie(w, "dbsc_challenge")

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
