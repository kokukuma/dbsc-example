package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// HandleLogin handles user login authentication
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Log the request method
	log.Printf("Login request received with method: %s", r.Method)

	// Check for existing session
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		// We have a session cookie, validate it
		valid, username := s.validateSession(cookie.Value)
		if valid {
			log.Printf("Valid session found for user: %s", username)
			// Extend session
			s.extendSession(cookie.Value)
			// Set updated cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    cookie.Value,
				Path:     "/",
				MaxAge:   sessionMaxAge,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   r.TLS != nil, // Set secure flag if HTTPS
			})
			// Redirect to home page
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		} else {
			log.Printf("Invalid or expired session cookie found")
		}
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

	// Check if this is a form submission
	if err := r.ParseForm(); err == nil {
		username := r.FormValue("username")
		password := r.FormValue("current-password")

		if username != "" && password != "" {
			log.Printf("Form login attempt: username=%s, password=%s", username, password)

			// Authenticate the user
			authenticated := false
			s.mu.RLock()
			for _, user := range s.users {
				if user.Username == username && user.Password == password {
					authenticated = true
					log.Printf("Form authentication successful for user: %s - Will initiate DBSC flow", username)
					break
				}
			}
			s.mu.RUnlock()

			if authenticated {
				// Start DBSC flow - Generate a challenge
				challenge, err := generateDbscChallenge()
				if err != nil {
					log.Printf("Error generating DBSC challenge: %v", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				// Generate challenge ID for tracking
				challengeId, err := generateSessionID()
				if err != nil {
					log.Printf("Error generating challenge ID: %v", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				// Store the challenge
				now := time.Now()
				dbscChallenge := DbscChallenge{
					Challenge: challenge,
					Username:  username,
					CreatedAt: now,
					ExpiresAt: now.Add(time.Duration(dbscChallengeMaxAge) * time.Second),
				}

				s.mu.Lock()
				s.dbscChallenges[challengeId] = dbscChallenge
				s.mu.Unlock()

				// Set HTTP-only cookie with challenge ID
				http.SetCookie(w, &http.Cookie{
					Name:     "dbsc_challenge",
					Value:    challengeId,
					Path:     "/",
					MaxAge:   dbscChallengeMaxAge,
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Secure:   r.TLS != nil,
				})

				// Add the Sec-Session-Registration header
				headerValue := fmt.Sprintf("(ES256 RS256);path=\"/securesession/startsession\";challenge=\"%s\"", challenge)
				w.Header().Set("Sec-Session-Registration", headerValue)

				log.Printf("[DBSC] Login (form) endpoint initiating DBSC flow - User: %s, Challenge: %s, ChallengeId: %s",
					username, challenge[:10]+"...", challengeId[:10]+"...")

				// Create a new login session
				loginSessionId, err := s.createSession(username)
				if err != nil {
					log.Printf("Failed to create session: %v", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				// Set session cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    loginSessionId,
					Path:     "/",
					MaxAge:   sessionMaxAge,
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Secure:   r.TLS != nil, // Set secure flag if HTTPS
				})

				// Redirect to home page after successful login
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			} else {
				log.Printf("Form authentication failed for user: %s", username)
				// Authentication failed, send error back to login page
				http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
				return
			}
		}
	}

	// If not a form submission, try to parse as JSON API request
	var loginReq LoginRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginReq); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Log received credentials (don't do this in production!)
	log.Printf("API login attempt: username=%s, password=%s", loginReq.Username, loginReq.Password)

	// Authenticate the user
	authenticated := false
	s.mu.RLock()
	for _, user := range s.users {
		if user.Username == loginReq.Username && user.Password == loginReq.Password {
			authenticated = true
			log.Printf("API authentication successful for user: %s", loginReq.Username)
			break
		}
	}
	s.mu.RUnlock()

	if authenticated {
		// Start DBSC flow - Generate a challenge
		challenge, err := generateDbscChallenge()
		if err != nil {
			log.Printf("Error generating DBSC challenge: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate challenge ID for tracking
		challengeId, err := generateSessionID()
		if err != nil {
			log.Printf("Error generating challenge ID: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store the challenge
		now := time.Now()
		dbscChallenge := DbscChallenge{
			Challenge: challenge,
			Username:  loginReq.Username,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Duration(dbscChallengeMaxAge) * time.Second),
		}

		s.mu.Lock()
		s.dbscChallenges[challengeId] = dbscChallenge
		s.mu.Unlock()

		// Set HTTP-only cookie with challenge ID
		http.SetCookie(w, &http.Cookie{
			Name:     "dbsc_challenge",
			Value:    challengeId,
			Path:     "/",
			MaxAge:   dbscChallengeMaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
		})

		// Add the Sec-Session-Registration header
		headerValue := fmt.Sprintf("(ES256 RS256);path=\"/securesession/startsession\";challenge=\"%s\"", challenge)
		w.Header().Set("Sec-Session-Registration", headerValue)

		log.Printf("[DBSC] Login endpoint initiating DBSC flow - User: %s, Challenge: %s, ChallengeId: %s",
			loginReq.Username, challenge[:10]+"...", challengeId[:10]+"...")

		// Also create a temporary login session (would be replaced by DBSC session)
		loginSessionId, err := s.createSession(loginReq.Username)
		if err != nil {
			log.Printf("Failed to create session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    loginSessionId,
			Path:     "/",
			MaxAge:   sessionMaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil, // Set secure flag if HTTPS
		})
	} else {
		log.Printf("API authentication failed for user: %s", loginReq.Username)
	}

	// Create response
	resp := LoginResponse{
		Success: authenticated,
	}

	if authenticated {
		resp.Message = "Login successful"
	} else {
		resp.Message = "Invalid username or password"
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if !authenticated {
		w.WriteHeader(http.StatusUnauthorized)
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Sending response: %s", string(respData))
	w.Write(respData)
}

// HandleHome serves the home page, checking for user session according to DBSC protocol
func (s *Server) HandleHome(w http.ResponseWriter, r *http.Request) {
	var username string
	var loggedIn bool
	var hasDbscCookie bool
	var dbscCookieValid bool

	// First check for session_id to get the username reference
	var loginSessionId string
	sessionCookie, sessionErr := r.Cookie("session_id")
	if sessionErr == nil && sessionCookie.Value != "" {
		loginSessionId = sessionCookie.Value
		// Validate the session
		valid, sessionUsername := s.validateSession(loginSessionId)
		if valid {
			// We have a valid session to identify the user - mark as logged in
			username = sessionUsername
			loggedIn = true

			// Extend the session regardless of DBSC status
			s.extendSession(loginSessionId)

			// Update session_id cookie expiration
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    loginSessionId,
				Path:     "/",
				MaxAge:   sessionMaxAge,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   r.TLS != nil,
			})

			// Check for DBSC auth_cookie (separate from login status)
			authCookie, authErr := r.Cookie("auth_cookie")
			if authErr == nil && authCookie.Value != "" {
				hasDbscCookie = true

				// Verify that this auth_cookie is mapped to a valid device bound session
				s.mu.RLock()
				deviceBoundSessionId, exists := s.authToLoginSession[authCookie.Value]
				if exists {
					// Check if that device bound session exists and is valid
					session, sessionExists := s.sessions[deviceBoundSessionId]
					if sessionExists && session.Username == username && time.Now().Before(session.ExpiresAt) {
						dbscCookieValid = true
						log.Printf("DBSC protected session for user: %s", username)
					} else {
						log.Printf("Device bound session invalid or expired")
						dbscCookieValid = false
					}
				} else {
					log.Printf("Auth cookie exists but is not mapped to any device bound session")
					dbscCookieValid = false
				}
				s.mu.RUnlock()
				// Browser with native DBSC support will automatically refresh if needed
			} else {
				log.Printf("No auth_cookie found but session_id is valid. Session not protected by DBSC.")
				// Browser with native DBSC support will automatically establish protection
			}
		}
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

	// Clear the session_id cookie by setting MaxAge to -1
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Also clear the DBSC auth_cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_cookie",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})

	// And clear any challenge cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "dbsc_challenge",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
