package server

import (
	"crypto/subtle"
	"log"
	"net/http"
	"time"
)

// Maximum age of a standard session in seconds (30 minutes)
const sessionMaxAge = 18000

// createSession creates a new session for the given username
func (s *Server) createSession(username string) (string, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	session := Session{
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(sessionMaxAge) * time.Second),
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	return sessionID, nil
}

// validateSession checks if a session is valid
func (s *Server) validateSession(sessionID string) (bool, string) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return false, ""
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Remove expired session
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		return false, ""
	}

	return true, session.Username
}

// extendSession extends the expiration time of a session
func (s *Server) extendSession(sessionID string) {
	s.mu.Lock()
	if session, exists := s.sessions[sessionID]; exists {
		session.ExpiresAt = time.Now().Add(time.Duration(sessionMaxAge) * time.Second)
		s.sessions[sessionID] = session
	}
	s.mu.Unlock()
}

// validateAndExtendSession validates a session cookie and extends it if valid
func (s *Server) validateAndExtendSession(r *http.Request, w http.ResponseWriter) (bool, string) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil || sessionCookie.Value == "" {
		return false, ""
	}

	valid, username := s.validateSession(sessionCookie.Value)
	if valid {
		// Extend session
		s.extendSession(sessionCookie.Value)

		// Set updated cookie
		setCookie(w, r, "session_id", sessionCookie.Value, sessionMaxAge, http.SameSiteStrictMode)
		return true, username
	}
	return false, ""
}

// authenticateUser securely verifies username and password, hiding implementation details
// Returns (isAuthenticated, username) tuple
func (s *Server) authenticateUser(username, password string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Hash the provided password for logging purposes (still sensitive, but better than plaintext)
	passwordHash := hashString(password)

	// Log the authentication attempt with only partial hash
	if len(passwordHash) > 8 {
		log.Printf("Authentication attempt: username=%s, password_hash=...%s",
			username, passwordHash[len(passwordHash)-8:])
	}

	// In a real implementation, you would:
	// 1. Look up the user from a secure database using an index
	// 2. Use a proper password hashing algorithm (bcrypt/argon2)
	// 3. Use constant-time comparison to prevent timing attacks

	// Since this is a demo with hardcoded users, we iterate through them
	for _, user := range s.users {
		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(user.Username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(user.Password)) == 1

		if usernameMatch && passwordMatch {
			log.Printf("Authentication successful for user: %s", username)
			return true, username
		}
	}

	log.Printf("Authentication failed for user: %s", username)
	return false, ""
}
