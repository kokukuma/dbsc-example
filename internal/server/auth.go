package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Maximum age of a session in seconds (30 minutes)
const sessionMaxAge = 18000

// Maximum age of a DBSC challenge in seconds (5 minutes)
const dbscChallengeMaxAge = 300

// generateSessionID creates a secure random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

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

// generateDbscChallenge creates a secure random challenge for DBSC
func generateDbscChallenge() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
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

// verifyDbscAuthCookie checks if the auth_cookie is valid for the given username
func (s *Server) verifyDbscAuthCookie(r *http.Request, username string) (hasDbscCookie bool, isValid bool) {
	authCookie, err := r.Cookie("auth_cookie")
	if err != nil || authCookie.Value == "" {
		return false, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	deviceBoundSessionId, exists := s.authTokenToDeviceSession[authCookie.Value]
	if !exists {
		log.Printf("Auth cookie exists but is not mapped to any device bound session")
		return true, false
	}

	session, sessionExists := s.sessions[deviceBoundSessionId]
	if sessionExists && session.Username == username && time.Now().Before(session.ExpiresAt) {
		log.Printf("DBSC protected session for user: %s", username)
		return true, true
	}

	log.Printf("Device bound session invalid or expired")
	return true, false
}

// setCookie sets a cookie with standard security parameters
func setCookie(w http.ResponseWriter, r *http.Request, name string, value string, maxAge int, sameSiteMode http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: sameSiteMode,
		Secure:   r.TLS != nil || sameSiteMode == http.SameSiteNoneMode, // Always secure for SameSite=None
	})
}

// clearCookie clears a cookie by setting its MaxAge to -1
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
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

// hashString creates a SHA-256 hash of the input string
// NOTE: This is NOT suitable for password storage! Use bcrypt/argon2 in production
func hashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// createDbscChallenge generates a new DBSC challenge for the given username
// Returns challengeId, challenge object, and error if any
func (s *Server) createDbscChallenge(username string) (string, DbscChallenge, error) {
	// Generate a random challenge
	challenge, err := generateDbscChallenge()
	if err != nil {
		return "", DbscChallenge{}, err
	}

	// Generate challenge ID for tracking
	challengeId, err := generateSessionID()
	if err != nil {
		return "", DbscChallenge{}, err
	}

	// Create challenge object
	now := time.Now()
	dbscChallenge := DbscChallenge{
		Challenge: challenge,
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(dbscChallengeMaxAge) * time.Second),
	}

	// Store in server's challenge map
	s.mu.Lock()
	s.dbscChallenges[challengeId] = dbscChallenge
	s.mu.Unlock()

	return challengeId, dbscChallenge, nil
}

// setDbscChallengeCookie sets the DBSC challenge cookie
func setDbscChallengeCookie(w http.ResponseWriter, r *http.Request, challengeId string) {
	setCookie(w, r, "dbsc_challenge", challengeId, dbscChallengeMaxAge, http.SameSiteNoneMode)
}

// getAndVerifyDbscChallenge retrieves and verifies the DBSC challenge from the request
// Returns challengeId, challenge object, and error if any
func (s *Server) getAndVerifyDbscChallenge(r *http.Request) (string, DbscChallenge, error) {
	cookie, err := r.Cookie("dbsc_challenge")
	if err != nil || cookie.Value == "" {
		return "", DbscChallenge{}, fmt.Errorf("no DBSC challenge cookie found")
	}

	challengeId := cookie.Value

	s.mu.RLock()
	challenge, exists := s.dbscChallenges[challengeId]
	s.mu.RUnlock()

	if !exists {
		return "", DbscChallenge{}, fmt.Errorf("challenge not found: %s", challengeId)
	}

	// Check if challenge has expired
	if time.Now().After(challenge.ExpiresAt) {
		s.mu.Lock()
		delete(s.dbscChallenges, challengeId)
		s.mu.Unlock()
		return "", DbscChallenge{}, fmt.Errorf("challenge expired: %s", challengeId)
	}

	return challengeId, challenge, nil
}

// clearDbscChallenge clears the DBSC challenge from the server and client
func (s *Server) clearDbscChallenge(w http.ResponseWriter, challengeId string) {
	s.mu.Lock()
	delete(s.dbscChallenges, challengeId)
	s.mu.Unlock()

	clearCookie(w, "dbsc_challenge")
}

// createDeviceBoundSession creates a new device bound session for a user and maps an auth token to it
// Returns deviceBoundSessionId, authToken, and error if any
func (s *Server) createDeviceBoundSession(username string) (string, string, error) {
	// Create a device bound session ID
	deviceBoundSessionId, err := generateSessionID()
	if err != nil {
		return "", "", fmt.Errorf("error generating device bound session ID: %v", err)
	}

	// Generate an auth token for the session
	authToken, err := generateSessionID()
	if err != nil {
		return "", "", fmt.Errorf("error generating auth token: %v", err)
	}

	// Create a server-side device bound session
	now := time.Now()
	session := Session{
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(sessionMaxAge) * time.Second),
	}

	// Store session and auth token mapping
	s.mu.Lock()
	s.sessions[deviceBoundSessionId] = session
	s.authTokenToDeviceSession[authToken] = deviceBoundSessionId
	s.mu.Unlock()

	log.Printf("[DBSC] Created device bound session for user %s: %s", username, deviceBoundSessionId[:10]+"...")
	return deviceBoundSessionId, authToken, nil
}

// updateDeviceBoundSession updates an existing device bound session and creates a new auth token for it
// Returns new authToken and error if any
func (s *Server) updateDeviceBoundSession(deviceBoundSessionId string, session Session) (string, error) {
	// Generate a new auth token
	newAuthToken, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("error generating new auth token: %v", err)
	}

	// Update the device bound session
	now := time.Now()
	session.ExpiresAt = now.Add(time.Duration(sessionMaxAge) * time.Second)

	s.mu.Lock()
	// Update device bound session
	s.sessions[deviceBoundSessionId] = session

	// Map the auth token to the device bound session ID
	s.authTokenToDeviceSession[newAuthToken] = deviceBoundSessionId

	// Remove any old auth tokens for this device bound session
	for authToken, sid := range s.authTokenToDeviceSession {
		if sid == deviceBoundSessionId && authToken != newAuthToken {
			delete(s.authTokenToDeviceSession, authToken)
		}
	}
	s.mu.Unlock()

	log.Printf("[DBSC] Updated device bound session: %s", deviceBoundSessionId[:10]+"...")
	return newAuthToken, nil
}

// cookieMaxAge defines the lifetime of auth cookies (10 minutes as recommended in the DBSC spec)
const cookieMaxAge = 600

// setAuthCookie sets the auth cookie for a device bound session
func setAuthCookie(w http.ResponseWriter, r *http.Request, authToken string) {
	setCookie(w, r, "auth_cookie", authToken, cookieMaxAge, http.SameSiteNoneMode)
}

// getAuthCookieAttributes returns the string representation of cookie attributes
// This ensures consistent cookie attributes between cookie setting and DBSC response
func getAuthCookieAttributes() string {
	return "Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None"
}

// 関数はdbsc_protocol.goに移動しました

// logRequest logs full HTTP request details for DBSC operations
func logRequest(prefix string, r *http.Request) {
	log.Printf("===== [DBSC] %s REQUEST =====", prefix)
	log.Printf("Method: %s, Path: %s", r.Method, r.URL.Path)
	log.Printf("User-Agent: %s", r.UserAgent())
	log.Printf("Remote Address: %s", r.RemoteAddr)

	// Log all headers
	log.Printf("--- Headers ---")
	for name, values := range r.Header {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}

	// Log cookies
	log.Printf("--- Cookies ---")
	for _, cookie := range r.Cookies() {
		log.Printf("  %s: %s", cookie.Name, cookie.Value)
	}
}

// logResponse logs HTTP response details for DBSC operations
func logResponse(prefix string, w http.ResponseWriter, status int, responseBody interface{}, sessionInfo map[string]string) {
	log.Printf("===== [DBSC] %s RESPONSE =====", prefix)
	log.Printf("Status: %d", status)

	// Log response headers
	log.Printf("--- Headers ---")
	for name, values := range w.Header() {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}

	// Log response body if present
	if responseBody != nil {
		responseJSON, err := json.MarshalIndent(responseBody, "", "  ")
		if err == nil {
			log.Printf("--- Body ---")
			log.Printf("%s", string(responseJSON))
		}
	}

	// Log session summary if provided
	if len(sessionInfo) > 0 {
		log.Printf("--- Summary ---")
		for key, value := range sessionInfo {
			// Truncate values that might be too long
			if len(value) > 50 && !strings.Contains(key, "User") {
				value = value[:50] + "..."
			}
			log.Printf("%s: %s", key, value)
		}
	}

	log.Printf("=====================================")
}
