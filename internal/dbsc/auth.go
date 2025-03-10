package dbsc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Maximum age of a DBSC challenge in seconds (5 minutes)
const ChallengeMaxAge = 300

// CookieMaxAge defines the lifetime of auth cookies (10 minutes as recommended in the DBSC spec)
const CookieMaxAge = 600

// DeviceBoundSessionMaxAge defines the lifetime of device bound sessions (7 days)
// This allows maintaining device binding for longer periods while still using short-lived auth cookies
const DeviceBoundSessionMaxAge = 604800 // 7 days in seconds

// SessionManager handles DBSC session management
type SessionManager struct {
	// Maps challengeId to Challenge
	challenges map[string]Challenge
	// Maps deviceBoundSessionId to Session
	sessions map[string]Session
	// Maps authToken to deviceBoundSessionId
	authTokenToSession map[string]string
	mu                 sync.RWMutex
}

// Session represents a user session
type Session struct {
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewSessionManager creates a new DBSC session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		challenges:         make(map[string]Challenge),
		sessions:           make(map[string]Session),
		authTokenToSession: make(map[string]string),
	}
}

// GenerateChallenge creates a secure random challenge for DBSC
func GenerateChallenge() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// VerifyAuthCookie checks if the auth_cookie is valid for the given username
func (sm *SessionManager) VerifyAuthCookie(r *http.Request, username string, cookieName string) (hasDbscCookie bool, isValid bool) {
	authCookie, err := r.Cookie(cookieName)
	if err != nil || authCookie.Value == "" {
		return false, false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	deviceBoundSessionId, exists := sm.authTokenToSession[authCookie.Value]
	if !exists {
		log.Printf("Auth cookie exists but is not mapped to any device bound session")
		return true, false
	}

	session, sessionExists := sm.sessions[deviceBoundSessionId]
	if sessionExists && session.Username == username && time.Now().Before(session.ExpiresAt) {
		log.Printf("DBSC protected session for user: %s", username)
		return true, true
	}

	log.Printf("Device bound session invalid or expired")
	return true, false
}

// CreateChallenge generates a new DBSC challenge for the given username
// Returns challengeId, challenge object, and error if any
func (sm *SessionManager) CreateChallenge(username string) (string, Challenge, error) {
	// Generate a random challenge
	challenge, err := GenerateChallenge()
	if err != nil {
		return "", Challenge{}, err
	}

	// Generate challenge ID for tracking
	challengeId, err := GenerateSessionID()
	if err != nil {
		return "", Challenge{}, err
	}

	// Create challenge object
	now := time.Now()
	dbscChallenge := Challenge{
		Challenge: challenge,
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(ChallengeMaxAge) * time.Second),
	}

	// Store in server's challenge map
	sm.mu.Lock()
	sm.challenges[challengeId] = dbscChallenge
	sm.mu.Unlock()

	return challengeId, dbscChallenge, nil
}

// SetChallengeCookie sets the DBSC challenge cookie
func SetChallengeCookie(w http.ResponseWriter, r *http.Request, challengeId string) {
	SetCookie(w, r, "dbsc_challenge", challengeId, ChallengeMaxAge, http.SameSiteNoneMode)
}

// GetAndVerifyChallenge retrieves and verifies the DBSC challenge from the request
// Returns challengeId, challenge object, and error if any
func (sm *SessionManager) GetAndVerifyChallenge(r *http.Request) (string, Challenge, error) {
	cookie, err := r.Cookie("dbsc_challenge")
	if err != nil || cookie.Value == "" {
		return "", Challenge{}, fmt.Errorf("no DBSC challenge cookie found")
	}

	challengeId := cookie.Value

	sm.mu.RLock()
	challenge, exists := sm.challenges[challengeId]
	sm.mu.RUnlock()

	if !exists {
		return "", Challenge{}, fmt.Errorf("challenge not found: %s", challengeId)
	}

	// Check if challenge has expired
	if time.Now().After(challenge.ExpiresAt) {
		sm.mu.Lock()
		delete(sm.challenges, challengeId)
		sm.mu.Unlock()
		return "", Challenge{}, fmt.Errorf("challenge expired: %s", challengeId)
	}

	return challengeId, challenge, nil
}

// ClearChallenge clears the DBSC challenge from the server and client
func (sm *SessionManager) ClearChallenge(w http.ResponseWriter, challengeId string) {
	sm.mu.Lock()
	delete(sm.challenges, challengeId)
	sm.mu.Unlock()

	ClearCookie(w, "dbsc_challenge")
}

// CreateDeviceBoundSession creates a new device bound session for a user and maps an auth token to it
// Returns deviceBoundSessionId, authToken, and error if any
func (sm *SessionManager) CreateDeviceBoundSession(username string) (string, string, error) {
	// Create a device bound session ID
	deviceBoundSessionId, err := GenerateSessionID()
	if err != nil {
		return "", "", fmt.Errorf("error generating device bound session ID: %v", err)
	}

	// Generate an auth token for the session
	authToken, err := GenerateSessionID()
	if err != nil {
		return "", "", fmt.Errorf("error generating auth token: %v", err)
	}

	// Create a server-side device bound session with long-term expiration
	now := time.Now()
	session := Session{
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(DeviceBoundSessionMaxAge) * time.Second),
	}

	// Store session and auth token mapping
	sm.mu.Lock()
	sm.sessions[deviceBoundSessionId] = session
	sm.authTokenToSession[authToken] = deviceBoundSessionId
	sm.mu.Unlock()

	log.Printf("[DBSC] Created device bound session for user %s: %s (valid for %d days)",
		username, deviceBoundSessionId[:10]+"...", DeviceBoundSessionMaxAge/86400)
	return deviceBoundSessionId, authToken, nil
}

// UpdateDeviceBoundSession updates an existing device bound session and creates a new auth token for it
// Returns new authToken and error if any
func (sm *SessionManager) UpdateDeviceBoundSession(deviceBoundSessionId string, session Session) (string, error) {
	// Generate a new auth token
	newAuthToken, err := GenerateSessionID()
	if err != nil {
		return "", fmt.Errorf("error generating new auth token: %v", err)
	}

	// Extend the device bound session expiration
	now := time.Now()
	session.ExpiresAt = now.Add(time.Duration(DeviceBoundSessionMaxAge) * time.Second)

	sm.mu.Lock()
	// Update device bound session
	sm.sessions[deviceBoundSessionId] = session

	// Map the auth token to the device bound session ID
	sm.authTokenToSession[newAuthToken] = deviceBoundSessionId

	// Remove any old auth tokens for this device bound session
	for authToken, sid := range sm.authTokenToSession {
		if sid == deviceBoundSessionId && authToken != newAuthToken {
			delete(sm.authTokenToSession, authToken)
		}
	}
	sm.mu.Unlock()

	log.Printf("[DBSC] Updated device bound session: %s (extended for %d days)",
		deviceBoundSessionId[:10]+"...", DeviceBoundSessionMaxAge/86400)
	return newAuthToken, nil
}

// GetSession retrieves a session by deviceBoundSessionId
func (sm *SessionManager) GetSession(deviceBoundSessionId string) (Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[deviceBoundSessionId]
	return session, exists
}

// SetAuthCookie sets the auth cookie for a device bound session
func SetAuthCookie(w http.ResponseWriter, r *http.Request, authToken string, cookieName string) {
	// Set the auth cookie with short-term expiration
	SetCookie(w, r, cookieName, authToken, CookieMaxAge, http.SameSiteNoneMode)
	log.Printf("[DBSC] Set auth cookie with short-term expiration (%d minutes)", CookieMaxAge/60)
}

// GetAuthCookieAttributes returns the string representation of cookie attributes
// This ensures consistent cookie attributes between cookie setting and DBSC response
func GetAuthCookieAttributes() string {
	return fmt.Sprintf("Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=None", CookieMaxAge)
}

// Helper functions

// GenerateSessionID creates a secure random session ID
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetCookie sets a cookie with standard security parameters
func SetCookie(w http.ResponseWriter, r *http.Request, name string, value string, maxAge int, sameSiteMode http.SameSite) {
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

// ClearCookie clears a cookie by setting its MaxAge to -1
func ClearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}
