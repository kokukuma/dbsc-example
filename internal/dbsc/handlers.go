package dbsc

import (
	"crypto/ecdsa"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Handler handles DBSC HTTP requests
type Handler struct {
	sessionManager   *SessionManager
	serverPrivateKey *ecdsa.PrivateKey
	authCookieName   string
}

// NewHandler creates a new DBSC handler
func NewHandler(privateKey *ecdsa.PrivateKey, authCookieName string) *Handler {
	if authCookieName == "" {
		authCookieName = "auth_cookie"
	}

	return &Handler{
		sessionManager:   NewSessionManager(),
		serverPrivateKey: privateKey,
		authCookieName:   authCookieName,
	}
}

// GetSessionManager returns the session manager for the handler
func (h *Handler) GetSessionManager() *SessionManager {
	return h.sessionManager
}

// HandleStartSession handles DBSC session registration
func (h *Handler) HandleStartSession(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	LogRequest("START SESSION", r)

	// This endpoint only handles the response to the Sec-Session-Registration
	// header that was sent during login. It should never send the initial challenge.
	secSessionResponse, err := ParseResponse(r)
	if err != nil {
		log.Printf("[DBSC] Error: %v. The challenge should have been sent during login.", err)
		http.Error(w, "Missing DBSC response", http.StatusBadRequest)
		return
	}

	// Get and verify the DBSC challenge
	challengeId, challenge, err := h.sessionManager.GetAndVerifyChallenge(r)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	// Extract JWT from the Sec-Session-Response header
	clientToken := secSessionResponse
	log.Printf("[DBSC] Processing JWT from Sec-Session-Response: %s", clientToken[:50]+"...")

	// Parse the JWT to extract the payload without verification
	jwtPayload, err := ParseJWT(clientToken)
	if err != nil {
		log.Printf("[DBSC] Error parsing JWT: %v", err)
		http.Error(w, "Invalid JWT format", http.StatusBadRequest)
		return
	}

	// Verify that the challenge is in the jti claim
	if err := ValidateJwtPayload(jwtPayload, challenge); err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Challenge mismatch", http.StatusBadRequest)
		return
	}

	// Extract and convert the public key from the JWT payload
	clientPublicKeyPEM, err := ConvertJWKToPEM(jwtPayload.Key)
	if err != nil {
		log.Printf("[DBSC] Error converting public key from JWT: %v", err)
		http.Error(w, "Invalid public key format", http.StatusBadRequest)
		return
	}

	log.Printf("[DBSC] Extracted public key from JWT: %s", clientPublicKeyPEM[:50]+"...")

	// Set username from the JWT's subject or from the DBSC challenge
	username := jwtPayload.Sub
	if username == "" {
		username = challenge.Username
		log.Printf("[DBSC] No subject in JWT, using username from challenge: %s", username)
	}

	// Create a device bound session and get an auth token
	// Now using the sessionManager's updated method signature (without passing cookieMaxAge)
	deviceBoundSessionId, authToken, err := h.sessionManager.CreateDeviceBoundSession(username)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clear the challenge cookie and remove the challenge from the server
	h.sessionManager.ClearChallenge(w, challengeId)

	// Set auth cookie
	SetAuthCookie(w, r, authToken, h.authCookieName)

	// Create the DBSC session registration response
	response := CreateRegistrationResponse(deviceBoundSessionId, r, h.authCookieName, GetAuthCookieAttributes())

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Log the response information
	sessionInfo := map[string]string{
		"User":                 username,
		"DeviceBoundSessionId": deviceBoundSessionId,
		"AuthToken":            authToken,
	}
	LogResponse("START SESSION", w, http.StatusOK, response, sessionInfo)

	// Send the response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	w.Write(responseJSON)
}

// HandleRefreshSession handles DBSC session refresh
func (h *Handler) HandleRefreshSession(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	LogRequest("REFRESH SESSION", r)

	// Only proceed with POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for device bound session ID in the header
	deviceBoundSessionId, err := GetSessionId(r)
	if err != nil {
		log.Printf("No device bound session ID provided: %v", err)
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get Sec-Session-Response header if present
	secSessionResponse := r.Header.Get("Sec-Session-Response")

	// Verify the device bound session exists
	session, sessionExists := h.sessionManager.GetSession(deviceBoundSessionId)
	if !sessionExists {
		log.Printf("Device bound session not found: %s", deviceBoundSessionId)
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}

	// Check if device bound session has expired
	if time.Now().After(session.ExpiresAt) {
		h.sessionManager.mu.Lock()
		delete(h.sessionManager.sessions, deviceBoundSessionId)
		h.sessionManager.mu.Unlock()
		log.Printf("Device bound session expired: %s", deviceBoundSessionId)
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	// If no Sec-Session-Response, this is a request for a challenge
	if secSessionResponse == "" {
		h.handleRefreshSessionChallenge(w, r, deviceBoundSessionId, session)
		return
	}

	// If we have a Sec-Session-Response, this is the browser's response to our challenge
	h.handleRefreshSessionResponse(w, r, deviceBoundSessionId, session, secSessionResponse)
	return
}

// handleRefreshSessionChallenge handles the challenge phase of DBSC refresh
func (h *Handler) handleRefreshSessionChallenge(w http.ResponseWriter, r *http.Request, deviceBoundSessionId string, session Session) {
	// Generate a new challenge for this user
	challengeId, dbscChallenge, err := h.sessionManager.CreateChallenge(session.Username)
	if err != nil {
		log.Printf("Error creating DBSC challenge: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set a cookie with the challenge ID
	SetChallengeCookie(w, r, challengeId)

	// According to the spec, send a 401 with Sec-Session-Challenge header
	AddChallengeHeader(w, dbscChallenge.Challenge, deviceBoundSessionId)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized) // 401 to indicate authentication challenge

	// Log the challenge response
	sessionInfo := map[string]string{
		"DeviceBoundSessionId": deviceBoundSessionId,
		"Challenge":            dbscChallenge.Challenge,
		"ChallengeId":          challengeId,
	}
	LogResponse("REFRESH SESSION CHALLENGE", w, http.StatusUnauthorized, nil, sessionInfo)
}

// handleRefreshSessionResponse handles the response phase of DBSC refresh
func (h *Handler) handleRefreshSessionResponse(w http.ResponseWriter, r *http.Request, deviceBoundSessionId string, session Session, secSessionResponse string) {
	// Get and verify the DBSC challenge
	challengeId, challenge, err := h.sessionManager.GetAndVerifyChallenge(r)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	// Extract JWT from the Sec-Session-Response header
	clientToken := secSessionResponse
	log.Printf("[DBSC] Processing JWT from Sec-Session-Response for refresh: %s", clientToken[:50]+"...")

	// Parse the JWT to extract the payload without verification
	jwtPayload, err := ParseJWT(clientToken)
	if err != nil {
		log.Printf("[DBSC] Error parsing JWT: %v", err)
		http.Error(w, "Invalid JWT format", http.StatusBadRequest)
		return
	}

	// Verify that the challenge is in the jti claim
	if jwtPayload.Jti != challenge.Challenge {
		log.Printf("[DBSC] Challenge mismatch: %s vs %s", jwtPayload.Jti, challenge.Challenge)
		http.Error(w, "Challenge mismatch", http.StatusBadRequest)
		return
	}

	// Verify the audience matches the refresh endpoint URL
	if err := ValidateJwtAudience(jwtPayload, r); err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Audience mismatch", http.StatusBadRequest)
		return
	}

	// In a production implementation, we would also verify the signature
	// using the public key stored during session registration

	// Update the device bound session and get a new auth token
	// Now using the updated method signature (without passing CookieMaxAge)
	newAuthToken, err := h.sessionManager.UpdateDeviceBoundSession(deviceBoundSessionId, session)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clear the challenge cookie and remove it from the server
	h.sessionManager.ClearChallenge(w, challengeId)

	// Set a new auth cookie
	SetAuthCookie(w, r, newAuthToken, h.authCookieName)

	// Create response object
	response := CreateRefreshResponse(deviceBoundSessionId, r, h.authCookieName, GetAuthCookieAttributes())

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Log the response
	sessionInfo := map[string]string{
		"User":                 session.Username,
		"DeviceBoundSessionId": deviceBoundSessionId,
		"NewAuthToken":         newAuthToken,
	}
	LogResponse("REFRESH SESSION RESPONSE", w, http.StatusOK, response, sessionInfo)

	// Send the response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	w.Write(responseJSON)
}
