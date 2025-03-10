package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// HandleDbscStartSession handles DBSC session registration
func (s *Server) HandleDbscStartSession(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	logRequest("START SESSION", r)

	// This endpoint only handles the response to the Sec-Session-Registration
	// header that was sent during login. It should never send the initial challenge.
	secSessionResponse, err := parseDbscResponse(r)
	if err != nil {
		log.Printf("[DBSC] Error: %v. The challenge should have been sent during login.", err)
		http.Error(w, "Missing DBSC response", http.StatusBadRequest)
		return
	}

	// Get and verify the DBSC challenge
	challengeId, challenge, err := s.getAndVerifyDbscChallenge(r)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	// Extract JWT from the Sec-Session-Response header
	clientToken := secSessionResponse
	log.Printf("[DBSC] Processing JWT from Sec-Session-Response: %s", clientToken[:50]+"...")

	// Parse the JWT to extract the payload without verification
	jwtPayload, err := parseJWT(clientToken)
	if err != nil {
		log.Printf("[DBSC] Error parsing JWT: %v", err)
		http.Error(w, "Invalid JWT format", http.StatusBadRequest)
		return
	}

	// Verify that the challenge is in the jti claim
	if err := validateDbscJwtPayload(jwtPayload, challenge); err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Challenge mismatch", http.StatusBadRequest)
		return
	}

	// Extract and convert the public key from the JWT payload
	clientPublicKeyPEM, err := convertJWKToPEM(jwtPayload.Key)
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
	deviceBoundSessionId, authToken, err := s.createDeviceBoundSession(username)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clear the challenge cookie and remove the challenge from the server
	s.clearDbscChallenge(w, challengeId)

	// Set auth cookie
	setAuthCookie(w, r, authToken)

	// Create the DBSC session registration response
	response := createDbscRegistrationResponse(deviceBoundSessionId, r)

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Log the response information
	sessionInfo := map[string]string{
		"User":                 username,
		"DeviceBoundSessionId": deviceBoundSessionId,
		"AuthToken":            authToken,
	}
	logResponse("START SESSION", w, http.StatusOK, response, sessionInfo)

	// Send the response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	w.Write(responseJSON)
}

// HandleDbscRefreshSession handles DBSC session refresh
func (s *Server) HandleDbscRefreshSession(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	logRequest("REFRESH SESSION", r)

	// Only proceed with POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for device bound session ID in the header
	deviceBoundSessionId, err := getDbscSessionId(r)
	if err != nil {
		log.Printf("No device bound session ID provided: %v", err)
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get Sec-Session-Response header if present
	secSessionResponse := r.Header.Get("Sec-Session-Response")

	// Verify the device bound session exists
	s.mu.RLock()
	session, sessionExists := s.sessions[deviceBoundSessionId]
	s.mu.RUnlock()

	if !sessionExists {
		log.Printf("Device bound session not found: %s", deviceBoundSessionId)
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}

	// Check if device bound session has expired
	if time.Now().After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, deviceBoundSessionId)
		s.mu.Unlock()
		log.Printf("Device bound session expired: %s", deviceBoundSessionId)
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	// If no Sec-Session-Response, this is a request for a challenge
	if secSessionResponse == "" {
		s.handleDbscRefreshSessionChallenge(w, r, deviceBoundSessionId, session)
		return
	}

	// If we have a Sec-Session-Response, this is the browser's response to our challenge
	s.handleDbscRefreshSessionResponse(w, r, deviceBoundSessionId, session, secSessionResponse)
	return
}

// handleDbscRefreshSessionChallenge handles the challenge phase of DBSC refresh
func (s *Server) handleDbscRefreshSessionChallenge(w http.ResponseWriter, r *http.Request, deviceBoundSessionId string, session Session) {
	// Generate a new challenge for this user
	challengeId, dbscChallenge, err := s.createDbscChallenge(session.Username)
	if err != nil {
		log.Printf("Error creating DBSC challenge: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set a cookie with the challenge ID
	setDbscChallengeCookie(w, r, challengeId)

	// According to the spec, send a 401 with Sec-Session-Challenge header
	addDbscChallengeHeader(w, dbscChallenge.Challenge, deviceBoundSessionId)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized) // 401 to indicate authentication challenge

	// Log the challenge response
	sessionInfo := map[string]string{
		"DeviceBoundSessionId": deviceBoundSessionId,
		"Challenge":            dbscChallenge.Challenge,
		"ChallengeId":          challengeId,
	}
	logResponse("REFRESH SESSION CHALLENGE", w, http.StatusUnauthorized, nil, sessionInfo)
}

// handleDbscRefreshSessionResponse handles the response phase of DBSC refresh
func (s *Server) handleDbscRefreshSessionResponse(w http.ResponseWriter, r *http.Request, deviceBoundSessionId string, session Session, secSessionResponse string) {
	// Get and verify the DBSC challenge
	challengeId, challenge, err := s.getAndVerifyDbscChallenge(r)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	// Extract JWT from the Sec-Session-Response header
	clientToken := secSessionResponse
	log.Printf("[DBSC] Processing JWT from Sec-Session-Response for refresh: %s", clientToken[:50]+"...")

	// Parse the JWT to extract the payload without verification
	jwtPayload, err := parseJWT(clientToken)
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
	if err := validateDbscJwtAudience(jwtPayload, r); err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Audience mismatch", http.StatusBadRequest)
		return
	}

	// In a production implementation, we would also verify the signature
	// using the public key stored during session registration

	// Update the device bound session and get a new auth token
	newAuthToken, err := s.updateDeviceBoundSession(deviceBoundSessionId, session)
	if err != nil {
		log.Printf("[DBSC] %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clear the challenge cookie and remove it from the server
	s.clearDbscChallenge(w, challengeId)

	// Set a new auth cookie
	setAuthCookie(w, r, newAuthToken)

	// Create response object
	response := createDbscRefreshResponse(deviceBoundSessionId, r)

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Log the response
	sessionInfo := map[string]string{
		"User":                 session.Username,
		"DeviceBoundSessionId": deviceBoundSessionId,
		"NewAuthToken":         newAuthToken,
	}
	logResponse("REFRESH SESSION RESPONSE", w, http.StatusOK, response, sessionInfo)

	// Send the response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	w.Write(responseJSON)
}
