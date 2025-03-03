package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Configuration constants
const (
	cookieMaxAge = 10 // 10 minutes as recommended in the DBSC spec
)

// HandleDbscStartSession handles DBSC session registration
func (s *Server) HandleDbscStartSession(w http.ResponseWriter, r *http.Request) {
	// Log full request details
	log.Printf("===== [DBSC] START SESSION REQUEST =====")
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

	// This endpoint only handles the response to the Sec-Session-Registration
	// header that was sent during login. It should never send the initial challenge.
	secSessionResponse := r.Header.Get("Sec-Session-Response")

	// If no Sec-Session-Response, this should be an error - the initial challenge
	// should have been sent during login, not here.
	if secSessionResponse == "" {
		log.Printf("[DBSC] Error: No Sec-Session-Response header found. The challenge should have been sent during login.")
		http.Error(w, "Missing DBSC response", http.StatusBadRequest)
		return
	}

	// Get the challenge ID from cookie
	cookie, err := r.Cookie("dbsc_challenge")
	if err != nil || cookie.Value == "" {
		log.Printf("No DBSC challenge cookie found")
		http.Error(w, "Missing challenge cookie", http.StatusBadRequest)
		return
	}

	challengeId := cookie.Value

	// Get the challenge data
	s.mu.RLock()
	challenge, exists := s.dbscChallenges[challengeId]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Challenge not found: %s", challengeId)
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	// Check if challenge has expired
	if time.Now().After(challenge.ExpiresAt) {
		log.Printf("Challenge expired: %s", challengeId)
		s.mu.Lock()
		delete(s.dbscChallenges, challengeId)
		s.mu.Unlock()
		http.Error(w, "Challenge expired", http.StatusBadRequest)
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
	if jwtPayload.Jti != challenge.Challenge {
		log.Printf("[DBSC] Challenge mismatch: %s vs %s", jwtPayload.Jti, challenge.Challenge)
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

	// Create a device bound session ID
	deviceBoundSessionId, err := generateSessionID()
	if err != nil {
		log.Printf("Error generating device bound session ID: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a server-side device bound session
	now := time.Now()
	session := Session{
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(sessionMaxAge) * time.Second),
	}

	// Generate a secure auth_cookie value (different from sessionId)
	authToken, err := generateSessionID()
	if err != nil {
		log.Printf("Error generating auth token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	// Store the new device bound session
	s.sessions[deviceBoundSessionId] = session
	// Map auth token directly to device bound session ID
	s.authToLoginSession[authToken] = deviceBoundSessionId
	delete(s.dbscChallenges, challengeId) // Remove the used challenge
	s.mu.Unlock()

	log.Printf("[DBSC] Auth cookie bound to device bound session: %s", deviceBoundSessionId[:10]+"...")

	// Clear the challenge cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "dbsc_challenge",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	// Set auth cookie with short expiration
	cookieName := "auth_cookie"
	cookieValue := authToken // Use the secure token instead of sessionId

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true, // Required for SameSite=None
	})

	// Get proper scheme (http/https) for origin
	scheme := "https"

	// Create the DBSC session registration response according to the spec
	response := DbscSessionRegistrationResponse{
		SessionIdentifier: deviceBoundSessionId,
		RefreshURL:        fmt.Sprintf("%s://%s/securesession/refresh", scheme, r.Host),
		Scope: struct {
			Origin        string `json:"origin"`
			IncludeSite   bool   `json:"include_site"`
			DeferRequests bool   `json:"defer_requests"`
		}{
			Origin:        fmt.Sprintf("%s://%s", scheme, r.Host),
			IncludeSite:   true,
			DeferRequests: true,
		},
		Credentials: []struct {
			Type       string `json:"type"`
			Name       string `json:"name"`
			Attributes string `json:"attributes"`
		}{
			{
				Type:       "cookie",
				Name:       cookieName,
				Attributes: "Path=/; Max-Age=10; HttpOnly; Secure; SameSite=None",
			},
		},
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Get response body before encoding
	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Log the complete response
	log.Printf("===== [DBSC] START SESSION RESPONSE =====")
	log.Printf("Status: 200 OK")
	log.Printf("--- Headers ---")
	for name, values := range w.Header() {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}
	log.Printf("--- Body ---")
	log.Printf("%s", string(responseJSON))
	log.Printf("--- Summary ---")
	log.Printf("User: %s", username)
	log.Printf("DeviceBoundSessionId: %s", deviceBoundSessionId)
	log.Printf("AuthToken: %s", authToken)
	log.Printf("=====================================")

	// Send the response
	w.Write(responseJSON)
}

// HandleDbscRefreshSession handles DBSC session refresh
func (s *Server) HandleDbscRefreshSession(w http.ResponseWriter, r *http.Request) {
	// Log full request details
	log.Printf("===== [DBSC] REFRESH SESSION REQUEST =====")
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

	// Only proceed with POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for device bound session ID in the header
	deviceBoundSessionId := r.Header.Get("Sec-Session-Id")
	secSessionResponse := r.Header.Get("Sec-Session-Response")

	if deviceBoundSessionId == "" {
		log.Printf("No device bound session ID provided")
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

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
		// Generate a new challenge
		challenge, err := generateDbscChallenge()
		if err != nil {
			log.Printf("Error generating challenge: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate a challengeId
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
			Username:  session.Username,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Duration(dbscChallengeMaxAge) * time.Second),
		}

		s.mu.Lock()
		s.dbscChallenges[challengeId] = dbscChallenge
		s.mu.Unlock()

		// Set a cookie with the challenge ID
		http.SetCookie(w, &http.Cookie{
			Name:     "dbsc_challenge",
			Value:    challengeId,
			Path:     "/",
			MaxAge:   dbscChallengeMaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
			Secure:   true, // Required for SameSite=None
		})

		// According to the spec, send a 401 with Sec-Session-Challenge header
		challengeHeader := fmt.Sprintf("\"%s\";id=\"%s\"", challenge, deviceBoundSessionId)
		w.Header().Set("Sec-Session-Challenge", challengeHeader)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized) // 401 to indicate authentication challenge

		// Log the complete challenge response
		log.Printf("===== [DBSC] REFRESH SESSION CHALLENGE RESPONSE =====")
		log.Printf("Status: 401 Unauthorized")
		log.Printf("--- Headers ---")
		for name, values := range w.Header() {
			for _, value := range values {
				log.Printf("  %s: %s", name, value)
			}
		}
		log.Printf("--- Cookies ---")
		log.Printf("  dbsc_challenge: %s (MaxAge: %d, HttpOnly: true, SameSite: None, Secure: true)",
			challengeId, dbscChallengeMaxAge)
		log.Printf("--- Summary ---")
		log.Printf("DeviceBoundSessionId: %s", deviceBoundSessionId)
		log.Printf("Challenge: %s", challenge)
		log.Printf("ChallengeId: %s", challengeId)
		log.Printf("=====================================")
		return
	}

	// If we have a Sec-Session-Response, this is the browser's response to our challenge
	// Get the challenge ID from cookie
	cookie, err := r.Cookie("dbsc_challenge")
	if err != nil || cookie.Value == "" {
		log.Printf("No DBSC challenge cookie found")
		http.Error(w, "Missing challenge cookie", http.StatusBadRequest)
		return
	}

	challengeId := cookie.Value

	// Get the challenge data
	s.mu.RLock()
	challenge, exists := s.dbscChallenges[challengeId]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Challenge not found: %s", challengeId)
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	// Check if challenge has expired
	if time.Now().After(challenge.ExpiresAt) {
		log.Printf("Challenge expired: %s", challengeId)
		s.mu.Lock()
		delete(s.dbscChallenges, challengeId)
		s.mu.Unlock()
		http.Error(w, "Challenge expired", http.StatusBadRequest)
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

	// Verify the subject matches the device bound session ID
	// if jwtPayload.Sub != deviceBoundSessionId {
	// 	log.Printf("[DBSC] Session ID mismatch: %s vs %s", jwtPayload.Sub, deviceBoundSessionId)
	// 	http.Error(w, "Session ID mismatch", http.StatusBadRequest)
	// 	return
	// }

	// Verify the audience matches the refresh endpoint URL
	scheme := "https"
	expectedAudience := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	if jwtPayload.Aud != expectedAudience {
		log.Printf("[DBSC] Audience mismatch: %s vs %s", jwtPayload.Aud, expectedAudience)
		http.Error(w, "Audience mismatch", http.StatusBadRequest)
		return
	}

	// In a production implementation, we would also verify the signature
	// using the public key stored during session registration

	// Update the device bound session expiration time
	now := time.Now()
	session.ExpiresAt = now.Add(time.Duration(cookieMaxAge) * time.Second)

	// Generate a new auth token
	newAuthToken, err := generateSessionID()
	if err != nil {
		log.Printf("Error generating new auth token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	// Update device bound session
	s.sessions[deviceBoundSessionId] = session

	// Map the auth token directly to the device bound session ID
	// This is more consistent with DBSC spec where the token is bound to the device session
	s.authToLoginSession[newAuthToken] = deviceBoundSessionId

	// Remove any old auth tokens for this device bound session
	for authToken, sid := range s.authToLoginSession {
		if sid == deviceBoundSessionId && authToken != newAuthToken {
			delete(s.authToLoginSession, authToken)
		}
	}

	log.Printf("[DBSC] New auth token mapped to device bound session: %s", deviceBoundSessionId[:10]+"...")

	// Remove the used challenge
	delete(s.dbscChallenges, challengeId)
	s.mu.Unlock()

	// Clear the challenge cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "dbsc_challenge",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	// Set a new auth cookie with short expiration
	cookieName := "auth_cookie"
	cookieValue := newAuthToken // Use a new secure token

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true, // Required for SameSite=None
	})

	// Create response according to the spec
	response := DbscSessionRefreshResponse{
		SessionIdentifier: deviceBoundSessionId,
		Continue:          true, // Continue the session
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Get response body before encoding
	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Log the complete response
	log.Printf("===== [DBSC] REFRESH SESSION RESPONSE =====")
	log.Printf("Status: 200 OK")
	log.Printf("--- Headers ---")
	for name, values := range w.Header() {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}
	log.Printf("--- Cookies ---")
	log.Printf("  %s: %s (MaxAge: %d, SameSite: None, Secure: true, HttpOnly: true)",
		cookieName, cookieValue, cookieMaxAge)
	log.Printf("--- Body ---")
	log.Printf("%s", string(responseJSON))
	log.Printf("--- Summary ---")
	log.Printf("User: %s", session.Username)
	log.Printf("DeviceBoundSessionId: %s", deviceBoundSessionId)
	log.Printf("NewAuthToken: %s", newAuthToken)
	log.Printf("=====================================")

	// Send the response
	w.Write(responseJSON)
}
