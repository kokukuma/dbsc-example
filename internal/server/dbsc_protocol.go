package server

import (
	"fmt"
	"net/http"
	"time"
)

// Configuration constants
const (
// cookieMaxAge = 600 // 10 minutes as recommended in the DBSC spec - Moved to auth.go
)

// DbscChallenge represents a DBSC challenge
type DbscChallenge struct {
	Challenge string    `json:"challenge"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// JWTHeader represents the header part of a JWT
type JWTHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// JWTKey represents the public key in the JWT payload
type JWTKey struct {
	// RSA key parameters
	E   string `json:"e,omitempty"`
	Kty string `json:"kty"` // "RSA" or "EC"
	N   string `json:"n,omitempty"`

	// EC key parameters
	Crv string `json:"crv,omitempty"` // e.g., "P-256"
	X   string `json:"x,omitempty"`   // Base64URL-encoded x coordinate
	Y   string `json:"y,omitempty"`   // Base64URL-encoded y coordinate
}

// JWTPayload represents the payload part of a JWT with the public key
type JWTPayload struct {
	Aud           string      `json:"aud"`
	Jti           string      `json:"jti"` // This will contain the challenge
	Iat           interface{} `json:"iat"` // Can be int or string
	Key           JWTKey      `json:"key"`
	Authorization string      `json:"authorization"`
	Sub           string      `json:"sub"` // Subject (username)
}

// DbscSessionRefreshRequest is the request for refreshing a DBSC session
type DbscSessionRefreshRequest struct {
	ClientToken string `json:"clientToken"` // Used in our mock client
	PublicKey   string `json:"publicKey"`   // Used in our mock client
}

// DbscScope represents the scope of a DBSC session
type DbscScope struct {
	Origin        string `json:"origin,omitempty"`
	IncludeSite   bool   `json:"include_site,omitempty"`
	DeferRequests bool   `json:"defer_requests,omitempty"`
}

// DbscCredential represents a single credential in a DBSC session
type DbscCredential struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Attributes string `json:"attributes,omitempty"`
}

// DbscSessionRegistrationResponse represents the response for DBSC session registration
type DbscSessionRegistrationResponse struct {
	SessionIdentifier string           `json:"session_identifier"`
	RefreshURL        string           `json:"refresh_url"`
	Scope             DbscScope        `json:"scope"`
	Credentials       []DbscCredential `json:"credentials"`
}

// DbscSessionRefreshResponse represents the response for refreshing a DBSC session
type DbscSessionRefreshResponse struct {
	SessionIdentifier string           `json:"session_identifier,omitempty"`
	RefreshURL        string           `json:"refresh_url,omitempty"`
	Scope             DbscScope        `json:"scope,omitempty"`
	Credentials       []DbscCredential `json:"credentials,omitempty"`
	Continue          bool             `json:"continue"`
}

// addDbscRegistrationHeader adds the Sec-Session-Registration header with the challenge
func addDbscRegistrationHeader(w http.ResponseWriter, challenge string) {
	headerValue := fmt.Sprintf("(ES256 RS256);path=\"/securesession/startsession\";challenge=\"%s\"", challenge)
	w.Header().Set("Sec-Session-Registration", headerValue)
}

// addDbscChallengeHeader adds the Sec-Session-Challenge header with challenge and session ID
func addDbscChallengeHeader(w http.ResponseWriter, challenge string, sessionId string) {
	challengeHeader := fmt.Sprintf("\"%s\";id=\"%s\"", challenge, sessionId)
	w.Header().Set("Sec-Session-Challenge", challengeHeader)
}

// createDbscRegistrationResponse creates the DBSC session registration response according to the spec
func createDbscRegistrationResponse(deviceBoundSessionId string, r *http.Request) DbscSessionRegistrationResponse {
	scheme := "https"
	cookieName := "auth_cookie"

	return DbscSessionRegistrationResponse{
		SessionIdentifier: deviceBoundSessionId,
		RefreshURL:        fmt.Sprintf("%s://%s/securesession/refresh", scheme, r.Host),
		Scope: DbscScope{
			Origin:        fmt.Sprintf("%s://%s", scheme, r.Host),
			IncludeSite:   true,
			DeferRequests: true,
		},
		Credentials: []DbscCredential{
			{
				Type:       "cookie",
				Name:       cookieName,
				Attributes: getAuthCookieAttributes(),
			},
		},
	}
}

// createDbscRefreshResponse creates the DBSC session refresh response according to the spec
func createDbscRefreshResponse(deviceBoundSessionId string, r *http.Request) DbscSessionRefreshResponse {
	scheme := "https"
	cookieName := "auth_cookie"

	return DbscSessionRefreshResponse{
		SessionIdentifier: deviceBoundSessionId,
		RefreshURL:        fmt.Sprintf("%s://%s/securesession/refresh", scheme, r.Host),
		Scope: DbscScope{
			Origin:        fmt.Sprintf("%s://%s", scheme, r.Host),
			IncludeSite:   true,
			DeferRequests: true,
		},
		Credentials: []DbscCredential{
			{
				Type:       "cookie",
				Name:       cookieName,
				Attributes: getAuthCookieAttributes(),
			},
		},
		Continue: true, // Continue the session
	}
}

// parseDbscResponse parses the Sec-Session-Response header
func parseDbscResponse(r *http.Request) (string, error) {
	secSessionResponse := r.Header.Get("Sec-Session-Response")
	if secSessionResponse == "" {
		return "", fmt.Errorf("missing Sec-Session-Response header")
	}
	return secSessionResponse, nil
}

// getDbscSessionId gets the device bound session ID from the Sec-Session-Id header
func getDbscSessionId(r *http.Request) (string, error) {
	deviceBoundSessionId := r.Header.Get("Sec-Session-Id")
	if deviceBoundSessionId == "" {
		return "", fmt.Errorf("missing Sec-Session-Id header")
	}
	return deviceBoundSessionId, nil
}

// validateDbscJwtPayload validates the JWT payload against the DBSC challenge
func validateDbscJwtPayload(jwtPayload *JWTPayload, challenge DbscChallenge) error {
	if jwtPayload.Jti != challenge.Challenge {
		return fmt.Errorf("challenge mismatch: %s vs %s", jwtPayload.Jti, challenge.Challenge)
	}
	return nil
}

// validateDbscJwtAudience validates the JWT audience against the expected URL
func validateDbscJwtAudience(jwtPayload *JWTPayload, r *http.Request) error {
	scheme := "https"
	expectedAudience := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	if jwtPayload.Aud != expectedAudience {
		return fmt.Errorf("audience mismatch: %s vs %s", jwtPayload.Aud, expectedAudience)
	}
	return nil
}
