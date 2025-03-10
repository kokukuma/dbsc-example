package dbsc

import (
	"fmt"
	"net/http"
	"time"
)

// DbscChallenge represents a DBSC challenge
type Challenge struct {
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

// Scope represents the scope of a DBSC session
type Scope struct {
	Origin        string `json:"origin,omitempty"`
	IncludeSite   bool   `json:"include_site,omitempty"`
	DeferRequests bool   `json:"defer_requests,omitempty"`
}

// Credential represents a single credential in a DBSC session
type Credential struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Attributes string `json:"attributes,omitempty"`
}

// SessionRegistrationResponse represents the response for DBSC session registration
type SessionRegistrationResponse struct {
	SessionIdentifier string       `json:"session_identifier"`
	RefreshURL        string       `json:"refresh_url"`
	Scope             Scope        `json:"scope"`
	Credentials       []Credential `json:"credentials"`
}

// SessionRefreshResponse represents the response for refreshing a DBSC session
type SessionRefreshResponse struct {
	SessionIdentifier string       `json:"session_identifier,omitempty"`
	RefreshURL        string       `json:"refresh_url,omitempty"`
	Scope             Scope        `json:"scope,omitempty"`
	Credentials       []Credential `json:"credentials,omitempty"`
	Continue          bool         `json:"continue"`
}

// AddRegistrationHeader adds the Sec-Session-Registration header with the challenge
func AddRegistrationHeader(w http.ResponseWriter, challenge string) {
	headerValue := fmt.Sprintf("(ES256 RS256);path=\"/securesession/startsession\";challenge=\"%s\"", challenge)
	w.Header().Set("Sec-Session-Registration", headerValue)
}

// AddChallengeHeader adds the Sec-Session-Challenge header with challenge and session ID
func AddChallengeHeader(w http.ResponseWriter, challenge string, sessionId string) {
	challengeHeader := fmt.Sprintf("\"%s\";id=\"%s\"", challenge, sessionId)
	w.Header().Set("Sec-Session-Challenge", challengeHeader)
}

// CreateRegistrationResponse creates the DBSC session registration response according to the spec
func CreateRegistrationResponse(deviceBoundSessionId string, r *http.Request, cookieName string, cookieAttributes string) SessionRegistrationResponse {
	scheme := "https"
	return SessionRegistrationResponse{
		SessionIdentifier: deviceBoundSessionId,
		RefreshURL:        fmt.Sprintf("%s://%s/securesession/refresh", scheme, r.Host),
		Scope: Scope{
			Origin:        fmt.Sprintf("%s://%s", scheme, r.Host),
			IncludeSite:   true,
			DeferRequests: true,
		},
		Credentials: []Credential{
			{
				Type:       "cookie",
				Name:       cookieName,
				Attributes: cookieAttributes,
			},
		},
	}
}

// CreateRefreshResponse creates the DBSC session refresh response according to the spec
func CreateRefreshResponse(deviceBoundSessionId string, r *http.Request, cookieName string, cookieAttributes string) SessionRefreshResponse {
	scheme := "https"
	return SessionRefreshResponse{
		SessionIdentifier: deviceBoundSessionId,
		RefreshURL:        fmt.Sprintf("%s://%s/securesession/refresh", scheme, r.Host),
		Scope: Scope{
			Origin:        fmt.Sprintf("%s://%s", scheme, r.Host),
			IncludeSite:   true,
			DeferRequests: true,
		},
		Credentials: []Credential{
			{
				Type:       "cookie",
				Name:       cookieName,
				Attributes: cookieAttributes,
			},
		},
		Continue: true, // Continue the session
	}
}

// ParseResponse parses the Sec-Session-Response header
func ParseResponse(r *http.Request) (string, error) {
	secSessionResponse := r.Header.Get("Sec-Session-Response")
	if secSessionResponse == "" {
		return "", fmt.Errorf("missing Sec-Session-Response header")
	}
	return secSessionResponse, nil
}

// GetSessionId gets the device bound session ID from the Sec-Session-Id header
func GetSessionId(r *http.Request) (string, error) {
	deviceBoundSessionId := r.Header.Get("Sec-Session-Id")
	if deviceBoundSessionId == "" {
		return "", fmt.Errorf("missing Sec-Session-Id header")
	}
	return deviceBoundSessionId, nil
}

// ValidateJwtPayload validates the JWT payload against the DBSC challenge
func ValidateJwtPayload(jwtPayload *JWTPayload, challenge Challenge) error {
	if jwtPayload.Jti != challenge.Challenge {
		return fmt.Errorf("challenge mismatch: %s vs %s", jwtPayload.Jti, challenge.Challenge)
	}
	return nil
}

// ValidateJwtAudience validates the JWT audience against the expected URL
func ValidateJwtAudience(jwtPayload *JWTPayload, r *http.Request) error {
	scheme := "https"
	expectedAudience := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	if jwtPayload.Aud != expectedAudience {
		return fmt.Errorf("audience mismatch: %s vs %s", jwtPayload.Aud, expectedAudience)
	}
	return nil
}
