package server

import (
	"time"
)

// User represents a simple user with username and password
type User struct {
	Username string
	Password string
}

// Session represents a user session
type Session struct {
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// LoginRequest represents the login request from client
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the login response to client
type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// DbscChallenge represents a DBSC challenge
type DbscChallenge struct {
	Challenge string    `json:"challenge"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// DbscSessionRegistrationResponse is the response for DBSC session registration
type DbscSessionRegistrationResponse struct {
	SessionIdentifier string `json:"session_identifier"`
	RefreshURL        string `json:"refresh_url"`
	Scope             struct {
		Origin        string `json:"origin"`
		IncludeSite   bool   `json:"include_site"`
		DeferRequests bool   `json:"defer_requests"`
	} `json:"scope"`
	Credentials []struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Attributes string `json:"attributes"`
	} `json:"credentials"`
}

// DbscSessionRefreshResponse is the response for refreshing a DBSC session
type DbscSessionRefreshResponse struct {
	SessionIdentifier string `json:"session_identifier"`
	Continue          bool   `json:"continue"`
}

// DbscSessionRefreshRequest is the request for refreshing a DBSC session
type DbscSessionRefreshRequest struct {
	ClientToken string `json:"clientToken"` // Used in our mock client
	PublicKey   string `json:"publicKey"`   // Used in our mock client
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