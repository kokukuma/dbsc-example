package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
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

// generateSessionID creates a secure random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
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

// hashString creates a SHA-256 hash of the input string
// NOTE: This is NOT suitable for password storage! Use bcrypt/argon2 in production
func hashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
