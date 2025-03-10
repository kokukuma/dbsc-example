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

// Note: LoginRequest and LoginResponse types were removed as they were only used for the API login,
// which is no longer needed.

// DBSC関連の型定義は dbsc_protocol.go に移動しました
