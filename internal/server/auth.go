package server

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// Maximum age of a session in seconds (30 minutes)
const sessionMaxAge = 1800

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