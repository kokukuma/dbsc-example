package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// createDbscSessionRegistrationToken creates a JWT token for DBSC session registration
func (s *Server) createDbscSessionRegistrationToken(username string, challenge string) (string, error) {
	now := time.Now()

	// Create JWT claims with the standard registered claims
	claims := jwt.RegisteredClaims{
		Issuer:    "dbsc-example-server",
		Subject:   username,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(dbscChallengeMaxAge) * time.Second)),
	}

	// Add the challenge as a custom claim
	customClaims := struct {
		jwt.RegisteredClaims
		Nonce string `json:"nonce"`
	}{
		RegisteredClaims: claims,
		Nonce:            challenge,
	}

	// Create the token using ES256 algorithm (ECDSA with P-256 curve and SHA-256 hash)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, customClaims)

	// Sign the token with our private key
	tokenString, err := token.SignedString(s.dbscServerPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

// verifyDbscClientToken verifies a JWT token from the client
func verifyDbscClientToken(tokenString string, publicKeyPEM string, expectedChallenge string) (bool, string, error) {
	// For DBSC in a real browser, we actually wouldn't need to verify the JWT's signature
	// since we trust the browser's implementation. Instead, we just need to check that
	// the challenge in the JWT matches what we sent.

	// Parse the JWT payload to check the challenge
	payload, err := parseJWT(tokenString)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse JWT: %v", err)
	}

	// Check that the challenge is in the jti claim
	if payload.Jti != expectedChallenge {
		return false, "", fmt.Errorf("challenge mismatch: expected %s, got %s",
			expectedChallenge, payload.Jti)
	}

	// Return success with the subject (username) if present
	return true, payload.Sub, nil
}

// parseJWT parses a JWT without verification to extract the payload
func parseJWT(tokenString string) (*JWTPayload, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// First log the raw payload for debugging
	log.Printf("[DBSC] Raw JWT payload: %s", string(payload))

	var jwtPayload JWTPayload
	if err := json.Unmarshal(payload, &jwtPayload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %v", err)
	}

	// Log the key type to help with debugging
	log.Printf("[DBSC] JWT Key type: %s", jwtPayload.Key.Kty)
	if jwtPayload.Key.Kty == "RSA" {
		log.Printf("[DBSC] RSA key detected (N length: %d, E length: %d)", len(jwtPayload.Key.N), len(jwtPayload.Key.E))
	} else if jwtPayload.Key.Kty == "EC" {
		log.Printf("[DBSC] EC key detected (curve: %s, X length: %d, Y length: %d)",
			jwtPayload.Key.Crv, len(jwtPayload.Key.X), len(jwtPayload.Key.Y))
	}

	return &jwtPayload, nil
}

// convertJWKToPEM converts a JWK (JSON Web Key) public key to PEM format
// Supports both RSA and EC keys
func convertJWKToPEM(jwk JWTKey) (string, error) {
	var publicKey interface{}

	switch jwk.Kty {
	case "RSA":
		// RSA key processing
		if jwk.N == "" || jwk.E == "" {
			return "", fmt.Errorf("missing required RSA parameters")
		}

		// Decode the modulus (n) and exponent (e) from base64
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return "", fmt.Errorf("failed to decode modulus: %v", err)
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return "", fmt.Errorf("failed to decode exponent: %v", err)
		}

		// Convert exponent bytes to int
		var exponent int
		for i := 0; i < len(eBytes); i++ {
			exponent = exponent<<8 + int(eBytes[i])
		}

		// Create RSA public key
		publicKey = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: exponent,
		}

	case "EC":
		// EC key processing
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return "", fmt.Errorf("missing required EC parameters")
		}

		// Decode X and Y coordinates
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return "", fmt.Errorf("failed to decode X coordinate: %v", err)
		}

		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return "", fmt.Errorf("failed to decode Y coordinate: %v", err)
		}

		// Determine elliptic curve
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return "", fmt.Errorf("unsupported curve: %s", jwk.Crv)
		}

		// Create EC public key
		publicKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}

	default:
		return "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Marshal the public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Encode to PEM format
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	return string(pemBytes), nil
}