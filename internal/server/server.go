package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"sync"
)

type Server struct {
	users                []User
	sessions             map[string]Session
	dbscChallenges       map[string]DbscChallenge
	dbscServerPrivateKey *ecdsa.PrivateKey
	dbscServerPublicKey  string
	authTokenToDeviceSession   map[string]string // Maps auth_cookie values to device bound session IDs
	mu                   sync.RWMutex
}

func NewServer(webauthn interface{}) *Server {
	// Hardcoded user for demo purposes
	users := []User{
		{Username: "dbsc-user", Password: "password"},
	}

	// Generate ECDSA key pair for DBSC
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate ECDSA key: %v", err))
	}

	// Store public key in PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal public key: %v", err))
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	server := &Server{
		users:                users,
		sessions:             make(map[string]Session),
		dbscChallenges:       make(map[string]DbscChallenge),
		dbscServerPrivateKey: privateKey,
		dbscServerPublicKey:  string(publicKeyPEM),
		authTokenToDeviceSession:   make(map[string]string), // Maps auth_cookie values to device bound session IDs
	}

	log.Println("DBSC server initialized with ES256 key pair")

	return server
}