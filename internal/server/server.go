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

	"github.com/kokukuma/dbsc-example/internal/dbsc"
)

type Server struct {
	users              []User
	sessions           map[string]Session
	authTokenToSession map[string]string
	mu                 sync.RWMutex

	// DBSC components
	dbscHandler          *dbsc.Handler
	dbscServerPrivateKey *ecdsa.PrivateKey
	dbscServerPublicKey  string
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
		authTokenToSession:   make(map[string]string),
		dbscServerPrivateKey: privateKey,
		dbscServerPublicKey:  string(publicKeyPEM),
	}

	// Initialize DBSC handler with the server's private key
	server.dbscHandler = dbsc.NewHandler(privateKey, "auth_cookie")

	log.Println("DBSC server initialized with ES256 key pair")

	return server
}
