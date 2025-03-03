package server

import (
	"net/http"
	"sync"
)

func NewServer(webauthn interface{}) *Server {
	return &Server{}
}

type Server struct {
	mu sync.RWMutex
}
