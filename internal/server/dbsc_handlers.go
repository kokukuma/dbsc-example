package server

import (
	"net/http"
)

// HandleDbscStartSession is a wrapper around the DBSC handler's HandleStartSession
func (s *Server) HandleDbscStartSession(w http.ResponseWriter, r *http.Request) {
	s.dbscHandler.HandleStartSession(w, r)
}

// HandleDbscRefreshSession is a wrapper around the DBSC handler's HandleRefreshSession
func (s *Server) HandleDbscRefreshSession(w http.ResponseWriter, r *http.Request) {
	s.dbscHandler.HandleRefreshSession(w, r)
}
