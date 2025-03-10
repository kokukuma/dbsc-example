package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// logRequest logs full HTTP request details for DBSC operations
func logRequest(prefix string, r *http.Request) {
	log.Printf("===== [DBSC] %s REQUEST =====", prefix)
	log.Printf("Method: %s, Path: %s", r.Method, r.URL.Path)
	log.Printf("User-Agent: %s", r.UserAgent())
	log.Printf("Remote Address: %s", r.RemoteAddr)

	// Log all headers
	log.Printf("--- Headers ---")
	for name, values := range r.Header {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}

	// Log cookies
	log.Printf("--- Cookies ---")
	for _, cookie := range r.Cookies() {
		log.Printf("  %s: %s", cookie.Name, cookie.Value)
	}
}

// logResponse logs HTTP response details for DBSC operations
func logResponse(prefix string, w http.ResponseWriter, status int, responseBody interface{}, sessionInfo map[string]string) {
	log.Printf("===== [DBSC] %s RESPONSE =====", prefix)
	log.Printf("Status: %d", status)

	// Log response headers
	log.Printf("--- Headers ---")
	for name, values := range w.Header() {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}

	// Log response body if present
	if responseBody != nil {
		responseJSON, err := json.MarshalIndent(responseBody, "", "  ")
		if err == nil {
			log.Printf("--- Body ---")
			log.Printf("%s", string(responseJSON))
		}
	}

	// Log session summary if provided
	if len(sessionInfo) > 0 {
		log.Printf("--- Summary ---")
		for key, value := range sessionInfo {
			// Truncate values that might be too long
			if len(value) > 50 && !strings.Contains(key, "User") {
				value = value[:50] + "..."
			}
			log.Printf("%s: %s", key, value)
		}
	}

	log.Printf("=====================================")
}
