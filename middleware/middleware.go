package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/imrany/smart_spore_hub/server/database/crypto"
	v1 "github.com/imrany/smart_spore_hub/server/internal/v1"
)

// respondError sends a JSON error response
func respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v1.Response{
		Success: false,
		Message: message,
	})
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Call next handler
		next.ServeHTTP(w, r)

		// Log request details
		duration := time.Since(start)
		slog.Info("HTTP Request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", r.Response.StatusCode,
			"duration", duration,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

// AuthMiddleware validates JWT tokens from Authorization header
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Authorization header is required")
			return
		}

		// Check if it starts with "Bearer "
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			respondError(w, http.StatusUnauthorized, "Invalid authorization format. Use: Bearer <token>")
			return
		}

		if parts[0] != "Bearer" {
			respondError(w, http.StatusUnauthorized, "Invalid authorization type. Expected: Bearer")
			return
		}

		// Extract token
		tokenString := parts[1]
		if tokenString == "" {
			respondError(w, http.StatusUnauthorized, "Token is required")
			return
		}

		// Validate token
		_, err := crypto.ValidateToken(tokenString)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Call next handler with updated context
		next.ServeHTTP(w, r)
	})
}

// CorsMiddleware handles CORS (Cross-Origin Resource Sharing)
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call next handler
		next.ServeHTTP(w, r)
	})
}
