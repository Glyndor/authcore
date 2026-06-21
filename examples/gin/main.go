// Command gin demonstrates authcore integrated with Gin.
//
// Routes:
//
//	POST /register  — hash and store a new user's password
//	POST /login     — verify password, issue JWT pair
//	GET  /me        — protected: verify access token, return claims
//	POST /refresh   — rotate refresh token, issue new pair
package main

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/gin-gonic/gin"
)

// ---- in-memory "database" ---------------------------------------------------

type user struct {
	id           string
	email        string
	passwordHash string
	refreshHash  string
}

var (
	mu    sync.RWMutex
	users = map[string]*user{} // keyed by email
)

// ---- custom claims ----------------------------------------------------------

type UserClaims struct {
	Email string `json:"email"`
}

// ---- main -------------------------------------------------------------------

func main() {
	// Initialise authcore and modules once at startup.
	auth, err := authcore.New(authcore.DefaultConfig())
	if err != nil {
		log.Fatalf("authcore: %v", err)
	}

	pwdMod, err := password.New(auth)
	if err != nil {
		log.Fatalf("password module: %v", err)
	}

	jwtCfg := jwt.DefaultConfig()
	jwtCfg.Issuer = "my-service"
	jwtCfg.Audience = []string{"my-app"}

	jwtMod, err := jwt.New[UserClaims](auth, jwtCfg)
	if err != nil {
		log.Fatalf("jwt module: %v", err)
	}

	r := gin.Default()

	// -------------------------------------------------------------------------
	// POST /register
	// Body: { "email": "...", "password": "..." }
	// -------------------------------------------------------------------------
	r.POST("/register", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}

		// Fail-fast: reject weak passwords before spending CPU on Argon2id.
		// ErrWeakPassword is CLIENT-SAFE: unwrap to get the specific reason
		// ("must be at least 12 characters") without the module prefix.
		if err := pwdMod.ValidatePolicy(req.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errors.Unwrap(err).Error()})
			return
		}

		hash, err := pwdMod.Hash(req.Password)
		if err != nil {
			// ErrInvalidHash and salt errors are INTERNAL — log, return generic 500.
			log.Printf("hash error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		mu.Lock()
		users[req.Email] = &user{
			id:           req.Email, // use a real UUID v7 in production
			email:        req.Email,
			passwordHash: hash,
		}
		mu.Unlock()

		c.JSON(http.StatusCreated, gin.H{"message": "user created"})
	})

	// -------------------------------------------------------------------------
	// POST /login
	// Body: { "email": "...", "password": "..." }
	// -------------------------------------------------------------------------
	r.POST("/login", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}

		mu.RLock()
		u, exists := users[req.Email]
		mu.RUnlock()

		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		ok, err := pwdMod.Verify(req.Password, u.passwordHash)
		if err != nil {
			// ErrInvalidHash is INTERNAL — log it, return generic 401.
			// %q quotes and escapes control characters so a hostile email
			// containing newlines cannot forge extra log entries.
			log.Printf("verify error for %q: %v", req.Email, err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		pair, err := jwtMod.CreateTokens(u.id, UserClaims{Email: u.email})
		if err != nil {
			// INTERNAL: sign error or invalid subject — log it, return generic 500.
			log.Printf("create tokens error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		// Persist only the hash — never the raw refresh token.
		mu.Lock()
		u.refreshHash = pair.RefreshTokenHash
		mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"access_token":  pair.AccessToken,
			"refresh_token": pair.RefreshToken, // send via HttpOnly cookie in production
			"expires_at":    pair.AccessTokenExpiresAt,
		})
	})

	// -------------------------------------------------------------------------
	// jwtMiddleware extracts and verifies the Bearer token.
	// On success it stores the claims under the key "claims" for the handler.
	// -------------------------------------------------------------------------
	jwtMiddleware := func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found || token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		claims, err := jwtMod.VerifyAccessToken(token)
		if err != nil {
			// Always log the full error — it may contain internal details useful
			// for debugging (algorithm name, token type mismatch, etc.).
			log.Printf("access token verification failed: %v", err)

			// Only ErrTokenExpired is CLIENT-SAFE — it tells the client to refresh.
			// All other errors collapse to a generic "unauthorized".
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.Set("claims", claims)
		c.Next()
	}

	// -------------------------------------------------------------------------
	// GET /me  (protected)
	// Header: Authorization: Bearer <access_token>
	// -------------------------------------------------------------------------
	r.GET("/me", jwtMiddleware, func(c *gin.Context) {
		claims := c.MustGet("claims").(*jwt.Claims[UserClaims])
		c.JSON(http.StatusOK, gin.H{
			"user_id": claims.Subject,
			"email":   claims.Extra.Email,
		})
	})

	// -------------------------------------------------------------------------
	// POST /refresh
	// Body: { "refresh_token": "..." }
	// -------------------------------------------------------------------------
	r.POST("/refresh", func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}

		// Find the user whose stored hash matches this token (constant-time).
		// In production: decode the session ID from the refresh token claims
		// and look up the user directly — no table scan needed.
		mu.RLock()
		var found *user
		for _, u := range users {
			if jwtMod.VerifyRefreshTokenHash(req.RefreshToken, u.refreshHash) {
				found = u
				break
			}
		}
		mu.RUnlock()

		if found == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		newPair, err := jwtMod.RotateTokens(req.RefreshToken, UserClaims{Email: found.email})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "could not rotate token"})
			return
		}

		// Atomically replace the stored hash in the database.
		mu.Lock()
		found.refreshHash = newPair.RefreshTokenHash
		mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"access_token":  newPair.AccessToken,
			"refresh_token": newPair.RefreshToken,
			"expires_at":    newPair.AccessTokenExpiresAt,
		})
	})

	log.Println("listening on :3000")
	log.Fatal(r.Run(":3000"))
}
