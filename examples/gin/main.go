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
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/gin-gonic/gin"
)

// ---- custom claims ----------------------------------------------------------

// UserClaims is the application data carried inside the access token.
type UserClaims struct {
	Email string `json:"email"`
}

// ---- main -------------------------------------------------------------------

func main() {
	pwdMod, jwtMod, err := newModules(authcore.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}

	r := newRouter(pwdMod, jwtMod)

	log.Println("listening on :3000")
	log.Fatal(r.Run(":3000"))
}

// newModules initialises authcore from cfg and returns the two modules the
// routes use. Call it once at startup and share the result between requests.
func newModules(cfg authcore.Config) (*password.Password, *jwt.JWT[UserClaims], error) {
	auth, err := authcore.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("authcore: %w", err)
	}

	pwdMod, err := password.New(auth)
	if err != nil {
		return nil, nil, fmt.Errorf("password module: %w", err)
	}

	jwtCfg := jwt.DefaultConfig()
	jwtCfg.Issuer = "my-service"
	jwtCfg.Audience = []string{"my-app"}

	jwtMod, err := jwt.New[UserClaims](auth, jwtCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt module: %w", err)
	}

	return pwdMod, jwtMod, nil
}

// newRouter builds the Gin engine with every route of the example wired to
// pwdMod and jwtMod, over a fresh empty user store. main serves it, and the
// tests drive the same engine through net/http/httptest.
func newRouter(pwdMod *password.Password, jwtMod *jwt.JWT[UserClaims]) *gin.Engine {
	db := newStore()
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

		// The id is the JWT subject and must be a UUID v7. The email stays a
		// separate field: it can change, the subject cannot.
		created := db.insert(user{
			id:           newUserID(),
			email:        req.Email,
			passwordHash: hash,
		})
		if !created {
			// Never overwrite: a second registration of an address must not
			// touch the account that owns it.
			//
			// This 409 tells the caller the address is registered. Accept that
			// in a demo only. In production answer every registration the same
			// way and deliver the outcome to the mailbox, so the endpoint
			// cannot be used to enumerate accounts.
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}

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

		u, exists := db.findByEmail(req.Email)
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
		if !db.setRefreshHash(u.email, pair.RefreshTokenHash) {
			// The account disappeared between the lookup and this write.
			// Fail closed: tokens whose hash was not stored must not be sent.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

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

		// 1. Look the session up by the hash of the presented token, then
		//    confirm the match in constant time.
		presented := jwtMod.HashRefreshToken(req.RefreshToken)
		found, ok := db.findByRefreshHash(presented)
		if !ok || !jwtMod.VerifyRefreshTokenHash(req.RefreshToken, found.refreshHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		// 2. Mint outside any lock. RotateTokens checks signature and expiry.
		//    Nothing minted here may reach the client before step 3 succeeds.
		newPair, err := jwtMod.RotateTokens(req.RefreshToken, UserClaims{Email: found.email})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "could not rotate token"})
			return
		}

		// 3. Consume the presented token: swap its hash for the new one only
		//    if it is still the stored one. The lookup in step 1 is not enough,
		//    because a concurrent redemption of the same token passes it too.
		//    Whoever loses this swap gets 401 and its minted pair is dropped.
		if !db.swapRefreshHash(found.email, presented, newPair.RefreshTokenHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  newPair.AccessToken,
			"refresh_token": newPair.RefreshToken,
			"expires_at":    newPair.AccessTokenExpiresAt,
		})
	})

	return r
}
