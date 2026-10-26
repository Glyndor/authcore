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

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
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
	pwdMod, jwtMod, emailMod, err := newModules(authcore.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}

	r, err := newRouter(pwdMod, jwtMod, emailMod)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("listening on :3000")
	log.Fatal(newServer(":3000", r).ListenAndServe())
}

// newModules initialises authcore from cfg and returns the three modules the
// routes use. Call it once at startup and share the result between requests.
func newModules(cfg authcore.Config) (*password.Password, *jwt.JWT[UserClaims], *email.Email, error) {
	auth, err := authcore.New(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authcore: %w", err)
	}

	pwdMod, err := password.New(auth)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("password module: %w", err)
	}

	emailMod, err := email.New(auth)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("email module: %w", err)
	}

	jwtCfg := jwt.DefaultConfig()
	jwtCfg.Issuer = "my-service"
	jwtCfg.Audience = []string{"my-app"}

	jwtMod, err := jwt.New[UserClaims](auth, jwtCfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jwt module: %w", err)
	}

	return pwdMod, jwtMod, emailMod, nil
}

// newRouter builds the Gin engine with every route of the example wired to
// the three modules, over a fresh empty user store. main serves it, and the
// tests drive the same engine through net/http/httptest.
func newRouter(pwdMod *password.Password, jwtMod *jwt.JWT[UserClaims], emailMod *email.Email) (*gin.Engine, error) {
	db := newStore()
	r := gin.Default()
	r.Use(hardening)

	// Login verifies against this hash when the account does not exist, so an
	// unknown address costs one Argon2id derivation like a wrong password.
	decoy, err := pwdMod.Hash(decoyPassword)
	if err != nil {
		return nil, fmt.Errorf("decoy hash: %w", err)
	}

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
			badBody(c, err)
			return
		}

		// The canonical address is the key: without it "Ana@example.com" and
		// "ana@example.com" are two accounts. ErrInvalidEmail is CLIENT-SAFE.
		addr, err := emailMod.ValidateAndNormalize(req.Email)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errors.Unwrap(err).Error()})
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
			email:        addr,
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
			badBody(c, err)
			return
		}
		if len(req.Password) > maxLoginPassword {
			// Verify applies no length policy and hashes all of its input.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		// Unknown and malformed addresses take the same path as a wrong
		// password: one Argon2id derivation, then the same 401.
		hash := decoy
		var u user
		exists := false
		if addr, addrErr := emailMod.ValidateAndNormalize(req.Email); addrErr == nil {
			u, exists = db.findByEmail(addr)
		}
		if exists {
			hash = u.passwordHash
		}

		ok, err := pwdMod.Verify(req.Password, hash)
		if err != nil {
			// ErrInvalidHash is INTERNAL — log it, return generic 401.
			// %q quotes and escapes control characters so a hostile email
			// containing newlines cannot forge extra log entries.
			log.Printf("verify error for %q: %v", req.Email, err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		if !ok || !exists {
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
		token, found := bearerToken(c.Request.Header.Values("Authorization"))
		if !found {
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
			badBody(c, err)
			return
		}

		// 1. Look the session up by the hash of the presented token, then
		//    confirm the match in constant time.
		presented, hashErr := jwtMod.HashRefreshToken(req.RefreshToken)
		if hashErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		found, ok := db.findByRefreshHash(presented)
		if !ok || !jwtMod.VerifyRefreshTokenHash(req.RefreshToken, found.refreshHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		// 2. Mint outside any lock. RotateTokens checks signature and expiry.
		//    Nothing minted here may reach the client before step 3 succeeds.
		newPair, err := jwtMod.RotateTokens(req.RefreshToken, UserClaims{Email: found.email})
		if err != nil {
			// Same answer as an unknown token: do not tell which one failed.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
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

	return r, nil
}
