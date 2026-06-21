// Command fiber demonstrates authcore integrated with Fiber v3.
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
	"strings"
	"sync"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/gofiber/fiber/v3"
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

	app := fiber.New()

	// -------------------------------------------------------------------------
	// POST /register
	// Body: { "email": "...", "password": "..." }
	// -------------------------------------------------------------------------
	app.Post("/register", func(c fiber.Ctx) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}

		// Fail-fast: reject weak passwords before spending CPU on Argon2id.
		// ErrWeakPassword is CLIENT-SAFE: unwrap to get the specific reason
		// ("must be at least 12 characters") without the module prefix.
		if err := pwdMod.ValidatePolicy(req.Password); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": errors.Unwrap(err).Error(),
			})
		}

		hash, err := pwdMod.Hash(req.Password)
		if err != nil {
			// ErrInvalidHash and salt errors are INTERNAL — log, return generic 500.
			log.Printf("hash error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}

		mu.Lock()
		users[req.Email] = &user{
			id:           req.Email, // use a real UUID v7 in production
			email:        req.Email,
			passwordHash: hash,
		}
		mu.Unlock()

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "user created"})
	})

	// -------------------------------------------------------------------------
	// POST /login
	// Body: { "email": "...", "password": "..." }
	// -------------------------------------------------------------------------
	app.Post("/login", func(c fiber.Ctx) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}

		mu.RLock()
		u, exists := users[req.Email]
		mu.RUnlock()

		if !exists {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}

		ok, err := pwdMod.Verify(req.Password, u.passwordHash)
		if err != nil {
			// ErrInvalidHash is INTERNAL — log it, return generic 401.
			// %q quotes and escapes control characters so a hostile email
			// containing newlines cannot forge extra log entries.
			log.Printf("verify error for %q: %v", req.Email, err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}

		pair, err := jwtMod.CreateTokens(u.id, UserClaims{Email: u.email})
		if err != nil {
			// INTERNAL: sign error or invalid subject — log it, return generic 500.
			log.Printf("create tokens error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}

		// Persist only the hash — never the raw refresh token.
		mu.Lock()
		u.refreshHash = pair.RefreshTokenHash
		mu.Unlock()

		return c.JSON(fiber.Map{
			"access_token":  pair.AccessToken,
			"refresh_token": pair.RefreshToken, // send via HttpOnly cookie in production
			"expires_at":    pair.AccessTokenExpiresAt,
		})
	})

	// -------------------------------------------------------------------------
	// GET /me  (protected)
	// Header: Authorization: Bearer <access_token>
	// -------------------------------------------------------------------------
	app.Get("/me", func(c fiber.Ctx) error {
		header := c.Get("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found || token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing token"})
		}

		claims, err := jwtMod.VerifyAccessToken(token)
		if err != nil {
			// Always log the full error — it may contain internal details useful
			// for debugging (algorithm name, token type mismatch, etc.).
			log.Printf("access token verification failed: %v", err)

			// Only ErrTokenExpired is CLIENT-SAFE — it tells the client to refresh.
			// All other errors collapse to a generic "unauthorized".
			if errors.Is(err, jwt.ErrTokenExpired) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token expired"})
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}

		return c.JSON(fiber.Map{
			"user_id": claims.Subject,
			"email":   claims.Extra.Email,
		})
	})

	// -------------------------------------------------------------------------
	// POST /refresh
	// Body: { "refresh_token": "..." }
	// -------------------------------------------------------------------------
	app.Post("/refresh", func(c fiber.Ctx) error {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}

		mu.RLock()
		// In production: look up user by session ID from the refresh token claims.
		// Here we search by refresh hash for simplicity.
		var found *user
		for _, u := range users {
			if jwtMod.VerifyRefreshTokenHash(req.RefreshToken, u.refreshHash) {
				found = u
				break
			}
		}
		mu.RUnlock()

		if found == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
		}

		newPair, err := jwtMod.RotateTokens(req.RefreshToken, UserClaims{Email: found.email})
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "could not rotate token"})
		}

		// Atomically replace the stored hash in the database.
		mu.Lock()
		found.refreshHash = newPair.RefreshTokenHash
		mu.Unlock()

		return c.JSON(fiber.Map{
			"access_token":  newPair.AccessToken,
			"refresh_token": newPair.RefreshToken,
			"expires_at":    newPair.AccessTokenExpiresAt,
		})
	})

	log.Println("listening on :3000")
	log.Fatal(app.Listen(":3000"))
}
