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
	"fmt"
	"log"
	"strings"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/gofiber/fiber/v3"
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

	app := newApp(pwdMod, jwtMod)

	log.Println("listening on :3000")
	log.Fatal(app.Listen(":3000"))
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

// newApp builds the Fiber app with every route of the example wired to pwdMod
// and jwtMod, over a fresh empty user store. main serves it, and the tests
// drive the same app through app.Test.
func newApp(pwdMod *password.Password, jwtMod *jwt.JWT[UserClaims]) *fiber.App {
	db := newStore()
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
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "email already registered"})
		}

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

		u, exists := db.findByEmail(req.Email)
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
		if !db.setRefreshHash(u.email, pair.RefreshTokenHash) {
			// The account disappeared between the lookup and this write.
			// Fail closed: tokens whose hash was not stored must not be sent.
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}

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

		// 1. Look the session up by the hash of the presented token, then
		//    confirm the match in constant time.
		presented, hashErr := jwtMod.HashRefreshToken(req.RefreshToken)
		if hashErr != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}
		found, ok := db.findByRefreshHash(presented)
		if !ok || !jwtMod.VerifyRefreshTokenHash(req.RefreshToken, found.refreshHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
		}

		// 2. Mint outside any lock. RotateTokens checks signature and expiry.
		//    Nothing minted here may reach the client before step 3 succeeds.
		newPair, err := jwtMod.RotateTokens(req.RefreshToken, UserClaims{Email: found.email})
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "could not rotate token"})
		}

		// 3. Consume the presented token: swap its hash for the new one only
		//    if it is still the stored one. The lookup in step 1 is not enough,
		//    because a concurrent redemption of the same token passes it too.
		//    Whoever loses this swap gets 401 and its minted pair is dropped.
		if !db.swapRefreshHash(found.email, presented, newPair.RefreshTokenHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
		}

		return c.JSON(fiber.Map{
			"access_token":  newPair.AccessToken,
			"refresh_token": newPair.RefreshToken,
			"expires_at":    newPair.AccessTokenExpiresAt,
		})
	})

	return app
}
