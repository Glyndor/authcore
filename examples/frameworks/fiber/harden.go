package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

const (
	// maxBodyBytes caps a request body. Every body of this API is a small JSON
	// object. Fiber's default is 4 MiB, far more than any of them needs.
	maxBodyBytes = 16 << 10

	// maxLoginPassword caps the password bytes login hashes. Verify applies no
	// length policy, so the bound belongs here. Registration already refuses
	// more than the policy's maximum.
	maxLoginPassword = 1024

	// decoyPassword is hashed once at startup. It protects nothing: it only
	// gives login something to verify against when the account is unknown.
	decoyPassword = "Decoy-P@ssw0rd-never-matches!"
)

// newConfig returns the Fiber settings the server runs with: a small body cap,
// every timeout set, and an error handler that never prints an internal
// message.
func newConfig() fiber.Config {
	return fiber.Config{
		BodyLimit:    maxBodyBytes,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		ErrorHandler: errorHandler,
	}
}

// errorHandler turns any error that reaches Fiber into a JSON answer. Fiber's
// own default writes err.Error() to the client, which for a recovered panic or
// an unexpected failure is an internal message.
func errorHandler(c fiber.Ctx, err error) error {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return c.Status(fe.Code).JSON(fiber.Map{"error": http.StatusText(fe.Code)})
	}
	log.Printf("unhandled error: %v", err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
}

const (
	// maxConcurrentHashes bounds the Argon2id derivations that run at once.
	// Each one holds the profile's memory (64 MiB by default) until it ends,
	// and /register and /login are open to anyone, so without a bound N
	// connections hold N times that: 64 concurrent logins measured 3.1 GiB.
	maxConcurrentHashes = 4
)

// hashWait is how long a request waits for a derivation slot before it is
// refused with 503. It is a variable so a test can shorten it.
var hashWait = 2 * time.Second

var hashSlots = make(chan struct{}, maxConcurrentHashes)

// acquireHash waits for a derivation slot, for at most hashWait or until ctx
// ends. release must be called when the derivation is done.
func acquireHash(ctx context.Context) (release func(), ok bool) {
	ctx, cancel := context.WithTimeout(ctx, hashWait)
	defer cancel()
	select {
	case hashSlots <- struct{}{}:
		return func() { <-hashSlots }, true
	case <-ctx.Done():
		return nil, false
	}
}

// hardening runs before every route. It marks every response as uncacheable:
// they carry tokens, and a shared cache or a browser history must never keep
// one.
func hardening(c fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	c.Set("X-Content-Type-Options", "nosniff")
	return c.Next()
}

// badBody answers a body that did not bind. The message never echoes the
// decoder's complaint.
func badBody(c fiber.Ctx) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
}

// bearerToken extracts the token from the Authorization header values of a
// request. It fails closed: more than one header is refused, because proxies
// and servers disagree on which of them counts. The scheme is matched without
// regard to case, as RFC 7235 requires, and exactly one space separates it
// from a token that holds no whitespace.
func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
