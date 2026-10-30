package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// maxBodyBytes caps a request body. Every body of this API is a small JSON
	// object; without a cap, Gin reads whatever the client sends.
	maxBodyBytes = 16 << 10

	// maxLoginPassword caps the password bytes login hashes. Verify applies no
	// length policy, so the bound belongs here. Registration already refuses
	// more than the policy's maximum.
	maxLoginPassword = 1024

	// decoyPassword is hashed once at startup. It protects nothing: it only
	// gives login something to verify against when the account is unknown.
	decoyPassword = "Decoy-P@ssw0rd-never-matches!"
)

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

// hardening runs before every route. It caps the body, and marks every
// response as uncacheable: they carry tokens, and a shared cache or a browser
// history must never keep one.
func hardening(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
	c.Next()
}

// badBody answers a body that did not bind: 413 when it exceeded the cap,
// 400 otherwise. The message never echoes the decoder's complaint.
func badBody(c *gin.Context, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
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

// newServer wraps h in an http.Server with every timeout set. Gin's Run
// builds a server with none, which leaves the process open to clients that
// hold connections without finishing a request.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
