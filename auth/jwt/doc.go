// Package jwt provides JSON Web Token (JWT) authentication for authcore.
//
// Tokens are signed with Ed25519 (alg=EdDSA) using keys managed by authcore's
// key manager. Token encoding is handled by github.com/golang-jwt/jwt/v5.
//
// # Token strategy
//
// Two token kinds are issued:
//
//   - Access token  — short-lived (default 15 min), sent in Authorization: Bearer.
//   - Refresh token — long-lived  (default 24 h),  stored securely by the client.
//
// # Custom claims
//
// JWT is generic over T, which holds application-specific fields embedded
// in the access token payload under the "extra" key. The refresh token never
// carries custom claims.
//
//	type UserClaims struct {
//	    Name string `json:"name"`
//	    Role string `json:"role"`
//	}
//
//	jwtMod, _ := jwt.New[UserClaims](auth, jwt.DefaultConfig())
//
// # Storage model
//
// The library is storage-agnostic. It returns a hashed form of the refresh
// token that the application stores in its database. The raw token is never
// persisted by the library.
//
// # Typical server-side flow
//
//	// 1. Initialise once at startup.
//	auth, _    := authcore.New(authcore.DefaultConfig())
//	jwtMod, _ := jwt.New[UserClaims](auth, jwt.DefaultConfig())
//
//	// 2. Login — create a token pair for the authenticated user.
//	pair, _ := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "admin"})
//	sendToBrowser(pair.AccessToken, pair.RefreshToken)
//	db.StoreRefreshHash(userID, pair.RefreshTokenHash)
//
//	// 3. Authenticated request — verify the access token on each call.
//	claims, err := jwtMod.VerifyAccessToken(accessToken)
//	if err != nil { ... } // errors.Is(err, jwt.ErrTokenExpired)
//	fmt.Println(claims.Extra.Name)
//
//	// 4. Token rotation — verify the hash first (timing-safe), then rotate.
//	if !jwtMod.VerifyRefreshTokenHash(clientToken, storedHash) {
//	    return http.StatusUnauthorized
//	}
//	user, _ := db.GetUser(userID)
//	newPair, _ := jwtMod.RotateTokens(clientToken, UserClaims{Name: user.Name, Role: user.Role})
//	db.ReplaceRefreshHash(storedHash, newPair.RefreshTokenHash)
//	sendToBrowser(newPair.AccessToken, newPair.RefreshToken)
package jwt
