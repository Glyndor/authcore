// Package email provides email address validation and normalization for authcore.
//
// Validation follows RFC 5321 and RFC 5322 rules:
//   - Total length 1–254 characters
//   - Exactly one @ separating a non-empty local part and domain
//   - Local part ≤ 64 characters
//   - Domain contains at least one dot; no leading, trailing, or consecutive dots
//   - Each domain label is 1–63 characters
//
// Internationalised domain names (IDN) are supported: a Unicode domain such
// as "münchen.de" is converted to its ASCII punycode form ("xn--mnchen-3ya.de")
// during normalisation, matching what DNS actually resolves. Store the
// canonical ASCII form in your database so lookups are deterministic.
//
// Plus-addressing (`user+tag@example.com`) is accepted by default. A
// deployment that treats `(local, domain)` as the unique account key can
// opt in to [Config.RejectPlusAddressing] - this is a
// [configurable policy field](../docs/guides/configuration.md#the-principle),
// not a security control. The structural rules above stay fixed.
//
// The single entry point is [Email.ValidateAndNormalize] — it normalizes
// (lowercase + trim + punycode) and validates in one step, returning the
// canonical form.
// Always store and query emails using this canonical form:
//
//	emailMod, _ := email.New(auth)
//
//	// Registration
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...)
//
//	// Login lookup — same call, same canonical form, consistent results
//	normalized, err = emailMod.ValidateAndNormalize(req.Email)
//	if err != nil { ... }
//	user := db.FindByEmail(normalized)
//
// # Confusable characters in the local part
//
// The local part is opaque. It is brought to NFC and lowercased, and invisible
// and control characters are refused, but characters that merely look alike are
// not folded: "\u0430lice@example.com" (Cyrillic "a") and "alice@example.com"
// (Latin "a") are two different, both valid, canonical addresses. That is the
// design, not an oversight: only the receiving mail server can say which
// spellings reach the same mailbox, and RFC 5321 treats the local part as
// opaque, so the module has no sound rule to fold them by. An application that
// needs robust uniqueness or wants to block look-alike impersonation must apply
// its own policy before storing the address, for example restrict the local
// part to ASCII, or reject a mix of scripts. The domain is different: IDNA
// converts it to punycode, so a look-alike domain shows up as an "xn--" name.
//
// # Domain MX verification
//
// VerifyDomain performs an optional DNS MX lookup to confirm the domain can
// receive email. Results are cached per domain for [DefaultCacheTTL]
// (5 minutes by default) to avoid repeated lookups for the same domain.
// The Go stdlib LookupMX API does not surface DNS TTLs, so entries are
// held for the fixed [DefaultCacheTTL] regardless of the authority
// section of the response.
// This check is network I/O — always call it after ValidateAndNormalize and
// handle [ErrDomainUnresolvable] as a soft failure:
//
//	err = emailMod.VerifyDomain(ctx, normalized)
//	if errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
//	if errors.Is(err, email.ErrDomainUnresolvable) {
//	    log.Warn("DNS check unavailable: %v", err) // do not block the user
//	}
package email
