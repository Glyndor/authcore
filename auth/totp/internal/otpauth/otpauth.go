// Package otpauth builds the otpauth:// URI an authenticator app scans as a
// QR code.
package otpauth

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/Glyndor/authcore/auth/totp/internal/hotp"
)

// URI assembles the otpauth:// URI for the enrollment.
//
// With issuer set:
//
//	otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}
//
// Both issuer occurrences are percent-encoded; the colon between them
// stays literal (it is structural). With issuer empty:
//
//	otpauth://totp/{account}?secret={secret}
//
// The authenticator algorithm, digits and period are also included so
// any client that does parse them sees the closed defaults.
func URI(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("algorithm", hotp.Algo)
	q.Set("digits", strconv.Itoa(hotp.Digits))
	q.Set("period", strconv.Itoa(hotp.TimeStep))

	// The label is written as text rather than through url.URL: Path is the
	// decoded field, so the escaped label put there was escaped a second
	// time and an issuer "Acme Corp" reached the authenticator as
	// "Acme%20Corp" (measured 2026-09-25). A colon inside the issuer or the
	// account is escaped too, so the one literal colon stays the separator.
	label := escapeLabelPart(account)
	if issuer != "" {
		label = escapeLabelPart(issuer) + ":" + label
		q.Set("issuer", issuer)
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// escapeLabelPart percent-encodes one side of an otpauth label, including
// any colon, which the label reserves as its separator.
func escapeLabelPart(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}
