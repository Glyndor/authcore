package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The presets this package publishes (Google, Microsoft, GitHub, Discord) were
// hand written from the provider specifications. A hand written preset is an
// unverified claim: it might point at an endpoint the provider retired, or at
// a path the provider never published. The fixtures in testdata/providers/ are
// the real documents those providers served, captured on 2026-09-07, so a test
// that drives the parser against them catches a drift on either side: the
// document or the preset, without making the test a liveness check (a job
// that re-fetches the live endpoints and reddens when somebody else is having
// a bad afternoon).

// fixtureRoundTrip answers requests whose URL is in routes with the bytes the
// test registered, and 404 for everything else. The 404 is deliberate: a typo
// in a test URL would otherwise fall through to a real network fetch (in CI,
// to nothing; on a developer's box, to whatever DNS resolves) and either hang
// or pass for the wrong reason. A 404 surfaces the mistake immediately.
type fixtureRoundTrip struct {
	routes map[string][]byte
}

func (s *fixtureRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	body, ok := s.routes[req.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: 404,
			Status:     "404 Not Found",
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Request:    req,
	}, nil
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/providers/" + name)
	if err != nil {
		t.Fatalf("read fixture testdata/providers/%s: %v", name, err)
	}
	return b
}

func stubClient(routes map[string][]byte) *http.Client {
	return &http.Client{Transport: &fixtureRoundTrip{routes: routes}}
}

// TestPreset_GoogleDiscoveryMatchesGooglePreset pins every URL Google()
// hardcodes against the document Google publishes at its real OIDC discovery
// URL. The comparison is byte for byte against Google(), not against literals,
// so a change to either side flips the test in the right direction: editing
// the preset is the action the test is asking the maintainer to confirm.
func TestPreset_GoogleDiscoveryMatchesGooglePreset(t *testing.T) {
	t.Parallel()
	routes := map[string][]byte{
		"https://accounts.google.com/.well-known/openid-configuration": readFixture(t, "google-discovery.json"),
	}
	got, err := Discover(context.Background(),
		"https://accounts.google.com", stubClient(routes))
	if err != nil {
		t.Fatalf("Discover(google): %v", err)
	}
	want := Google()
	if got.Issuer != want.Issuer || got.AuthURL != want.AuthURL ||
		got.TokenURL != want.TokenURL || got.JWKSURL != want.JWKSURL {
		t.Fatalf("Google preset does not match the live discovery document:\n preset: %+v\n live:   %+v",
			want, got)
	}
}

// TestPreset_MicrosoftCommonDiscoveryRefusesTheTemplateIssuer pins the
// documented multi-tenant caveat: the "common" discovery document publishes
// its issuer as the literal template
// https://login.microsoftonline.com/{tenantid}/v2.0, so the OIDC requirement
// that the document's issuer equal the requested one cannot be satisfied with
// /common/v2.0. Discover must reject the request and the rejection must
// wrap ErrDiscovery and name the mismatch. Otherwise a regression that
// "fixes" Discover by stripping the issuer check would also pass this test.
func TestPreset_MicrosoftCommonDiscoveryRefusesTheTemplateIssuer(t *testing.T) {
	t.Parallel()
	routes := map[string][]byte{
		"https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration": readFixture(t, "microsoft-common-discovery.json"),
	}
	_, err := Discover(context.Background(),
		"https://login.microsoftonline.com/common/v2.0", stubClient(routes))
	if err == nil {
		t.Fatal("Discover(common/v2.0) must fail: the document's issuer is a per-tenant template, not /common/v2.0")
	}
	if !errors.Is(err, ErrDiscovery) {
		t.Fatalf("rejection must wrap ErrDiscovery, got: %v", err)
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("rejection must name the issuer mismatch, got: %v", err)
	}
	if !strings.Contains(err.Error(), "{tenantid}") {
		t.Fatalf("rejection must surface the template issuer from the document, got: %v", err)
	}
}

// TestPreset_AzureMultiTenantIssuer pins the validator returned by
// AzureMultiTenantIssuer: it must accept a concrete per-tenant issuer (the
// only issuer a real Azure AD ID token carries) and refuse the multi-tenant
// aliases and the template string itself. A validator that accepts the
// template would be an oracle: any token whose iss is the literal template
// passes, and the template is not a tenant at all.
func TestPreset_AzureMultiTenantIssuer(t *testing.T) {
	t.Parallel()
	validate := AzureMultiTenantIssuer()
	const concrete = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	if !validate(concrete) {
		t.Errorf("a concrete per-tenant issuer must be accepted: %s", concrete)
	}
	for _, reject := range []string{
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/organizations/v2.0",
		"https://login.microsoftonline.com/{tenantid}/v2.0",
		"https://login.microsoftonline.com",
		"https://login.microsoftonline.com/not-a-guid/v2.0",
	} {
		if validate(reject) {
			t.Errorf("alias/template issuer must be rejected: %s", reject)
		}
	}
}

// TestPreset_DiscordDiscoveryParsesAndMatchesPresetTokenURL pins two things
// and explicitly does NOT pin a third: the discovery document parses, its
// jwks_uri and token_endpoint are present, and its token_endpoint equals
// what Discord() hardcodes. authorization_endpoint is left alone: the preset
// says /oauth2/authorize and the live document says /api/oauth2/authorize,
// and both endpoints answer. That divergence is a decision, not a bug, and
// freezing it either way in a test would make the decision hard to revisit.
func TestPreset_DiscordDiscoveryParsesAndMatchesPresetTokenURL(t *testing.T) {
	t.Parallel()
	routes := map[string][]byte{
		"https://discord.com/.well-known/openid-configuration": readFixture(t, "discord-discovery.json"),
	}
	got, err := Discover(context.Background(),
		"https://discord.com", stubClient(routes))
	if err != nil {
		t.Fatalf("Discover(discord): %v", err)
	}
	if got.JWKSURL == "" {
		t.Fatal("jwks_uri must be present in the discord discovery document")
	}
	if got.TokenURL == "" {
		t.Fatal("token_endpoint must be present in the discord discovery document")
	}
	if got.TokenURL != Discord().TokenURL {
		t.Fatalf("Discord preset's TokenURL does not match the live document:\n preset: %s\n live:   %s",
			Discord().TokenURL, got.TokenURL)
	}
}

// TestPreset_DiscoveryDocumentIgnoresUnknownFields is the single most
// valuable assertion in this file. The decoder this module ships reads a
// fixed set of fields out of the discovery document and ignores the rest;
// the fixtures carry a long tail of OIDC extensions that a hand-written
// fixture would never include (Microsoft's "cloud_instance_name",
// "mtls_endpoint_aliases", "claims_supported", Discord's
// "subject_types_supported", Google's "code_challenge_methods_supported",
// and so on). A future tightening of the decoder (DisallowUnknownFields, a
// typed-map round trip) would break every real document this library is
// meant to handle, and a hand-written fixture would not catch it, so the
// test drives the real Discover through the fixture transport rather than
// decoding into a separate struct.
func TestPreset_DiscoveryDocumentIgnoresUnknownFields(t *testing.T) {
	t.Parallel()
	for name, file := range map[string]string{
		"google":    "google-discovery.json",
		"microsoft": "microsoft-common-discovery.json",
		"discord":   "discord-discovery.json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var issuer, wellKnown string
			switch name {
			case "google":
				issuer = "https://accounts.google.com"
			case "microsoft":
				issuer = "https://login.microsoftonline.com/common/v2.0"
				// The common/v2.0 document uses a template issuer, which
				// Discover rightly rejects, but the path the decoder takes
				// up to that rejection (json.Unmarshal of the whole document)
				// still has to accept the unknown fields. The well-known URL
				// is what the transport serves; the issuer mismatch only
				// fires after decoding.
				wellKnown = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
			case "discord":
				issuer = "https://discord.com"
			}
			if wellKnown == "" {
				wellKnown = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
			}
			routes := map[string][]byte{
				wellKnown: readFixture(t, file),
			}
			_, err := Discover(context.Background(), issuer, stubClient(routes))
			// Microsoft fails with the documented template issuer mismatch,
			// accept that explicitly so this test only fires on a decoder
			// regression (the mismatch is discovered only after the decoder
			// has parsed the whole document, including every unknown field).
			if name == "microsoft" {
				if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
					t.Fatalf("%s: Discover must surface the template mismatch, got %v", file, err)
				}
				return
			}
			// Google and Discord documents match the issuer and decode
			// cleanly: any error here means the decoder choked on an
			// unknown field, which is what this test guards against.
			if err != nil {
				t.Fatalf("%s: decoder refused an unknown field, got %v", file, err)
			}
			// No error means Discover accepted the document, including the
			// unknown fields the fixtures carry.
		})
	}
}

// TestPreset_EveryAdvertisedAlgIsAccepted reads each fixture's
// id_token_signing_alg_values_supported array and asserts that every
// algorithm in it is one the module accepts (idTokenAlgs in idtoken.go).
// That is the direction that breaks interoperability: the day a provider
// starts signing ID tokens with an algorithm this verifier rejects, every
// login through that preset fails, and a fixture recaptured after such a
// change is what makes it visible here rather than in production.
//
// The reverse containment is deliberately not asserted. The module accepts a
// superset on purpose, because providers publish only what they currently
// sign with (RS256 in all three fixtures on 2026-09-07) and never the tail a
// verifier is willing to accept. Requiring the full set would fail today and
// forever, for a reason that is not a defect.
//
// The list is also asserted non-empty first. Without that, a fixture whose
// array is missing or empty would satisfy the loop below by never entering
// it, and the test would report a pass it never earned.
func TestPreset_EveryAdvertisedAlgIsAccepted(t *testing.T) {
	t.Parallel()
	accepted := make(map[string]struct{}, len(idTokenAlgs))
	for _, alg := range idTokenAlgs {
		accepted[alg] = struct{}{}
	}
	for name, file := range map[string]string{
		"google":    "google-discovery.json",
		"microsoft": "microsoft-common-discovery.json",
		"discord":   "discord-discovery.json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var doc struct {
				Algs []string `json:"id_token_signing_alg_values_supported"`
			}
			if err := json.Unmarshal(readFixture(t, file), &doc); err != nil {
				t.Fatalf("decode %s: %v", file, err)
			}
			if len(doc.Algs) == 0 {
				t.Fatalf("%s advertises no id_token_signing_alg_values_supported; the containment check below would pass vacuously", file)
			}
			for _, alg := range doc.Algs {
				if _, ok := accepted[alg]; !ok {
					t.Errorf("%s advertises %q, which the module rejects; accepted set is %v, so every ID token signed with %q would fail the alg check",
						file, alg, idTokenAlgs, alg)
				}
			}
		})
	}
}

// TestFixture_JWKSKeysParseAndAreKeyTypeConformant walks every key in every
// JWKS fixture, runs it through parseJWK, and checks the decoded public key
// is the type the kty field declares. The key count is asserted as greater
// than zero and never as a fixed number, so a future recapture that picks
// up a rotation does not break this test for the wrong reason.
func TestFixture_JWKSKeysParseAndAreKeyTypeConformant(t *testing.T) {
	t.Parallel()
	for name, file := range map[string]string{
		"google":    "google-jwks.json",
		"microsoft": "microsoft-common-jwks.json",
		"discord":   "discord-jwks.json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var doc jwksDoc
			if err := json.Unmarshal(readFixture(t, file), &doc); err != nil {
				t.Fatalf("decode %s: %v", file, err)
			}
			if len(doc.Keys) == 0 {
				t.Fatalf("%s has no keys", file)
			}
			for i, k := range doc.Keys {
				pub, err := parseJWK(k)
				if err != nil {
					t.Errorf("key %d (kid=%q kty=%q) failed to parse: %v", i, k.Kid, k.Kty, err)
					continue
				}
				switch k.Kty {
				case "RSA":
					if _, ok := pub.(*rsa.PublicKey); !ok {
						t.Errorf("key %d (kid=%q) declared RSA but decoded to %T", i, k.Kid, pub)
					}
				case "EC":
					if _, ok := pub.(*ecdsa.PublicKey); !ok {
						t.Errorf("key %d (kid=%q) declared EC but decoded to %T", i, k.Kid, pub)
					}
				default:
					t.Errorf("key %d (kid=%q) has unknown kty %q", i, k.Kid, k.Kty)
				}
			}
		})
	}
}
