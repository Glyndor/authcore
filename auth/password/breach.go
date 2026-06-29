package password

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by the HaveIBeenPwned range API; it guards a k-anonymity prefix lookup, never password storage (that is Argon2id).
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

// BreachChecker reports whether a plaintext password appears in a known data
// breach corpus. It is the opt-in complement to the built-in policy: length
// and composition rules keep out structurally weak passwords, while a breach
// check keeps out passwords that are structurally fine but already public.
//
// Implementations must never transmit the full password. A network-backed
// implementation must use k-anonymity — send only a short hash prefix and
// compare suffixes locally (see HIBPChecker).
//
// The interface takes a context so a network implementation can honour a
// deadline; an offline implementation may ignore it.
type BreachChecker interface {
	// IsBreached reports whether plaintext appears in the breach corpus.
	// The boolean is only meaningful when the error is nil; on error the
	// caller must decide whether to fail open or closed for its threat model.
	IsBreached(ctx context.Context, plaintext string) (bool, error)
}

// CheckBreached reports whether plaintext appears in a known data breach,
// using the BreachChecker configured in Config.BreachChecker.
//
// It is a no-network-by-default, opt-in step — mirroring the email module's
// VerifyDomain. Configure a checker to enable it:
//
//	cfg := password.DefaultConfig()
//	cfg.BreachChecker = password.NewHIBPChecker()
//	pwdMod, _ := password.New(auth, cfg)
//
//	// Registration / password change, after ValidatePolicy:
//	if err := pwdMod.CheckBreached(ctx, req.Password); err != nil {
//	    if errors.Is(err, password.ErrBreachedPassword) {
//	        c.JSON(400, gin.H{"error": "this password has appeared in a data breach, choose another"})
//	        return
//	    }
//	    log.Printf("breach check unavailable: %v", err) // network error — decide your policy
//	}
//
// plaintext is normalised to Unicode NFC before the lookup, matching Hash and
// Verify, so the check is consistent across platforms.
//
// Returns:
//
//	nil                     — the password was not found in the corpus
//	ErrBreachedPassword     — the password was found (CLIENT-SAFE; ask for a new one)
//	ErrNoBreachChecker      — no checker is configured (programming error)
//	a wrapped checker error — the lookup itself failed (e.g. network/DNS); treat
//	                          as a soft failure unless your threat model needs fail-closed
func (p *Password) CheckBreached(ctx context.Context, plaintext string) error {
	if p.cfg.BreachChecker == nil {
		return ErrNoBreachChecker
	}
	breached, err := p.cfg.BreachChecker.IsBreached(ctx, norm.NFC.String(plaintext))
	if err != nil {
		return fmt.Errorf("password: breach check: %w", err)
	}
	if breached {
		return ErrBreachedPassword
	}
	return nil
}

// ----- HaveIBeenPwned (k-anonymity) ------------------------------------------

// hibpDefaultBaseURL is the HaveIBeenPwned Pwned Passwords range endpoint.
const hibpDefaultBaseURL = "https://api.pwnedpasswords.com"

// hibpDefaultTimeout bounds a single range request so a slow or unreachable
// service cannot stall a registration handler indefinitely. The per-call
// context still takes precedence when it has a shorter deadline.
const hibpDefaultTimeout = 5 * time.Second

// HIBPChecker is a BreachChecker backed by the HaveIBeenPwned Pwned Passwords
// range API using k-anonymity: it hashes the password with SHA-1, sends only
// the first five hex characters of the digest, and compares the 35-character
// suffixes returned by the service locally. The full password and its full
// hash never leave the process.
//
// Construct it with NewHIBPChecker and reuse it; it is safe for concurrent use.
type HIBPChecker struct {
	client  *http.Client
	baseURL string
}

// HIBPOption customises a HIBPChecker.
type HIBPOption func(*HIBPChecker)

// WithHTTPClient sets the HTTP client used for range requests.
// Use this to share a tuned client (proxy, transport, timeouts) across modules.
func WithHTTPClient(c *http.Client) HIBPOption {
	return func(h *HIBPChecker) {
		if c != nil {
			h.client = c
		}
	}
}

// WithBaseURL overrides the HaveIBeenPwned base URL.
// Intended for tests and for self-hosted/mirrored range endpoints.
func WithBaseURL(u string) HIBPOption {
	return func(h *HIBPChecker) {
		if u != "" {
			h.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// NewHIBPChecker returns a HIBPChecker with sensible defaults (a 5-second
// client timeout and the public HaveIBeenPwned endpoint). Override with options:
//
//	checker := password.NewHIBPChecker(
//	    password.WithHTTPClient(myClient),
//	)
func NewHIBPChecker(opts ...HIBPOption) *HIBPChecker {
	h := &HIBPChecker{
		client:  &http.Client{Timeout: hibpDefaultTimeout},
		baseURL: hibpDefaultBaseURL,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// IsBreached implements BreachChecker against the HaveIBeenPwned range API.
//
// It never transmits the password or its full hash: only the first five hex
// characters of the SHA-1 digest are sent, and the matching suffix is searched
// in the response. The "Add-Padding" header is set so the response size does
// not leak whether the prefix had many or few matches; padding entries (count
// 0) are ignored.
func (h *HIBPChecker) IsBreached(ctx context.Context, plaintext string) (bool, error) {
	sum := sha1.Sum([]byte(plaintext)) //nolint:gosec // k-anonymity prefix hash for the HIBP API, not password storage.
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	url := h.baseURL + "/range/" + prefix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	// Ask the service to pad the response so its length does not reveal how
	// many suffixes share this prefix.
	req.Header.Set("Add-Padding", "true")

	resp, err := h.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("range request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded amount so the connection can be reused, then report.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("range request: unexpected status %d", resp.StatusCode)
	}

	// Each line is "SUFFIX:COUNT". A real match has COUNT > 0; padding lines
	// carry COUNT 0 and are skipped. Suffix comparison is case-insensitive
	// because the API returns uppercase hex.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		sep := strings.IndexByte(line, ':')
		if sep < 0 {
			continue
		}
		if !strings.EqualFold(line[:sep], suffix) {
			continue
		}
		// Found the suffix; treat any non-"0" count as breached.
		count := strings.TrimSpace(line[sep+1:])
		return count != "" && count != "0", nil
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read range response: %w", err)
	}
	return false, nil
}

// ----- Local list ------------------------------------------------------------

// ListChecker is an offline BreachChecker backed by an in-memory set of known
// breached passwords. Use it to embed a curated list (e.g. the most common
// passwords) without any network dependency.
//
// Lookups are O(1) and constant across inputs. The set is built once and is
// safe for concurrent use.
type ListChecker struct {
	set map[string]struct{}
}

// NewListChecker builds a ListChecker from the given passwords. Each entry is
// normalised to Unicode NFC so lookups match CheckBreached's normalisation.
// Duplicates are collapsed.
func NewListChecker(passwords []string) *ListChecker {
	set := make(map[string]struct{}, len(passwords))
	for _, pw := range passwords {
		set[norm.NFC.String(pw)] = struct{}{}
	}
	return &ListChecker{set: set}
}

// IsBreached implements BreachChecker. It reports whether plaintext is present
// in the list. The error is always nil; the lookup is local and cannot fail.
func (l *ListChecker) IsBreached(_ context.Context, plaintext string) (bool, error) {
	_, ok := l.set[norm.NFC.String(plaintext)]
	return ok, nil
}
