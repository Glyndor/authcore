package username

// minLength and maxLength are fixed by the library.
// They are not configurable — this is a deliberate security standard,
// not an oversight. A username shorter than 3 characters is ambiguous;
// longer than 32 is impractical and increases attack surface on user-facing forms.
const (
	minLength = 3
	maxLength = 32
)

// defaultReservedNames is the built-in set of names that cannot be registered.
// These cover infrastructure roles, common attack targets, and names that would
// confuse users into believing they are interacting with the service itself.
var defaultReservedNames = []string{
	// Infrastructure and system accounts
	"admin", "administrator", "root", "superuser", "system",
	// API and service identifiers
	"api", "auth", "oauth", "webhook", "service", "daemon", "bot",
	// Protocol and server names
	"www", "ftp", "smtp", "pop", "imap", "mail", "email",
	// Common anonymous / placeholder identities
	"anonymous", "guest", "user", "self",
	// UI / navigation routes that would clash with URL paths
	"login", "logout", "register", "signup", "signin", "signout",
	"settings", "profile", "account", "dashboard", "home",
	// Special values that could cause parsing ambiguity
	"null", "undefined", "none", "true", "false",
	// Environment and support names
	"test", "dev", "prod", "staging", "support", "help", "info",
}
