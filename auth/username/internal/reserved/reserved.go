// Package reserved is the set of usernames that cannot be registered: the
// built-in list and the additions and removals a deployment configures.
package reserved

// Defaults is the built-in set of names that cannot be
// registered by default. These cover infrastructure roles, common attack
// targets, and names that would confuse users into believing they are
// interacting with the service itself.
//
// A deployment that needs one of these names - for example, a company that
// runs a real "support" account - passes it in Config.AllowReservedNames.
var Defaults = []string{
	// Infrastructure and system accounts
	"admin", "administrator", "root", "superuser", "system",
	// API and service identifiers
	"api", "auth", "oauth", "webhook", "service", "daemon", "bot",
	// Protocol and server names
	"www", "ftp", "smtp", "pop", "imap", "mail", "email",
	// Mailboxes a certificate authority or a mail system writes to: the
	// CA/Browser Forum domain-validation addresses (admin, administrator,
	// webmaster, hostmaster, postmaster) and the usual bounce and abuse ones.
	"webmaster", "hostmaster", "postmaster", "abuse", "noreply", "no-reply",
	"mailer-daemon", "security",
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

// Set builds the final reserved-name lookup set from the configured
// additions and removals applied to the built-in list. Names already present
// in extra are deduped against the built-in list. Both lists must already be
// normalised (lowercase + trimmed) so lookups can use the same form the
// module's normalisation produces for the input.
func Set(extra, allow []string) map[string]struct{} {
	// Start with the built-in blocklist.
	set := make(map[string]struct{}, len(Defaults)+len(extra))
	for _, name := range Defaults {
		set[name] = struct{}{}
	}

	// Additions. Already normalized; duplicates against the built-in list
	// collapse harmlessly into the same map slot.
	for _, name := range extra {
		set[name] = struct{}{}
	}

	// Removals. Removing a name that was never reserved is a no-op.
	for _, name := range allow {
		delete(set, name)
	}

	return set
}
