package email

// Config holds the email module's policy options.
//
// Today's behaviour is reproduced by the zero value, so callers that do not
// need to override anything can keep using New(p). NewWithConfig is the
// addition: it takes the policy explicitly.
type Config struct {
	// RejectPlusAddressing rejects addresses whose local part contains a
	// '+'. When false (the default), plus-addressing is accepted - the same
	// behaviour the module has always had.
	//
	// This is an account-uniqueness rule, not a security control. RFC 5233
	// defines plus-addressing so that user+anything@example.com and
	// user@example.com share one mailbox. Accepting it lets one mailbox own
	// N accounts: if your product treats (local, domain) as the unique key,
	// turn this on.
	RejectPlusAddressing bool
}
