package oauth

// DiscoverOption changes how Discover treats the endpoints a discovery
// document advertises.
type DiscoverOption func(*discoverOptions)

type discoverOptions struct{ allowPrivate bool }

// AllowPrivateNetwork lets the document advertise endpoints on private,
// link-local or otherwise internal addresses, and lets a client built by
// Discover reach them. Pass it only for an on-premises provider whose
// endpoints really live on an internal network; see Config.AllowPrivateNetwork.
func AllowPrivateNetwork() DiscoverOption {
	return func(o *discoverOptions) { o.allowPrivate = true }
}
