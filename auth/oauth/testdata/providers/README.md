# Provider fixtures

Real discovery and JWKS documents, fetched anonymously and committed verbatim.
They exist so the parsing this library ships is exercised against what providers
actually send, rather than against a document written from the specification by
the same person who wrote the parser. The Google, Microsoft and Discord
fixtures date from 2026-09-07; the Apple, Facebook, and Vercel fixtures were fetched on 2026-09-27.

| File | Source |
|---|---|
| `google-discovery.json` | `https://accounts.google.com/.well-known/openid-configuration` |
| `google-jwks.json` | `https://www.googleapis.com/oauth2/v3/certs` |
| `microsoft-common-discovery.json` | `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` |
| `microsoft-common-jwks.json` | `https://login.microsoftonline.com/common/discovery/v2.0/keys` |
| `discord-discovery.json` | `https://discord.com/.well-known/openid-configuration` |
| `discord-jwks.json` | `https://discord.com/api/oauth2/keys` |
| `apple-discovery.json` | `https://appleid.apple.com/.well-known/openid-configuration` (fetched 2026-09-27) |
| `apple-jwks.json` | `https://appleid.apple.com/auth/keys` (fetched 2026-09-27) |
| `facebook-discovery.json` | `https://www.facebook.com/.well-known/openid-configuration` (fetched 2026-09-27) |
| `facebook-jwks.json` | `https://www.facebook.com/.well-known/oauth/openid/jwks/` (fetched 2026-09-27) |
| `vercel-discovery.json` | `https://vercel.com/.well-known/openid-configuration` (fetched 2026-09-27) |
| `vercel-jwks.json` | `https://vercel.com/.well-known/jwks` (fetched 2026-09-27) |

GitHub is absent on purpose: it publishes no discovery document
(`https://github.com/.well-known/openid-configuration` answers 404), so its
preset cannot be checked this way and stays an unverified claim.

## What these are, and what they are not

They are a **regression baseline**. A fixture proves the parser handles what a
provider sent on the day it was captured, which is enough to catch a change on
this side that breaks a real document.

They are **not a liveness check**. Do not turn these tests into a scheduled job
that fetches the live endpoints: an informational lane that reddens because
somebody else is having a bad afternoon is a lane people learn to ignore.

Signing keys rotate, so `*-jwks.json` will drift from what the provider serves
today. That is expected and is not a reason to refresh them. Recapture only when
a provider changes the **shape** of what it sends, and say so in the commit.
