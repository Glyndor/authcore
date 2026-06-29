# auth/apikey — opaque API key example

Issue an opaque API key, then verify a presented key the way a request handler
would (parse the id, look up the stored hash, constant-time compare).

## Run

```bash
go run ./examples/apikey
```

## What it shows

| Step | API |
|---|---|
| Issue — key to show once, id + hash to store | `keyMod.Generate()` |
| Extract the lookup id from a presented key | `keyMod.ParseID(key)` |
| Verify in constant time | `keyMod.Verify(key, storedHash)` |

The library stores nothing — you persist `key.ID` (lookup) and `key.Hash`, never
the raw key. See [API keys](../../docs/apikey.md).
