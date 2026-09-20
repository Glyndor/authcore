# Field-level encryption with a blind index

`auth/field` encrypts a single column's value and produces a separate
"blind index" that lets the database enforce uniqueness on the
encrypted value without ever seeing the plaintext. The case that
drives it: store a user's email address encrypted, and still enforce
one account per address.

The module does three things: it makes the ciphertext unreadable
(AES-256-GCM with a fresh nonce per call), it makes a stolen
ciphertext from one column useless against another (the column name
is bound into the GCM additional authenticated data), and it gives
the caller a deterministic hash of the plaintext under the same
binding so a `UNIQUE` index on the index column enforces one
account per email. The library never stores anything; you own the
database. See the [error reference](errors.md).

## Setup

```go
cfg := authcore.DefaultConfig()
cfg.RequireExistingKeys = true // refuse to run if KeysDir is missing
                              // or empty: a fresh key set would silently
                              // invalidate every ciphertext and blind
                              // index already in the database.
auth, err := authcore.New(cfg)
fld, err := field.New(auth, field.Config{Context: "email"})
// One module per column. Context is the column name; it is bound
// into the AAD and the index so a ciphertext from "email" cannot
// be decrypted as "phone".
fldPhone, err := field.New(auth, field.Config{Context: "phone"})
```

`RequireExistingKeys` is the load-only flag on `authcore.Config` (see
[Key management](key-management.md)). Leaving it at its zero value lets the
library generate a fresh key set on first start; if the configured `KeysDir`
later goes missing or is empty, `New` succeeds with brand-new material and
every existing row becomes permanently undecryptable.

`Context` has no default. An empty value is rejected at `New` with
`field.ErrInvalidConfig`, because silently accepting `""` would
make every field share one keyspace and the whole point of the
binding would vanish.

## Encrypted email with uniqueness, end to end

```sql
-- The table shape. ciphertext stores the encrypted email; idx
-- stores the blind index. The UNIQUE index on idx is what gives
-- "one account per address" without the database ever seeing the
-- plaintext.
CREATE TABLE users (
    id    BIGSERIAL PRIMARY KEY,
    email_ct TEXT NOT NULL,    -- field.Encrypt(plaintext)
    email_idx TEXT NOT NULL    -- field.BlindIndex(plaintext)
);
CREATE UNIQUE INDEX users_email_idx_uniq ON users (email_idx);
```

```go
// 1. Normalise the input. The module never normalises; index the
//    same form you store, every time, or lookups miss. auth/email
//    and auth/username both do this.
plain := strings.ToLower(strings.TrimSpace(userInput))

// 2. Encrypt the plaintext for storage. The output drops into a
//    TEXT column as is; a BYTEA-style column can store the raw
//    bytes via base64.RawStdEncoding.DecodeString.
ct, err := fldEmail.Encrypt(plain)
if err != nil { return serverError() }

// 3. Produce the blind index the UNIQUE constraint runs against.
idx, err := fldEmail.BlindIndex(plain)
if err != nil { return serverError() }

// 4. Insert. ON CONFLICT (email_idx) DO NOTHING enforces uniqueness
//    at the database; the application learns whether the row was
//    taken via RowsAffected.
res, err := db.Exec(`
    INSERT INTO users (email_ct, email_idx) VALUES ($1, $2)
    ON CONFLICT (email_idx) DO NOTHING`,
    ct, idx)
if err != nil { return serverError() }
n, _ := res.RowsAffected()
if n == 0 { return conflictError() } // generic: "could not create account"

// 5. Login path: hash the candidate, look up the row, then decrypt.
candidate, err := fldEmail.BlindIndex(strings.ToLower(strings.TrimSpace(form.Email)))
if err != nil { return serverError() }
row := db.QueryRow(`SELECT email_ct FROM users WHERE email_idx = $1`, candidate)
var stored string
if err := row.Scan(&stored); err != nil { return notFound() }
plain, err := fldEmail.Decrypt(stored)
if err != nil { return serverError() }
// An index hit is not the same as a plaintext match. Nothing in the
// database schema prevents a row holding BlindIndex("alice") next to
// Encrypt("bob"), so the lookup succeeds while the decrypted value is
// not what was indexed. Confirm by recomputing the index of the
// decrypted value and comparing; reject on mismatch.
check, err := fldEmail.BlindIndex(plain)
if err != nil { return serverError() }
if check != candidate {
    return notFound()
}
```

The `ON CONFLICT (email_idx) DO NOTHING` pattern is the whole
point: the database sees only the index, which it can compare for
equality, and the ciphertext, which it cannot. The application
never asks "is this email already in use?" with a plaintext query,
which would defeat the encryption.

## What you must do on top

The module does three things well: it makes the ciphertext
unreadable (AES-256-GCM with a fresh 12-byte nonce per call), it
makes a stolen ciphertext from one column useless against another
(the column name is bound into the GCM AAD), and it gives the
caller a deterministic hash so a `UNIQUE` index on the index
column enforces uniqueness. Four things the module deliberately
does NOT do, because they belong to the application and
forgetting any one of them ships a broken field:

1. **Normalisation is the caller's.** `BlindIndex` hashes the
   bytes it is handed. Lowercase, trim, Unicode fold, strip
   `+tags` from addresses, whatever the application's
   "same address" rule is, do it once, in one place, and
   `BlindIndex` the same form every time. `auth/email` and
   `auth/username` both do this. A module that normalised
   silently would make `BlindIndex` disagree with whatever
   the caller stored, and lookups would miss. The cost of
   getting this wrong is not "the user sees an error"; it is
   "the user creates a second account under a different
   capitalisation", which is the exact failure the column was meant
   to prevent.

2. **The blind index leaks equality, on purpose.** Anyone with
   read access to the database can see which rows share an
   index, and can confirm a guess if they can compute the
   index, which needs the derived key. The index buys
   searchability and costs exactly that. Do NOT index a
   low-entropy field where confirming a guess is the whole
   attack: a four-digit SMS code, a yes/no flag, a country
   code. For an email address, the search space is large
   enough that equality is the right tradeoff. For a PIN, it
   is not.

3. **Losing the key loses the data.** There is no recovery
   path. The library-managed refresh secret (the input to the
   HKDF derivation) is the only thing that can produce the
   AES key; lose it, and every row is unreadable. Back up the
   key material the same way you back up the database. See
   [key management](key-management.md) for sourcing it from
   a secret manager.

4. **Rotating the key requires re-encrypting every row.**
   The library does not do it for you, because doing so
   without a window where the row is decryptable by either
   the old key or the new one would either require keeping
   both around or making the migration the caller's problem
   in a different shape. The shape is: read with the old
   module, write with the new one, in batches, in a single
   transaction per row so a partial run leaves no row in
   a state neither key can read.

   ```go
   // Migration sketch. Run in batches of 1000 rows; every
   // row is in a transaction so a crash mid-batch leaves
   // the rest of the table consistent. The blind index
   // MUST be recomputed and written in the same UPDATE as
   // the new ciphertext: leaving the index on the old key
   // makes lookups miss, and a later UPDATE that writes the
   // same plaintext again passes the UNIQUE index only
   // because the old index for that plaintext has already
   // been replaced, and a duplicate slips through if it
   // lands between two rows migrating out of order.
   for {
       rows, _ := db.Query(`SELECT id, email_ct FROM users
                             WHERE email_migrated_at IS NULL
                             LIMIT 1000`)
       if !rows.Next() { break }
       var (
           id  int64
           ct  string
       )
       _ = rows.Scan(&id, &ct)
       // ... open tx, decrypt with old module,
       // re-encrypt with new module,
       // compute the new index from the plaintext,
       // UPDATE email_ct, email_idx, email_migrated_at,
       // commit ...
   }
   ```

   Pausing writes to the column for the duration of the migration is
   required by this simple recipe: any concurrent INSERT or UPDATE
   that lands while a row is being migrated can write against an index
   the migration is about to replace, and the UNIQUE guarantee this column
   exists to enforce breaks down for the window. For a non-trivial
   migration run a dual-key window instead, old module reads and new
   module writes with a verification step on every read, and rotate
   `Keys().RefreshSecret()` only after the dual-key path has caught up.

## Ciphertext shape

- 12 random bytes (96 bits) of nonce from `crypto/rand`, drawn
  fresh on every `Encrypt`
- AES-256-GCM over the plaintext, with the bound `Context`
  (length-prefixed with a big-endian uint32) as the additional
  authenticated data
- Output: `base64.RawStdEncoding.EncodeToString(nonce || sealed)`,
  so it drops into a TEXT column as-is. A `BYTEA`-style column
  can store the raw bytes via
  `base64.RawStdEncoding.DecodeString(ciphertext)` instead.
- The blind index is `hex(HMAC-SHA256(idxKey, len(context)||context
  || len(value)||value))`, each length a big-endian uint32, so
  `("a", "bc")` and `("ab", "c")` cannot collide. A separator
  byte would only disambiguate while no field contained it, and
  a Go string can contain any byte.

The encryption key and the index key are both derived from
`Keys().RefreshSecret()` with HKDF-SHA256 and distinct info
labels (`authcore/field/aes-256-gcm/v1` and
`authcore/field/blind-index/v1`). The version suffix in the
info string is deliberate: if the derivation ever has to
change, the old label stays available so existing rows remain
decryptable.

## Footguns the caller must handle

Beyond the four above, two smaller traps:

- **Use one module per column.** The same `fld` instance
  protects one column, named in its `Context`. Two columns
  need two `field.New` calls with two different `Context`
  strings. A single module shared across columns would not
  bind to a column, and the whole point of the AAD would
  vanish.
- **Treat `ErrDecrypt` as a server error, not a 404.** A
  stored ciphertext that does not decrypt is corrupt, was
  never written by this module, or was written under a
  different `Context`. None of those is "the user does
  not exist", and surfacing it as one would let an
  attacker probe the database by writing rows they know
  will fail to decrypt. Return a generic 500 and log
  the offending row id.

## What is fixed and why

The cryptographic layer is **closed**: AES-256-GCM, a
12-byte random nonce per `Encrypt` from `crypto/rand`, the
HKDF-SHA256 derivation of the encryption and index keys
from the library-managed refresh secret, the HMAC-SHA256
construction of the blind index, the length-prefixed
binding of the `Context` into both the AES additional
authenticated data and the index, and the base64
encoding of the ciphertext are all fixed. Weaken any of
these and a stolen ciphertext, or a guessed value, can
recover data the column is meant to protect.

The policy layer is **open with one required field**:
`Context`, the name of the database column the module
is protecting. `Context` is not decoration: it is the
whole point of the AAD binding. A caller who does not
name the field is telling the module nothing, and
silently accepting `""` would make every field share
one keyspace, so `validateConfig` refuses the empty
string at `New`. See [configuration](configuration.md)
for the principle.
