# Migrating from bcrypt / other libraries

authcore can take over password verification from another library **without
forcing every user to reset their password**. Use the "re-hash on next login"
pattern:

```go
func Login(email, submitted string) error {
    user := db.FindUser(email)

    // 1. Try authcore first. New users and already-migrated users land here.
    if ok, _ := pwdMod.Verify(submitted, user.PasswordHash); ok {
        return issueSession(user)
    }

    // 2. Fall back to the legacy hasher (e.g. bcrypt).
    if !legacyBcrypt.Compare(submitted, user.PasswordHash) {
        return ErrWrongPassword
    }

    // 3. Password is correct — upgrade the hash transparently.
    newHash, err := pwdMod.Hash(submitted)
    if err != nil {
        return err
    }
    db.UpdatePasswordHash(user.ID, newHash)
    return issueSession(user)
}
```

After a few weeks, most active users are migrated and you can delete the legacy
path. Dormant accounts can be forced into password reset the next time they log
in.

> [!NOTE]
> If your existing hashes are already in **PHC Argon2id format**
> (`$argon2id$v=19$…`), no migration is needed — `pwdMod.Verify` reads all
> parameters from the stored hash, regardless of which library produced it.
