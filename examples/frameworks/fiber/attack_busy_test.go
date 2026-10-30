package main

import (
	"net/http"
	"testing"
	"time"
)

// Login and registration are open to anyone and every request derives an
// Argon2id key, which holds the profile's memory until it ends. The example
// bounds how many run at once, and a request that cannot get a slot in time is
// refused with 503 and Retry-After rather than piling more memory on.
func TestHashSlotsRefuseWhenAllAreHeld(t *testing.T) {
	call := newExample(t)
	if status, body := call(http.MethodPost, "/register", credentials(readmeEmail, readmePassword), ""); status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, body)
	}

	shortWait := hashWait
	hashWait = 50 * time.Millisecond
	t.Cleanup(func() { hashWait = shortWait })
	for range maxConcurrentHashes {
		hashSlots <- struct{}{}
	}
	drained := false
	drain := func() {
		if !drained {
			drained = true
			for range maxConcurrentHashes {
				<-hashSlots
			}
		}
	}
	t.Cleanup(drain)

	for _, path := range []string{"/login", "/register"} {
		status, body := call(http.MethodPost, path, credentials("other@example.com", readmePassword), "")
		if status != http.StatusServiceUnavailable || text(body, "error") != "server busy" {
			t.Errorf("%s with every slot held: %d %v, want 503 server busy", path, status, body)
		}
	}

	drain()
	if status, body := call(http.MethodPost, "/login", credentials(readmeEmail, readmePassword), ""); status != http.StatusOK {
		t.Errorf("login after the slots were released: %d %v", status, body)
	}
}
