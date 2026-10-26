// Package fieldtable attacks auth/field the way a users table uses it: the
// email stored as ciphertext, a blind index under a UNIQUE constraint, and
// registration and login following docs/modules/field.md. The adversary
// registers the same address from many requests at once, reads the whole
// table, and writes rows of its own into it.
package fieldtable

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// service is the registration and login code of the guide, over the table.
type service struct {
	fld   *field.Field
	users *hostiletest.Users
}

func newService(t *testing.T) *service {
	t.Helper()
	return &service{fld: hostiletest.NewEnv(t).Field(t, "email"), users: hostiletest.NewUsers()}
}

func normalise(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *service) register(email string) error {
	plain := normalise(email)
	ct, err := s.fld.Encrypt(plain)
	if err != nil {
		return err
	}
	idx, err := s.fld.BlindIndex(plain)
	if err != nil {
		return err
	}
	_, err = s.users.Insert(ct, idx)
	return err
}

var errNotFound = errors.New("not found")

// login is step 5 of the guide, including the confirmation after the index hit.
func (s *service) login(email string) (int, error) {
	candidate, err := s.fld.BlindIndex(normalise(email))
	if err != nil {
		return 0, err
	}
	row, ok := s.users.FindByIdx(candidate)
	if !ok {
		return 0, errNotFound
	}
	plain, err := s.fld.Decrypt(row.EmailCT)
	if err != nil {
		return 0, err
	}
	check, err := s.fld.BlindIndex(plain)
	if err != nil {
		return 0, err
	}
	if check != candidate {
		return 0, errNotFound
	}
	return row.ID, nil
}

// The same address registered by many requests at once: exactly one row, the
// others get the conflict, and the stored ciphertext decrypts to the address.
func TestE2E_Field_concurrentRegistrationOfOneAddressYieldsOneRow(t *testing.T) {
	s := newService(t)
	const requests = 64
	var (
		wg        sync.WaitGroup
		start     = make(chan struct{})
		created   atomic.Int64
		conflicts atomic.Int64
	)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch err := s.register("Alice@Example.com"); {
			case err == nil:
				created.Add(1)
			case errors.Is(err, hostiletest.ErrDuplicate):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if created.Load() != 1 || conflicts.Load() != requests-1 {
		t.Fatalf("created=%d conflicts=%d, want 1 and %d", created.Load(), conflicts.Load(), requests-1)
	}
	if id, err := s.login("alice@example.com"); err != nil || id != 1 {
		t.Errorf("login = %d, %v", id, err)
	}
}

// Spellings the application's own normalisation maps to one address share one
// index, so they cannot become two accounts, concurrently or one after the
// other; spellings it does not map stay different people.
func TestE2E_Field_theIndexFollowsTheApplicationsNormalisation(t *testing.T) {
	s := newService(t)
	if err := s.register("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, same := range []string{"ALICE@EXAMPLE.COM", " alice@example.com", "alice@example.com\t", "Alice@Example.Com"} {
		if err := s.register(same); !errors.Is(err, hostiletest.ErrDuplicate) {
			t.Errorf("%q registered a second account: %v", same, err)
		}
	}
	for _, different := range []string{"alice+tag@example.com", "alice@example.org", "alice@example.com.", "alice @example.com"} {
		if err := s.register(different); err != nil {
			t.Errorf("%q, a different address, was refused: %v", different, err)
		}
	}
	if s.users.Len() != 5 {
		t.Errorf("table holds %d rows, want 5", s.users.Len())
	}
}

// A crowd registering distinct addresses at once all succeed, each is found by
// its own address and by nobody else's, and every ciphertext round-trips.
func TestE2E_Field_distinctAddressesUnderConcurrencyAreAllFoundAndOnlyByThemselves(t *testing.T) {
	s := newService(t)
	const accounts = 96
	var wg sync.WaitGroup
	for i := 0; i < accounts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.register(fmt.Sprintf("user%03d@example.com", i)); err != nil {
				t.Errorf("register %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	seen := map[int]bool{}
	for i := 0; i < accounts; i++ {
		id, err := s.login(fmt.Sprintf("USER%03d@example.com", i))
		if err != nil || seen[id] {
			t.Fatalf("login %d = %d, %v (duplicate id: %v)", i, id, err, seen[id])
		}
		seen[id] = true
	}
	for _, miss := range []string{"user096@example.com", "user00@example.com", "user0000@example.com", ""} {
		if _, err := s.login(miss); !errors.Is(err, errNotFound) {
			t.Errorf("login of %q = %v, want not found", miss, err)
		}
	}
}

// What the reader of the dump sees: ciphertexts never repeat, even for equal
// plaintexts written by a module registered twice with the same data, the index
// repeats exactly when the plaintext does, and neither contains the plaintext.
func TestE2E_Field_theDumpLeaksEqualityOfTheIndexAndNothingElse(t *testing.T) {
	s := newService(t)
	plain := "alice@example.com"
	cts := map[string]bool{}
	var idx string
	for i := 0; i < 50; i++ {
		ct, err := s.fld.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if cts[ct] {
			t.Fatalf("ciphertext repeated on encryption %d", i)
		}
		cts[ct] = true
		if strings.Contains(ct, "alice") || strings.Contains(ct, "example") {
			t.Fatal("ciphertext contains the plaintext")
		}
		got, _ := s.fld.BlindIndex(plain)
		if i > 0 && got != idx {
			t.Fatal("the blind index of one value changed between calls")
		}
		idx = got
	}
	if strings.Contains(idx, "alice") {
		t.Error("index contains the plaintext")
	}
	other, _ := s.fld.BlindIndex("alice@example.org")
	if other == idx {
		t.Error("two values share an index")
	}
}
