package userinfo

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFetchRefusesAmbiguousMembers(t *testing.T) {
	for _, body := range []string{`{"id":"a","id":"b"}`, `{"id":"a","ID":"b"}`, `{"id":"a","\u0069d":"b"}`, `{"extra":{"id":1,"id":2}}`} {
		got, err := Fetch(context.Background(), respond(200, body), "https://idp.example/userinfo", "bearer", errUserInfo)
		if got != nil || !errors.Is(err, errUserInfo) || !strings.Contains(err.Error(), "ambiguous member") {
			t.Errorf("body %s: profile=%v err=%v", body, got, err)
		}
	}
}
