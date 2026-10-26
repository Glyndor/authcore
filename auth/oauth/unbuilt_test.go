package oauth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

func TestClient_unbuiltRefusesEveryCall(t *testing.T) {
	ctx := context.Background()
	var nilClient *oauth.Client
	for name, c := range map[string]*oauth.Client{"nil": nilClient, "zero": {}} {
		if _, err := c.AuthCodeURL(); !errors.Is(err, oauth.ErrInvalidConfig) {
			t.Errorf("%s AuthCodeURL: %v", name, err)
		}
		if _, err := c.Exchange(ctx, "c", "v"); !errors.Is(err, oauth.ErrInvalidConfig) {
			t.Errorf("%s Exchange: %v", name, err)
		}
		if _, err := c.UserInfo(ctx, "t"); !errors.Is(err, oauth.ErrInvalidConfig) {
			t.Errorf("%s UserInfo: %v", name, err)
		}
		if _, err := c.VerifyIDToken(ctx, "t", "n"); !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Errorf("%s VerifyIDToken: %v", name, err)
		}
	}
}
