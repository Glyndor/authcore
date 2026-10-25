package clientauth

import "testing"

func TestChoose(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		advertised []string
		hasSecret  bool
		want       Method
	}{
		{"public client skips authentication", []string{"client_secret_basic"}, false, None},
		{"nothing advertised keeps post", nil, true, Post},
		{"basic advertised", []string{"client_secret_basic"}, true, Basic},
		{"short basic spelling, any case", []string{"BASIC"}, true, Basic},
		{"post advertised", []string{"client_secret_post"}, true, Post},
		{"short post spelling", []string{"post"}, true, Post},
		{"both advertised prefers basic", []string{"client_secret_post", "client_secret_basic"}, true, Basic},
		{"only unknown methods", []string{"private_key_jwt", "tls_client_auth"}, true, None},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Choose(tc.advertised, tc.hasSecret); got != tc.want {
				t.Fatalf("Choose(%v, %v) = %v, want %v", tc.advertised, tc.hasSecret, got, tc.want)
			}
		})
	}
}
