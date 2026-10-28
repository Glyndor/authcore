package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestFetchIgnoresCaseVariantsOfEveryKnownMember(t *testing.T) {
	t.Parallel()
	base := docJSON()
	want, err := Fetch(context.Background(), issuer, respond(200, base), ErrDiscovery)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "token_endpoint_auth_methods_supported"} {
		for _, value := range []string{`42`, `"https://other.example/extension"`, `["extension"]`, `null`} {
			for _, first := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/first=%v", name, value, first), func(t *testing.T) {
					extension := `"` + strings.ToUpper(name) + `":` + value
					body := strings.TrimSuffix(base, "}") + "," + extension + "}"
					if first {
						body = "{" + extension + "," + strings.TrimPrefix(base, "{")
					}
					got, err := Fetch(context.Background(), issuer, respond(200, body), ErrDiscovery)
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("extension changed known metadata: doc=%+v, err=%v", got, err)
					}
				})
			}
		}
	}
}

func TestFetchRequiresExactKnownMemberNamesAndTypes(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "token_endpoint_auth_methods_supported"} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(docJSON()), &fields); err != nil {
				t.Fatal(err)
			}
			fields[strings.ToUpper(name)] = fields[name]
			delete(fields, name)
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Fetch(context.Background(), issuer, respond(200, string(raw)), ErrDiscovery)
			required := name != "userinfo_endpoint" && name != "token_endpoint_auth_methods_supported"
			if required {
				if !errors.Is(err, ErrDiscovery) {
					t.Fatalf("nonexact required member accepted: %+v, %v", doc, err)
				}
			} else if err != nil || (name == "userinfo_endpoint" && doc.UserInfoURL != "") || (name == "token_endpoint_auth_methods_supported" && doc.AuthMethods != nil) {
				t.Fatalf("nonexact optional member used: %+v, %v", doc, err)
			}
			fields[name] = json.RawMessage(`42`)
			raw, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Fetch(context.Background(), issuer, respond(200, string(raw)), ErrDiscovery); !errors.Is(err, ErrDiscovery) {
				t.Fatalf("wrong type for exact name accepted: %v", err)
			}
		})
	}
}

func TestDecodeDocumentPreservesExactNamesAndJSONShape(t *testing.T) {
	t.Parallel()
	want := Document{Issuer: "https://p.example", AuthURL: "https://p.example/auth", TokenURL: "https://p.example/token", JWKSURL: "https://p.example/jwks", UserInfoURL: "https://p.example/userinfo", AuthMethods: []string{"client_secret_basic"}}
	got, err := decodeDocument([]byte(docJSON()))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("document = %+v, %v", got, err)
	}
	for _, raw := range []string{`[]`, `true`, `"text"`, `{`, `{"issuer":42}`, `{"token_endpoint_auth_methods_supported":"basic"}`} {
		if _, err := decodeDocument([]byte(raw)); err == nil {
			t.Errorf("malformed document %s accepted", raw)
		}
	}
	for _, raw := range []string{`null`, `{}`, `{"ISSUER":42,"TOKEN_ENDPOINT":[],"extension":{"issuer":false}}`} {
		got, err := decodeDocument([]byte(raw))
		if err != nil || !reflect.DeepEqual(got, Document{}) {
			t.Errorf("unknown/empty metadata = %+v, %v", got, err)
		}
	}
}
