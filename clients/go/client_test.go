package darkvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientFormattingDoesNotExposeToken(t *testing.T) {
	token := "dv1_" + strings.Repeat("A", 60)
	c, err := New("https://vault.example.com", token)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(value, token) {
			t.Fatalf("client formatting exposed token: %s", value)
		}
	}
	if c.Token() != token {
		t.Fatal("explicit token accessor changed")
	}
}
func TestServerKeyCacheAndPlainErrorMetadata(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ServerKey{ProtocolVersion: 1, ServerID: "test", Kid: "test", PublicKey: jose.JSONWebKey{Key: &key.PublicKey}, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("https://vault.example.com", "dv1_"+strings.Repeat("A", 60))
	if err != nil {
		t.Fatal(err)
	}
	discovery, posts := 0, 0
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/crypto/key") {
			discovery++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: r}, nil
		}
		posts++
		return &http.Response{StatusCode: 429, Header: http.Header{"Content-Type": {"application/json"}, "Retry-After": {"7"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"rate_limited"}}`)), Request: r}, nil
	})
	for i := 0; i < 2; i++ {
		_, err = c.GetTokenInfo(context.Background())
		var api *APIError
		if !errors.As(err, &api) || api.Code != "rate_limited" || api.RetryAfter != 7*time.Second {
			t.Fatalf("plain error metadata: %v", err)
		}
	}
	if discovery != 1 || posts != 2 {
		t.Fatalf("unexpected cache calls: discovery=%d posts=%d", discovery, posts)
	}
}

func TestUnknownKeyRefreshesCachedServerKeyOnce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ServerKey{ProtocolVersion: 1, ServerID: "test", Kid: "test", PublicKey: jose.JSONWebKey{Key: &key.PublicKey}, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("https://vault.example.com", "dv1_"+strings.Repeat("A", 60))
	if err != nil {
		t.Fatal(err)
	}
	discovery, posts := 0, 0
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/crypto/key") {
			discovery++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: r}, nil
		}
		posts++
		code := "unknown_key"
		status := 400
		if posts > 1 {
			code, status = "unauthorized", 401
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"` + code + `"}}`)), Request: r}, nil
	})
	_, err = c.GetTokenInfo(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.Code != "unauthorized" || discovery != 2 || posts != 2 {
		t.Fatalf("unknown key refresh: %v discovery=%d posts=%d", err, discovery, posts)
	}
}

func TestConfiguredTimeoutCoversDiscoveryAndExecute(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ServerKey{ProtocolVersion: 1, ServerID: "test", Kid: "test", PublicKey: jose.JSONWebKey{Key: &key.PublicKey}, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("https://vault.example.com", "dv1_"+strings.Repeat("A", 60))
	if err != nil {
		t.Fatal(err)
	}
	var deadlines []time.Time
	c.HTTP.Timeout = 2 * time.Second
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("request has no deadline")
		}
		deadlines = append(deadlines, deadline)
		if len(deadlines) == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: r}, nil
		}
		return nil, errors.New("test transport stopped")
	})
	_, err = c.Execute(context.Background(), "bucket.list", map[string]any{})
	if err == nil || len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("request timeout was reset between discovery and execute")
	}
}

func TestDotNetJWEFixture(t *testing.T) {
	b, e := os.ReadFile("testdata/jwe.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		JWK                           jose.JSONWebKey `json:"jwk"`
		Kid, Type, Plaintext, Compact string
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	plain, e := Decrypt(f.Compact, f.JWK.Key.(*ecdsa.PrivateKey), f.Kid, f.Type)
	if e != nil || string(plain) != f.Plaintext {
		t.Fatalf("fixture mismatch: %v", e)
	}
	encrypted, e := Encrypt(plain, f.JWK.Public(), f.Kid, f.Type)
	if e != nil {
		t.Fatal(e)
	}
	back, e := Decrypt(encrypted, f.JWK.Key.(*ecdsa.PrivateKey), f.Kid, f.Type)
	if e != nil || string(back) != f.Plaintext {
		t.Fatal("round trip failed", e)
	}
	parts := strings.Split(encrypted, ".")
	parts[4] = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, e = Decrypt(strings.Join(parts, "."), f.JWK.Key.(*ecdsa.PrivateKey), f.Kid, f.Type); e == nil {
		t.Fatal("tampered tag accepted")
	}
	if ValidateJSON([]byte(`{"a":1,"a":2}`)) == nil {
		t.Fatal("duplicate accepted")
	}
}
