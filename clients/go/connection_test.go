package darkvault

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestConnectionStrings(t *testing.T) {
	token := "dv1_" + strings.Repeat("A", 60)
	for _, host := range []string{"vault.example.com", "localhost:8443", "[::1]:8443"} {
		c, err := NewFromURL("https://" + token + "@" + host + "/qa")
		if err != nil {
			t.Fatal(err)
		}
		if c.DefaultBucket != "qa" || c.Token() != token || c.URL != "https://"+host {
			t.Fatal("incorrect connection")
		}
		c.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://"+host+"/api/v1/crypto/key" || r.Header.Get("Authorization") != "" {
				t.Fatal("credentials exposed in discovery")
			}
			return &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})}
		if _, err := c.ReadBucket(context.Background(), ""); err == nil {
			t.Fatal("expected discovery failure")
		}
	}
	for _, raw := range []string{
		"http://TOKEN@vault.example.com/qa",
		"https://vault.example.com/qa",
		"https://TOKEN:password@vault.example.com/qa",
		"https://TOKEN@vault.example.com",
		"https://TOKEN@vault.example.com/",
		"https://TOKEN@vault.example.com/qa/",
		"https://TOKEN@vault.example.com/a/../qa",
		"https://TOKEN@vault.example.com/qa?x=1",
		"https://TOKEN@vault.example.com/qa#x",
		"https://TOKEN@vault.example.com/qa\n",
		"https://TOKEN@vault.example.com:0/qa",
		"https://TOKEN@vault.example.com:65536/qa",
		"https://TOKEN@[bad/qa",
		"https://TOKEN@/qa",
		"https://TOKEN@vault.example.com/UPPER",
		"https://TOKEN@vault.example.com/%71a",
		"https://bad@vault.example.com/qa",
	} {
		_, err := NewFromURL(strings.ReplaceAll(raw, "TOKEN", token))
		if err == nil || strings.Contains(err.Error(), token) {
			t.Fatal("invalid connection was accepted or exposed")
		}
	}
	c, _ := New("vault.example.com", token)
	if _, err := c.ReadBucket(context.Background(), ""); err == nil {
		t.Fatal("missing bucket accepted")
	}
}

func TestConfigurationEnvironmentValidation(t *testing.T) {
	var config map[string]any
	for _, value := range []string{"", " \t "} {
		t.Setenv("DARKVAULT_URL", value)
		if err := LoadConfigurationFromEnv(context.Background(), &config); err == nil || !strings.Contains(err.Error(), "DARKVAULT_URL") {
			t.Fatal("missing environment was not reported")
		}
	}
	t.Setenv("DARKVAULT_URL", "invalid")
	if err := LoadConfigurationFromEnv(context.Background(), &config); err == nil {
		t.Fatal("invalid environment accepted")
	}
}
