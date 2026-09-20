package darkvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidationAndRedirects(t *testing.T) {
	token := "dv1_" + strings.Repeat("A", 60)
	for _, server := range []string{"http://vault.example.com", "https://user@vault.example.com", "https://vault.example.com/path"} {
		if _, err := New(server, token); err == nil {
			t.Fatalf("accepted invalid server: %s", server)
		}
	}
	if _, err := New("vault.example.com", "invalid"); err == nil {
		t.Fatal("accepted invalid token")
	}
	c, err := New("vault.example.com", token)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	c.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://other.example.com"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	_, err = c.GetTokenInfo(context.Background())
	var apiError *APIError
	if calls != 1 || !errors.As(err, &apiError) || apiError.Status != 302 {
		t.Fatal("redirect was not rejected", calls, err)
	}
}

func TestLiveOperations(t *testing.T) {
	path := os.Getenv("DARKVAULT_ACCEPTANCE")
	if path == "" {
		t.Skip("Set DARKVAULT_ACCEPTANCE to the acceptance host descriptor")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor struct{ URL, CA, TokenFile string }
	if err = json.Unmarshal(data, &descriptor); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(descriptor.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(descriptor.URL, string(token))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = c.GetTokenInfo(ctx); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	ca, err := os.ReadFile(descriptor.CA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	c.HTTP.Transport = transport
	info, err := c.GetTokenInfo(ctx)
	if err != nil || info.ID == "" {
		t.Fatal("token info", err)
	}
	bucket, err := c.AddBucket(ctx, "go-sdk-live", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := c.GetBucket(context.Background(), "go-sdk-live")
		if err == nil {
			if err = c.DeleteBucket(context.Background(), "go-sdk-live", current.Revision, true); err != nil {
				t.Error(err)
			}
		}
	})
	bucket, err = c.UpdateBucket(ctx, "go-sdk-live", "updated", bucket.Revision)
	if err != nil || bucket.Description != "updated" {
		t.Fatal("update bucket", err)
	}
	page, err := c.ListBuckets(ctx, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextCursor == nil {
		t.Fatal("bucket pagination", err)
	}
	page, err = c.ListBuckets(ctx, *page.NextCursor, 1)
	if err != nil || len(page.Items) != 1 {
		t.Fatal("next bucket page", err)
	}
	secret, err := c.AddSecret(ctx, "go-sdk-live", "first", "秘密\nvalue")
	if err != nil {
		t.Fatal(err)
	}
	read, err := c.ReadSecret(ctx, "go-sdk-live", "first")
	if err != nil || read.Value != "秘密\nvalue" || read.ID != secret.ID {
		t.Fatal("read secret", err)
	}
	updated, err := c.UpdateSecret(ctx, "go-sdk-live", "first", "updated", secret.Revision)
	if err != nil {
		t.Fatal(err)
	}
	err = c.DeleteSecret(ctx, "go-sdk-live", "first", secret.Revision)
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != 409 || apiError.RequestID == "" {
		t.Fatal("revision conflict", err)
	}
	updated, err = c.SetSecret(ctx, "go-sdk-live", "first", "set", updated.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.SetSecret(ctx, "go-sdk-live", "second", "", 0); err != nil {
		t.Fatal(err)
	}
	secrets, err := c.ListSecrets(ctx, "go-sdk-live", "", 1)
	if err != nil || len(secrets.Items) != 1 || secrets.NextCursor == nil {
		t.Fatal("secret pagination", err)
	}
	secrets, err = c.ListSecrets(ctx, "go-sdk-live", *secrets.NextCursor, 1)
	if err != nil || len(secrets.Items) != 1 || secrets.NextCursor != nil {
		t.Fatal("next secret page", err)
	}
	values, err := c.ReadBucket(ctx, "go-sdk-live")
	if err != nil || values["first"] != "set" || len(values) != 2 {
		t.Fatal("read bucket", err)
	}
	if err = c.DeleteSecret(ctx, "go-sdk-live", "first", updated.Revision); err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.ReadBucketSnapshot(ctx, "go-sdk-live")
	if err != nil || snapshot.BucketID != bucket.ID || len(snapshot.Secrets) != 1 {
		t.Fatal("snapshot", err)
	}
	if err = c.DeleteBucket(ctx, "go-sdk-live", snapshot.Revision, true); err != nil {
		t.Fatal(err)
	}
}
