package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvironment(t *testing.T) {
	result, e := Environment([]string{"EXISTING=keep", "DARKVAULT_TOKEN=hidden"}, map[string]string{"ConnectionStrings:Main": "value"}, true, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range result {
		if v == "DARKVAULT_TOKEN=hidden" {
			t.Fatal("token inherited")
		}
	}
	if _, e = Environment(nil, map[string]string{"A:B": "a", "A__B": "b"}, true, false); e == nil {
		t.Fatal("collision accepted")
	}
	if _, e = Environment([]string{"A=old"}, map[string]string{"A": "new"}, false, false); e == nil {
		t.Fatal("override accepted")
	}
	if _, e = Environment(nil, map[string]string{"BAD-NAME": "x"}, false, false); e == nil {
		t.Fatal("bad name accepted")
	}
}
func TestLiveCLI(t *testing.T) {
	path := os.Getenv("DARKVAULT_ACCEPTANCE")
	if path == "" {
		t.Skip("Set DARKVAULT_ACCEPTANCE to the acceptance host descriptor")
	}
	cleanEnvironment(t)
	t.Setenv("DARKVAULT_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var descriptor struct{ URL, CA, TokenFile string }
	if e = json.Unmarshal(data, &descriptor); e != nil {
		t.Fatal(e)
	}
	ca, e := os.ReadFile(descriptor.CA)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	previous := http.DefaultTransport
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer func() {
		http.DefaultTransport.(*http.Transport).CloseIdleConnections()
		http.DefaultTransport = previous
	}()
	runText := func(args ...string) string {
		t.Helper()
		cmd := Command()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetArgs(args)
		if e := cmd.Execute(); e != nil {
			t.Fatal(e)
		}
		return output.String()
	}
	run := func(args ...string) map[string]any {
		t.Helper()
		var result map[string]any
		if e := json.Unmarshal([]byte(runText(args...)), &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	token, e := os.ReadFile(descriptor.TokenFile)
	if e != nil {
		t.Fatal(e)
	}
	runText("config", "set", "server", descriptor.URL)
	runText("config", "set", "token", string(token))
	runText("config", "set", "page-size", "1")
	bucket := run("bucket", "add", "go_live")
	if bucket["name"] != "go_live" {
		t.Fatal("wrong bucket")
	}
	run("bucket", "read", "interop")
	run("token", "info")
	page := run("bucket", "list")
	if len(page["items"].([]any)) != 1 || page["nextCursor"] == nil {
		t.Fatal("saved page size was not applied")
	}
	page = run("bucket", "list", "--limit", "2", "--server", descriptor.URL, "--token-file", descriptor.TokenFile)
	if len(page["items"].([]any)) != 2 {
		t.Fatal("explicit limit did not override saved page size")
	}
}
