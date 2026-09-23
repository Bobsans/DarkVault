package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvironment(t *testing.T) {
	result, e := Environment([]string{"EXISTING=keep", "DARKVAULT_TOKEN=hidden", "DARKVAULT_URL=hidden"}, map[string]string{"ConnectionStrings:Main": "value"}, true, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range result {
		if v == "DARKVAULT_TOKEN=hidden" || v == "DARKVAULT_URL=hidden" {
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
	// Windows keeps per-drive working directories as "=C:=..." entries; each must survive unchanged.
	drives, e := Environment([]string{`=C:=C:\work`, `=D:=D:\data`}, nil, false, false)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(drives, "|") != `=C:=C:\work|=D:=D:\data` {
		t.Fatalf("drive variables changed: %q", drives)
	}
}
func TestBucketUpdateRequiresAChange(t *testing.T) {
	cleanEnvironment(t)
	cmd := Command()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	// The unreachable server proves the command fails locally, before any request could clear the description.
	cmd.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "--server", "https://127.0.0.1:1", "--token", "dv1_" + strings.Repeat("A", 60), "bucket", "update", "qa", "--revision", "1"})
	if e := cmd.Execute(); e == nil || e.Error() != "set --name or --description" {
		t.Fatalf("bucket update without changes: %v", e)
	}
}
func TestLiveCLI(t *testing.T) {
	path := os.Getenv("DARKVAULT_ACCEPTANCE")
	if path == "" {
		// The verification gate requires the live run; without the flag a local run may still skip it.
		if os.Getenv("DARKVAULT_ACCEPTANCE_REQUIRED") != "" {
			t.Fatal("DARKVAULT_ACCEPTANCE_REQUIRED is set without DARKVAULT_ACCEPTANCE")
		}
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
	bucket = run("bucket", "update", "go_live", "--description", "Keep description", "--revision", fmt.Sprint(bucket["revision"]))
	renamed := run("bucket", "update", "go_live", "--name", "go_renamed", "--revision", fmt.Sprint(bucket["revision"]))
	if renamed["id"] != bucket["id"] || renamed["name"] != "go_renamed" || renamed["description"] != "Keep description" {
		t.Fatal("rename did not preserve bucket metadata")
	}
	run("bucket", "update", "go_renamed", "--name", "go_live", "--revision", fmt.Sprint(renamed["revision"]))
	input, err := os.CreateTemp(t.TempDir(), "typed-input")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err = input.WriteString("6379"); err != nil {
		t.Fatal(err)
	}
	if _, err = input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previousInput := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previousInput }()
	added := run("secret", "add", "go_live", "Redis:Port", "--type", "number", "--stdin")
	if added["type"] != "number" {
		t.Fatal("CLI lost secret type")
	}
	if _, err = input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	// An update without --type keeps the stored type instead of silently turning it into a string.
	kept := run("secret", "update", "go_live", "Redis:Port", "--revision", fmt.Sprint(added["revision"]), "--stdin")
	if kept["type"] != "number" {
		t.Fatal("update without --type changed the secret type")
	}
	t.Setenv("DARKVAULT_URL", strings.Replace(descriptor.URL, "https://", "https://"+string(token)+"@", 1)+"/go_live")
	if runText("secret", "get", "Redis:Port") != "6379" {
		t.Fatal("URL bucket was not used")
	}
	if runText("secret", "get", "go_live", "Redis:Port") != "6379" {
		t.Fatal("explicit bucket was not used")
	}
	typed := run("bucket", "read", "--format", "typed-json")
	if typed["Redis:Port"] != float64(6379) {
		t.Fatal("typed JSON lost number")
	}
	nested := run("bucket", "read", "go_live", "--format", "nested-json")
	if nested["Redis"].(map[string]any)["Port"] != float64(6379) {
		t.Fatal("nested JSON lost number")
	}
	if yaml := runText("bucket", "read", "go_live", "--format", "yaml"); !strings.Contains(yaml, `"Port": 6379`) {
		t.Fatal("YAML lost number")
	}
	snapshot := run("bucket", "read", "go_live")
	if snapshot["secrets"].(map[string]any)["Redis:Port"] != "6379" {
		t.Fatal("string fallback changed")
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
