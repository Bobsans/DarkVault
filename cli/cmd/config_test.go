package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bobsans/DarkVault/cli/config"
	"github.com/spf13/cobra"
)

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"DARKVAULT_CONFIG", "DARKVAULT_SERVER", "DARKVAULT_TOKEN", "DARKVAULT_TOKEN_FILE", "DARKVAULT_TIMEOUT", "DARKVAULT_PAGE_SIZE"} {
		t.Setenv(key, "")
	}
}
func TestConfigCommands(t *testing.T) {
	cleanEnvironment(t)
	emptyPath := Command()
	emptyPath.SetArgs([]string{"--config", "", "config", "path"})
	emptyPath.SetOut(io.Discard)
	emptyPath.SetErr(io.Discard)
	if emptyPath.Execute() == nil {
		t.Fatal("explicit empty path silently selected a different config")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	token := "dv1_" + strings.Repeat("A", 60)
	run := func(input string, args ...string) (string, error) {
		t.Helper()
		cmd := Command()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetIn(strings.NewReader(input))
		cmd.SetArgs(append([]string{"--config", path}, args...))
		err := cmd.Execute()
		if strings.Contains(output.String(), token) || (err != nil && strings.Contains(err.Error(), token)) {
			t.Fatal("token was exposed")
		}
		return output.String(), err
	}
	for _, args := range [][]string{{"config", "set", "server", "https://vault.example.com"}, {"config", "set", "token", token}, {"config", "set", "timeout", "8s"}, {"config", "set", "page-size", "25"}} {
		if _, err := run("", args...); err != nil {
			t.Fatal(err)
		}
	}
	got, err := run("", "config", "get", "server")
	if err != nil || got != "https://vault.example.com\n" {
		t.Fatal("server get failed", err)
	}
	got, err = run("", "config", "get", "token")
	if err != nil || got != "[redacted]\n" {
		t.Fatal("token get was not masked")
	}
	got, err = run("", "config", "list")
	if err != nil || !strings.Contains(got, `"page-size":25`) {
		t.Fatal("list failed", err)
	}
	if _, err = run("", "config", "unset", "token"); err != nil {
		t.Fatal(err)
	}
	settings, err := config.Load(path)
	if err != nil || settings.Token != "" || settings.Server != "https://vault.example.com" {
		t.Fatal("unset failed")
	}
	if _, err = run(token+"\r\n", "config", "set", "token", "--stdin"); err != nil {
		t.Fatal(err)
	}
	settings, err = config.Load(path)
	if err != nil || settings.Token != token {
		t.Fatal("stdin token not saved")
	}
	for _, args := range [][]string{{"config", "set", "token", "bad"}, {"config", "set", "timeout", "100s"}, {"config", "set", "page-size", "0"}, {"config", "get", "unknown"}} {
		if _, err = run("", args...); err == nil {
			t.Fatal("invalid setting accepted")
		}
	}
}
func TestRuntimePrecedence(t *testing.T) {
	cleanEnvironment(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	savedToken := "dv1_" + strings.Repeat("A", 60)
	envToken := "dv1_" + strings.Repeat("B", 60)
	fileToken := "dv1_" + strings.Repeat("C", 60)
	flagToken := "dv1_" + strings.Repeat("D", 60)
	saved := config.Settings{Server: "https://saved.example.com", Token: savedToken, Timeout: "10s", PageSize: 20}
	if err := config.Save(path, saved); err != nil {
		t.Fatal(err)
	}
	resolve := func(args ...string) (config.Settings, error) {
		t.Helper()
		root := Command()
		var got config.Settings
		probe := &cobra.Command{Use: "probe", RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			got, err = resolveConfiguration(cmd, path)
			return err
		}}
		probe.Flags().Int("limit", 100, "")
		root.AddCommand(probe)
		root.SetArgs(append([]string{"probe"}, args...))
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetErr(&output)
		err := root.Execute()
		return got, err
	}
	got, err := resolve()
	if err != nil || got != saved {
		t.Fatal("saved defaults were not used", err)
	}
	t.Setenv("DARKVAULT_SERVER", "https://environment.example.com")
	t.Setenv("DARKVAULT_TOKEN", envToken)
	t.Setenv("DARKVAULT_TIMEOUT", "9s")
	t.Setenv("DARKVAULT_PAGE_SIZE", "30")
	got, err = resolve()
	if err != nil || got.Token != envToken || got.Server != "https://environment.example.com" || got.Timeout != "9s" || got.PageSize != 30 {
		t.Fatal("environment did not override file", err)
	}
	tokenFile := filepath.Join(dir, "token")
	if err = os.WriteFile(tokenFile, []byte(fileToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DARKVAULT_TOKEN_FILE", tokenFile)
	got, err = resolve("--server", "https://flag.example.com", "--token", flagToken, "--timeout", "2s", "--limit", "5")
	if err != nil || got.Token != flagToken || got.Server != "https://flag.example.com" || got.Timeout != "2s" || got.PageSize != 5 {
		t.Fatal("explicit flags did not override environment", err)
	}
	c, err := connect(Command(), got)
	if err != nil || c.HTTP.Timeout != 2*time.Second {
		t.Fatal("timeout was not applied", err)
	}
	got, err = resolve()
	if err != nil || got.Token != fileToken {
		t.Fatal("environment token file did not take precedence", err)
	}
	got, err = resolve("--token-file", tokenFile)
	if err != nil || got.Token != fileToken {
		t.Fatal("explicit token file was not used", err)
	}
	if _, err = resolve("--token", flagToken, "--token-file", tokenFile); err == nil {
		t.Fatal("conflicting credential flags accepted")
	}
	if _, err = resolve("--token", ""); err == nil {
		t.Fatal("explicit empty token silently fell back")
	}
	if _, err = resolve("--server", "http://untrusted.example.com"); err == nil {
		t.Fatal("HTTP override accepted")
	}
	after, err := config.Load(path)
	if err != nil || after != saved {
		t.Fatal("runtime overrides modified saved config")
	}
}
