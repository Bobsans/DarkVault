package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveLoadPreserveAndProtect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings", "config.json")
	settings, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	token := "dv1_" + strings.Repeat("A", 60)
	for key, value := range map[string]string{"server": "https://vault.example.com/", "token": token, "timeout": "5s", "page-size": "20"} {
		if err = settings.Set(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err = Save(path, settings); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != settings {
		t.Fatal("configuration did not round trip")
	}
	if loaded.Server != "https://vault.example.com" || loaded.Redacted().Token == token {
		t.Fatal("normalization or redaction failed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("config is not owner-only")
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := settings
	bad.Timeout = "0s"
	if Save(path, bad) == nil {
		t.Fatal("invalid config was saved")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed validation overwrote configuration")
	}
	large := settings
	large.Server = "https://" + strings.Repeat("a", MaxSize) + ".example.com"
	if Save(path, large) == nil {
		t.Fatal("oversized configuration saved")
	}
	after, _ = os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("oversized write damaged configuration")
	}
	if err = loaded.Unset("token"); err != nil {
		t.Fatal(err)
	}
	if err = Save(path, loaded); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil || loaded.Token != "" || loaded.Server != settings.Server {
		t.Fatal("unset damaged other settings")
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 1 {
		t.Fatal("temporary files left behind")
	}
}
func TestRejectInvalidSettingsAndFiles(t *testing.T) {
	for _, input := range [][2]string{{"server", "http://vault.example.com"}, {"server", "https://user:password@vault.example.com"}, {"server", "https://vault.example.com/path"}, {"token", "not-a-token"}, {"timeout", "31s"}, {"timeout", "0s"}, {"page-size", "201"}, {"page-size", "0"}, {"unknown", "anything"}} {
		s := Defaults()
		if s.Set(input[0], input[1]) == nil {
			t.Errorf("accepted invalid %s", input[0])
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, text := range []string{`{"token":"private-invalid-value"}`, `{"server":"a","server":"b"}`, `{"unexpected":true}`, `null`, strings.Repeat("x", MaxSize+1)} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil || strings.Contains(err.Error(), "private-invalid-value") {
			t.Fatal("invalid configuration accepted or secret exposed")
		}
	}
	if _, err := Load(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted as configuration")
	}
}
func TestConfigPathSelection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DARKVAULT_CONFIG", filepath.Join(dir, "environment.json"))
	fromEnv, err := Path("")
	if err != nil || fromEnv != filepath.Join(dir, "environment.json") {
		t.Fatal("environment path was not selected")
	}
	explicit, err := Path(filepath.Join(dir, "explicit.json"))
	if err != nil || explicit != filepath.Join(dir, "explicit.json") {
		t.Fatal("explicit path did not override environment")
	}
}
