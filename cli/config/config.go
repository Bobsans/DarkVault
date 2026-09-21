// Package config persists the CLI's per-user defaults.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	client "github.com/Bobsans/DarkVault/clients/go/v2"
)

const MaxSize = 8192

type Settings struct {
	DefaultBucket string `json:"-"`
	Server        string `json:"server,omitempty"`
	Token         string `json:"token,omitempty"`
	Timeout       string `json:"timeout"`
	PageSize      int    `json:"page-size"`
}

func Defaults() Settings { return Settings{Timeout: "30s", PageSize: 100} }
func Path(explicit string) (string, error) {
	if explicit == "" {
		explicit = os.Getenv("DARKVAULT_CONFIG")
	}
	if explicit == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", errors.New("cannot locate user configuration directory; use --config")
		}
		explicit = filepath.Join(dir, "darkvault", "config.json")
	}
	return filepath.Abs(explicit)
}
func Load(path string) (Settings, error) {
	settings := Defaults()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return settings, errors.New("configuration must be a readable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return settings, errors.New("cannot read configuration")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxSize+1))
	if err != nil || len(data) > MaxSize {
		return settings, errors.New("cannot read configuration (maximum 8 KiB)")
	}
	if client.ValidateJSON(data) != nil || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return settings, errors.New("invalid configuration JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil {
		return Defaults(), errors.New("invalid configuration fields")
	}
	if err = settings.Validate(); err != nil {
		return Defaults(), err
	}
	return settings, nil
}
func (s Settings) Validate() error {
	if s.Server != "" {
		if _, err := client.NormalizeServer(s.Server); err != nil {
			return err
		}
	}
	if s.Token != "" {
		if err := client.ValidateToken(s.Token); err != nil {
			return err
		}
	}
	if _, err := ParseTimeout(s.Timeout); err != nil {
		return err
	}
	if s.PageSize < 1 || s.PageSize > 200 {
		return errors.New("page-size must be between 1 and 200")
	}
	return nil
}
func ParseTimeout(text string) (time.Duration, error) {
	duration, err := time.ParseDuration(text)
	if err != nil || duration < time.Second || duration > 30*time.Second {
		return 0, errors.New("timeout must be between 1s and 30s")
	}
	return duration, nil
}
func (s *Settings) Set(key, value string) error {
	switch key {
	case "server":
		normalized, err := client.NormalizeServer(value)
		if err != nil {
			return err
		}
		s.Server = normalized
	case "token":
		if err := client.ValidateToken(value); err != nil {
			return err
		}
		s.Token = value
	case "timeout":
		duration, err := ParseTimeout(value)
		if err != nil {
			return err
		}
		s.Timeout = duration.String()
	case "page-size":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 200 {
			return errors.New("page-size must be between 1 and 200")
		}
		s.PageSize = n
	default:
		return errors.New("unknown configuration key; use server, token, timeout or page-size")
	}
	return nil
}
func (s *Settings) Unset(key string) error {
	switch key {
	case "server":
		s.Server = ""
	case "token":
		s.Token = ""
	case "timeout":
		s.Timeout = Defaults().Timeout
	case "page-size":
		s.PageSize = Defaults().PageSize
	default:
		return errors.New("unknown configuration key")
	}
	return nil
}
func (s Settings) Redacted() Settings {
	if s.Token != "" {
		s.Token = "[redacted]"
	}
	return s
}
func (s Settings) Get(key string) (string, error) {
	switch key {
	case "server":
		return s.Server, nil
	case "token":
		return s.Redacted().Token, nil
	case "timeout":
		return s.Timeout, nil
	case "page-size":
		return strconv.Itoa(s.PageSize), nil
	default:
		return "", errors.New("unknown configuration key")
	}
}
func Save(path string, settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil || len(data)+1 > MaxSize {
		return errors.New("configuration must fit within 8 KiB")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("configuration must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect configuration")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create configuration directory")
	}
	// Write a private sibling first: validation or write failures leave the previous file intact.
	file, err := privateTemp(dir)
	if err != nil {
		return errors.New("cannot create private configuration file")
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(append(data, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot write configuration")
	}
	if err = os.Rename(name, path); err != nil {
		return errors.New("cannot replace configuration")
	}
	return nil
}
