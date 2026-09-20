package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionNeedsNoConfiguration(t *testing.T) {
	t.Setenv("DARKVAULT_CONFIG", "missing-config.json")
	command := Command()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"--version"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), Version+"+") {
		t.Fatal("missing version metadata")
	}
}

func TestReleaseVersion(t *testing.T) {
	previous := Version
	defer func() { Version = previous }()
	Version = "release:1.2.3+abcdef"
	if buildVersion() != "1.2.3+abcdef" {
		t.Fatal("release version was modified")
	}
}
