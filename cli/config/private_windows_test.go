package config

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsConfigurationHasPrivateDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Defaults()); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	// Normalize both descriptors because Windows may render well-known SIDs as aliases.
	if descriptor.String() != expected.String() {
		t.Fatalf("unexpected configuration DACL: %s", descriptor.String())
	}
}
