package darkvault

import (
	"math"
	"strings"
	"testing"
)

func TestTypedConfiguration(t *testing.T) {
	for _, value := range []any{math.NaN(), math.Inf(1), int64(9007199254740992), []string{}, map[string]string{}} {
		if _, _, err := EncodeScalar(value); err == nil {
			t.Fatal("invalid scalar accepted")
		}
	}
	for _, pair := range [][2]string{{"01", "number"}, {"true", "number"}, {"1", "boolean"}, {"", "null"}} {
		if _, err := ParseScalar(pair[0], pair[1]); err == nil {
			t.Fatal("type mismatch accepted")
		}
	}
	tree, err := BuildConfiguration(map[string]any{"Redis:Port": 6379, "Redis:Enabled": false, "Literal\\:Key": "00123", "Empty": nil, "Years:2026": "x"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if tree["Redis"].(map[string]any)["Port"] != 6379 || tree["Literal:Key"] != "00123" || tree["Years"].(map[string]any)["2026"] != "x" {
		t.Fatal("configuration lost types or paths")
	}
	yaml, err := ConfigurationYAML(tree)
	if err != nil || !strings.Contains(yaml, `"Enabled": false`) || !strings.Contains(yaml, `"Empty": null`) || !strings.Contains(yaml, `"Literal:Key": "00123"`) {
		t.Fatal("invalid YAML export", err)
	}
	for _, values := range []map[string]any{{"A": "x", "A:B": 1}, {"A:B": 1, "A": nil}, {"A::B": true}, {"A\\x": true}} {
		if _, err := BuildConfiguration(values, true); err == nil {
			t.Fatal("ambiguous configuration accepted")
		}
	}
}
