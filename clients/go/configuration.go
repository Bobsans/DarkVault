package darkvault

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
)

// ConfigurationYAML emits the object/scalar subset; it does not parse arbitrary YAML.
func ConfigurationYAML(config map[string]any) (string, error) {
	var lines []string
	var emit func(map[string]any, string) error
	emit = func(object map[string]any, indent string) error {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			quoted, _ := json.Marshal(key)
			prefix := indent + string(quoted) + ":"
			if child, ok := object[key].(map[string]any); ok {
				if len(child) == 0 {
					lines = append(lines, prefix+" {}")
				} else {
					lines = append(lines, prefix)
					if err := emit(child, indent+"  "); err != nil {
						return err
					}
				}
			} else {
				if _, _, err := EncodeScalar(object[key]); err != nil {
					return err
				}
				value, err := json.Marshal(object[key])
				if err != nil {
					return errors.New("invalid configuration scalar")
				}
				lines = append(lines, prefix+" "+string(value))
			}
		}
		return nil
	}
	if len(config) == 0 {
		return "{}\n", nil
	}
	if err := emit(config, ""); err != nil {
		return "", err
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ParseScalar converts a canonical wire string to its explicit scalar type.
func ParseScalar(value, kind string) (any, error) {
	if kind == "string" || kind == "" {
		return value, nil
	}
	var scalar any
	if json.Unmarshal([]byte(value), &scalar) != nil {
		return nil, errors.New("invalid secret scalar")
	}
	switch v := scalar.(type) {
	case nil:
		if kind == "null" {
			return nil, nil
		}
	case bool:
		if kind == "boolean" {
			return v, nil
		}
	case float64:
		if kind == "number" && !math.IsNaN(v) && !math.IsInf(v, 0) && (math.Trunc(v) != v || math.Abs(v) <= 9007199254740991) {
			return v, nil
		}
	}
	return nil, errors.New("invalid secret type or scalar value")
}

func EncodeScalar(value any) (string, string, error) {
	if text, ok := value.(string); ok {
		return text, "string", nil
	}
	kind := "number"
	switch value.(type) {
	case nil:
		kind = "null"
	case bool:
		kind = "boolean"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
	default:
		return "", "", errors.New("secret values must be scalars")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", "", errors.New("invalid secret scalar")
	}
	if _, err = ParseScalar(string(data), kind); err != nil {
		return "", "", err
	}
	return string(data), kind, nil
}

func (s Secret) TypedValue() (any, error) { return ParseScalar(s.Value, s.Type) }
func (s BucketSnapshot) TypedSecrets() (map[string]any, error) {
	for key := range s.Types {
		if _, ok := s.Secrets[key]; !ok {
			return nil, errors.New("invalid secret type map")
		}
	}
	values := make(map[string]any, len(s.Secrets))
	for key, value := range s.Secrets {
		parsed, err := ParseScalar(value, s.Types[key])
		if err != nil {
			return nil, err
		}
		values[key] = parsed
	}
	return values, nil
}

func BuildConfiguration(values map[string]any, nested bool) (map[string]any, error) {
	root := map[string]any{}
	for key, value := range values {
		if _, _, err := EncodeScalar(value); err != nil {
			return nil, err
		}
		parts := []string{key}
		if nested {
			parts = nil
			var part strings.Builder
			escaped := false
			for _, ch := range key {
				if escaped {
					if ch != ':' && ch != '\\' {
						return nil, errors.New("invalid configuration path escape")
					}
					part.WriteRune(ch)
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == ':' {
					parts = append(parts, part.String())
					part.Reset()
				} else {
					part.WriteRune(ch)
				}
			}
			parts = append(parts, part.String())
			if escaped || len(parts) > 16 {
				return nil, errors.New("invalid configuration path")
			}
			for _, p := range parts {
				if p == "" {
					return nil, errors.New("invalid configuration path")
				}
			}
		}
		parent := root
		for _, p := range parts[:len(parts)-1] {
			if _, ok := parent[p]; !ok {
				parent[p] = map[string]any{}
			}
			child, ok := parent[p].(map[string]any)
			if !ok {
				return nil, errors.New("configuration paths conflict")
			}
			parent = child
		}
		leaf := parts[len(parts)-1]
		if _, ok := parent[leaf]; ok {
			return nil, errors.New("configuration paths conflict")
		}
		parent[leaf] = value
	}
	return root, nil
}

func (c *Client) ReadTypedBucket(ctx context.Context, bucket string) (map[string]any, error) {
	snapshot, err := c.ReadBucketSnapshot(ctx, bucket)
	if err != nil {
		return nil, err
	}
	return snapshot.TypedSecrets()
}

// ReadConfiguration binds a nested configuration to a caller-supplied struct or map pointer.
func (c *Client) ReadConfiguration(ctx context.Context, bucket string, target any) error {
	values, err := c.ReadTypedBucket(ctx, bucket)
	if err != nil {
		return err
	}
	config, err := BuildConfiguration(values, true)
	if err != nil {
		return err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return errors.New("invalid configuration")
	}
	if json.Unmarshal(data, target) != nil {
		return errors.New("configuration does not match target type")
	}
	return nil
}

func (c *Client) writeTypedSecret(ctx context.Context, op, bucket, key string, input any, revision *int64) (SecretMetadata, error) {
	value, kind, err := EncodeScalar(input)
	if err != nil {
		return SecretMetadata{}, err
	}
	p := map[string]any{"bucket": bucket, "key": key, "value": value, "type": kind}
	if revision != nil {
		p["expectedRevision"] = *revision
	}
	return execute[SecretMetadata](ctx, c, op, p)
}
func (c *Client) AddTypedSecret(ctx context.Context, bucket, key string, value any) (SecretMetadata, error) {
	return c.writeTypedSecret(ctx, "secret.create", bucket, key, value, nil)
}
func (c *Client) UpdateTypedSecret(ctx context.Context, bucket, key string, value any, revision int64) (SecretMetadata, error) {
	return c.writeTypedSecret(ctx, "secret.update", bucket, key, value, &revision)
}
func (c *Client) SetTypedSecret(ctx context.Context, bucket, key string, value any, revision int64) (SecretMetadata, error) {
	return c.writeTypedSecret(ctx, "secret.set", bucket, key, value, &revision)
}
