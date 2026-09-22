package darkvault

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Bucket struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Revision    int64     `json:"revision"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type SecretMetadata struct {
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	BucketID  string    `json:"bucketId"`
	Key       string    `json:"key"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Secret struct {
	SecretMetadata
	Value string `json:"value"`
}

type BucketSnapshot struct {
	Types    map[string]string `json:"types"`
	BucketID string            `json:"bucketId"`
	Revision int64             `json:"revision"`
	Secrets  map[string]string `json:"secrets"`
}

type deleteResult struct {
	Deleted bool `json:"deleted"`
}

type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"nextCursor"`
}

type TokenInfo struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Scopes               []string   `json:"scopes"`
	BucketIDs            []string   `json:"bucketIds"`
	AllBuckets           bool       `json:"allBuckets"`
	CreatableBucketNames []string   `json:"creatableBucketNames"`
	ExpiresAt            *time.Time `json:"expiresAt"`
}

func requiredObject(data json.RawMessage) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("invalid response data")
	}
	return object, nil
}
func requiredFields(object map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return errors.New("invalid response data")
		}
	}
	return nil
}
func stringMap(raw json.RawMessage) error {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return errors.New("invalid response data")
	}
	for _, value := range values {
		var text string
		if string(value) == "null" || json.Unmarshal(value, &text) != nil {
			return errors.New("invalid response data")
		}
	}
	return nil
}
func validateData(operation string, data json.RawMessage) error {
	object, err := requiredObject(data)
	if err != nil {
		return err
	}
	switch {
	case strings.HasSuffix(operation, ".delete"):
		var deleted bool
		raw, ok := object["deleted"]
		if !ok || json.Unmarshal(raw, &deleted) != nil || !deleted {
			return errors.New("invalid response data")
		}
	case strings.HasSuffix(operation, ".list"):
		raw, ok := object["items"]
		var items []json.RawMessage
		if !ok || json.Unmarshal(raw, &items) != nil {
			return errors.New("invalid response data")
		}
		raw, ok = object["nextCursor"]
		if !ok || (string(raw) != "null" && func() bool { var cursor string; return json.Unmarshal(raw, &cursor) != nil }()) {
			return errors.New("invalid response data")
		}
	case operation == "bucket.read":
		if err := requiredFields(object, "bucketId", "revision", "secrets", "types"); err != nil {
			return err
		}
		if err := stringMap(object["secrets"]); err != nil {
			return err
		}
		if err := stringMap(object["types"]); err != nil {
			return err
		}
	case operation == "token.info":
		return requiredFields(object, "id", "name", "scopes", "bucketIds", "allBuckets", "creatableBucketNames", "expiresAt")
	case strings.HasPrefix(operation, "secret."):
		fields := []string{"id", "bucketId", "key", "revision", "createdAt", "updatedAt", "type"}
		if operation == "secret.read" {
			fields = append(fields, "value")
		}
		return requiredFields(object, fields...)
	default:
		return requiredFields(object, "id", "name", "description", "revision", "createdAt", "updatedAt")
	}
	return nil
}
func execute[T any](ctx context.Context, c *Client, operation string, parameters any) (T, error) {
	var result T
	data, err := c.Execute(ctx, operation, parameters)
	if err != nil {
		return result, err
	}
	if err = validateData(operation, data); err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

func (c *Client) AddBucket(ctx context.Context, name, description string) (Bucket, error) {
	return execute[Bucket](ctx, c, "bucket.create", map[string]any{"name": name, "description": description})
}
func (c *Client) GetBucket(ctx context.Context, bucket string) (Bucket, error) {
	return execute[Bucket](ctx, c, "bucket.get", map[string]any{"bucket": bucket})
}

// ListBuckets returns one page. Pass an empty cursor for the first page and a limit from 1 to 200.
func (c *Client) ListBuckets(ctx context.Context, cursor string, limit int) (Page[Bucket], error) {
	return execute[Page[Bucket]](ctx, c, "bucket.list", map[string]any{"cursor": cursor, "limit": limit})
}

// ReadBucketSnapshot uses DefaultBucket when bucket is empty.
func (c *Client) ReadBucketSnapshot(ctx context.Context, bucket string) (BucketSnapshot, error) {
	if bucket == "" {
		bucket = c.DefaultBucket
		if bucket == "" {
			return BucketSnapshot{}, errors.New("specify a bucket or use a connection string containing one")
		}
	}
	return execute[BucketSnapshot](ctx, c, "bucket.read", map[string]any{"bucket": bucket})
}
func (c *Client) UpdateBucket(ctx context.Context, bucket, description string, expectedRevision int64) (Bucket, error) {
	return execute[Bucket](ctx, c, "bucket.update", map[string]any{"bucket": bucket, "description": description, "expectedRevision": expectedRevision})
}
func (c *Client) RenameBucket(ctx context.Context, bucket, name string, expectedRevision int64) (Bucket, error) {
	return execute[Bucket](ctx, c, "bucket.update", map[string]any{"bucket": bucket, "name": name, "expectedRevision": expectedRevision})
}
func (c *Client) DeleteBucket(ctx context.Context, bucket string, expectedRevision int64, recursive bool) error {
	_, err := execute[deleteResult](ctx, c, "bucket.delete", map[string]any{"bucket": bucket, "expectedRevision": expectedRevision, "recursive": recursive})
	return err
}
func (c *Client) AddSecret(ctx context.Context, bucket, key, value string) (SecretMetadata, error) {
	return execute[SecretMetadata](ctx, c, "secret.create", map[string]any{"bucket": bucket, "key": key, "value": value})
}
func (c *Client) ReadSecret(ctx context.Context, bucket, key string) (Secret, error) {
	return execute[Secret](ctx, c, "secret.read", map[string]any{"bucket": bucket, "key": key})
}
func (c *Client) ListSecrets(ctx context.Context, bucket, cursor string, limit int) (Page[SecretMetadata], error) {
	return execute[Page[SecretMetadata]](ctx, c, "secret.list", map[string]any{"bucket": bucket, "cursor": cursor, "limit": limit})
}
func (c *Client) UpdateSecret(ctx context.Context, bucket, key, value string, expectedRevision int64) (SecretMetadata, error) {
	return execute[SecretMetadata](ctx, c, "secret.update", map[string]any{"bucket": bucket, "key": key, "value": value, "expectedRevision": expectedRevision})
}

// SetSecret creates a secret when expectedRevision is zero, or updates an existing revision.
func (c *Client) SetSecret(ctx context.Context, bucket, key, value string, expectedRevision int64) (SecretMetadata, error) {
	return execute[SecretMetadata](ctx, c, "secret.set", map[string]any{"bucket": bucket, "key": key, "value": value, "expectedRevision": expectedRevision})
}
func (c *Client) DeleteSecret(ctx context.Context, bucket, key string, expectedRevision int64) error {
	_, err := execute[deleteResult](ctx, c, "secret.delete", map[string]any{"bucket": bucket, "key": key, "expectedRevision": expectedRevision})
	return err
}
func (c *Client) GetTokenInfo(ctx context.Context) (TokenInfo, error) {
	return execute[TokenInfo](ctx, c, "token.info", struct{}{})
}
