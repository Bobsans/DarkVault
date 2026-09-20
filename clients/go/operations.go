package darkvault

import (
	"context"
	"encoding/json"
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
	BucketID string            `json:"bucketId"`
	Revision int64             `json:"revision"`
	Secrets  map[string]string `json:"secrets"`
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

func execute[T any](ctx context.Context, c *Client, operation string, parameters any) (T, error) {
	var result T
	data, err := c.Execute(ctx, operation, parameters)
	if err != nil {
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
func (c *Client) ReadBucketSnapshot(ctx context.Context, bucket string) (BucketSnapshot, error) {
	return execute[BucketSnapshot](ctx, c, "bucket.read", map[string]any{"bucket": bucket})
}
func (c *Client) UpdateBucket(ctx context.Context, bucket, description string, expectedRevision int64) (Bucket, error) {
	return execute[Bucket](ctx, c, "bucket.update", map[string]any{"bucket": bucket, "description": description, "expectedRevision": expectedRevision})
}
func (c *Client) DeleteBucket(ctx context.Context, bucket string, expectedRevision int64, recursive bool) error {
	_, err := c.Execute(ctx, "bucket.delete", map[string]any{"bucket": bucket, "expectedRevision": expectedRevision, "recursive": recursive})
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
	_, err := c.Execute(ctx, "secret.delete", map[string]any{"bucket": bucket, "key": key, "expectedRevision": expectedRevision})
	return err
}
func (c *Client) GetTokenInfo(ctx context.Context) (TokenInfo, error) {
	return execute[TokenInfo](ctx, c, "token.info", struct{}{})
}
