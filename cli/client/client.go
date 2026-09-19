// Package client implements the DarkVault HTTP v1 protocol.
package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

const MaxBody = 2 * 1024 * 1024

type Client struct {
	URL, Token string
	HTTP       *http.Client
}
type ServerKey struct {
	ProtocolVersion int             `json:"protocolVersion"`
	ServerID        string          `json:"serverId"`
	Kid             string          `json:"kid"`
	PublicKey       jose.JSONWebKey `json:"publicKey"`
	NotAfter        time.Time       `json:"notAfter"`
}
type Request struct {
	V          int             `json:"v"`
	RequestID  string          `json:"requestId"`
	IssuedAt   time.Time       `json:"issuedAt"`
	ServerID   string          `json:"serverId"`
	Audience   string          `json:"audience"`
	Operation  string          `json:"operation"`
	Parameters any             `json:"parameters"`
	ReplyKey   jose.JSONWebKey `json:"replyKey"`
}
type Response struct {
	V         int             `json:"v"`
	RequestID string          `json:"requestId"`
	ServerID  string          `json:"serverId"`
	Audience  string          `json:"audience"`
	Operation string          `json:"operation"`
	Status    int             `json:"status"`
	Data      json.RawMessage `json:"data"`
	Error     *APIError       `json:"error"`
}
type APIError struct {
	Code      string `json:"code"`
	Status    int    `json:"-"`
	RequestID string `json:"-"`
}

func (e *APIError) Error() string { return "DarkVault request failed (" + e.Code + ")" }
func NormalizeServer(server string) (string, error) {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("use an HTTPS origin")
	}
	return strings.TrimRight(server, "/"), nil
}
func ValidateToken(token string) error {
	if len(token) != 64 || !strings.HasPrefix(token, "dv1_") {
		return errors.New("invalid token format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[4:])
	if err != nil || len(raw) != 45 {
		return errors.New("invalid token format")
	}
	return nil
}
func New(server, token string) (*Client, error) {
	server, err := NormalizeServer(server)
	if err != nil {
		return nil, err
	}
	if err = ValidateToken(token); err != nil {
		return nil, err
	}
	return &Client{URL: server, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func readBody(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if e == nil && (len(b) > MaxBody || !utf8.Valid(b)) {
		return nil, errors.New("invalid body")
	}
	return b, e
}
func newID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func ValidateJSON(b []byte) error {
	if len(b) > 1536*1024 || !utf8.Valid(b) {
		return errors.New("invalid JSON size or encoding")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON too deep")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		switch t {
		case json.Delim('{'):
			names := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || names[s] {
					return errors.New("duplicate JSON field")
				}
				names[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case json.Delim('['):
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func ValidateEnvelope(body, kind, kid string) error {
	if len(body) > MaxBody {
		return errors.New("envelope too large")
	}
	parts := strings.Split(body, ".")
	if len(parts) != 5 || parts[1] != "" || len(parts[0]) > 4096 {
		return errors.New("invalid envelope")
	}
	decode := func(s string) ([]byte, error) {
		b, e := base64.RawURLEncoding.DecodeString(s)
		if e == nil && base64.RawURLEncoding.EncodeToString(b) != s {
			e = errors.New("noncanonical base64url")
		}
		return b, e
	}
	b, e := decode(parts[0])
	if e != nil {
		return e
	}
	if e = ValidateJSON(b); e != nil {
		return e
	}
	var h map[string]json.RawMessage
	if e = json.Unmarshal(b, &h); e != nil {
		return e
	}
	if len(h) != 6 {
		return errors.New("invalid header")
	}
	for name, want := range map[string]string{"alg": "ECDH-ES", "enc": "A256GCM", "typ": kind, "kid": kid, "cty": "application/json"} {
		var v string
		if json.Unmarshal(h[name], &v) != nil || v != want {
			return errors.New("invalid header")
		}
	}
	var epk map[string]json.RawMessage
	if json.Unmarshal(h["epk"], &epk) != nil || len(epk) != 4 {
		return errors.New("invalid public key")
	}
	var key jose.JSONWebKey
	if e = json.Unmarshal(h["epk"], &key); e != nil {
		return e
	}
	pub, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !key.IsPublic() {
		return errors.New("invalid public key")
	}
	for i, n := range map[int]int{2: 12, 4: 16} {
		b, e = decode(parts[i])
		if e != nil || len(b) != n {
			return errors.New("invalid IV or tag")
		}
	}
	if _, e = decode(parts[3]); e != nil {
		return e
	}
	return nil
}
func Encrypt(payload []byte, key jose.JSONWebKey, kid, kind string) (string, error) {
	if e := ValidateJSON(payload); e != nil {
		return "", e
	}
	pub, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return "", errors.New("invalid server key")
	}
	opts := new(jose.EncrypterOptions).WithType(jose.ContentType(kind)).WithContentType("application/json").WithHeader("kid", kid)
	enc, e := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, opts)
	if e != nil {
		return "", e
	}
	jwe, e := enc.Encrypt(payload)
	if e != nil {
		return "", e
	}
	body, e := jwe.CompactSerialize()
	if len(body) > MaxBody {
		return "", errors.New("request too large")
	}
	return body, e
}
func Decrypt(body string, key *ecdsa.PrivateKey, kid, kind string) ([]byte, error) {
	if e := ValidateEnvelope(body, kind, kid); e != nil {
		return nil, e
	}
	jwe, e := jose.ParseEncrypted(body, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if e != nil {
		return nil, e
	}
	plain, e := jwe.Decrypt(key)
	if e != nil {
		return nil, e
	}
	return plain, ValidateJSON(plain)
}
func (c *Client) Execute(ctx context.Context, op string, parameters any) (json.RawMessage, error) {
	timeout := c.HTTP.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	discovery, e := http.NewRequestWithContext(ctx, "GET", c.URL+"/api/v1/crypto/key", nil)
	if e != nil {
		return nil, e
	}
	r, e := c.HTTP.Do(discovery)
	if e != nil {
		return nil, errors.New("server unavailable")
	}
	body, e := readBody(r.Body)
	r.Body.Close()
	if e != nil {
		return nil, e
	}
	if r.StatusCode != 200 {
		return nil, &APIError{Code: "key_unavailable", Status: r.StatusCode}
	}
	var key ServerKey
	if e = ValidateJSON(body); e != nil {
		return nil, e
	}
	if e = json.Unmarshal(body, &key); e != nil {
		return nil, e
	}
	if key.ProtocolVersion != 1 || !key.NotAfter.After(time.Now()) {
		return nil, errors.New("invalid server key")
	}
	reply, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	id, e := newID()
	if e != nil {
		return nil, e
	}
	request := Request{1, id, time.Now().UTC(), key.ServerID, "data", op, parameters, jose.JSONWebKey{Key: &reply.PublicKey}}
	plain, e := json.Marshal(request)
	if e != nil {
		return nil, e
	}
	encrypted, e := Encrypt(plain, key.PublicKey, key.Kid, "darkvault-request+jwe")
	if e != nil {
		return nil, e
	}
	message, e := http.NewRequestWithContext(ctx, "POST", c.URL+"/api/v1/execute", strings.NewReader(encrypted))
	if e != nil {
		return nil, e
	}
	message.Header.Set("Authorization", "Bearer "+c.Token)
	message.Header.Set("Content-Type", "application/jose")
	message.Header.Set("Accept", "application/jose")
	r, e = c.HTTP.Do(message)
	if e != nil {
		return nil, errors.New("request outcome unknown; verify state before retrying")
	}
	defer r.Body.Close()
	body, e = readBody(r.Body)
	if e != nil {
		return nil, e
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/jose" {
		return nil, &APIError{Code: "transport_error", Status: r.StatusCode, RequestID: id}
	}
	plain, e = Decrypt(string(body), reply, id, "darkvault-response+jwe")
	if e != nil {
		return nil, errors.New("invalid encrypted response")
	}
	var response Response
	if e = json.Unmarshal(plain, &response); e != nil {
		return nil, e
	}
	if response.V != 1 || response.RequestID != id || response.ServerID != key.ServerID || response.Audience != "data" || response.Operation != op || response.Status != r.StatusCode {
		return nil, errors.New("mismatched response")
	}
	if response.Error != nil {
		response.Error.Status = r.StatusCode
		response.Error.RequestID = id
		return nil, response.Error
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 || len(response.Data) == 0 {
		return nil, fmt.Errorf("invalid response status: %d", r.StatusCode)
	}
	return response.Data, nil
}
func (c *Client) ReadBucket(ctx context.Context, bucket string) (map[string]string, error) {
	b, e := c.Execute(ctx, "bucket.read", map[string]any{"bucket": bucket})
	if e != nil {
		return nil, e
	}
	var s struct {
		Secrets map[string]string `json:"secrets"`
	}
	e = json.Unmarshal(b, &s)
	return s.Secrets, e
}
