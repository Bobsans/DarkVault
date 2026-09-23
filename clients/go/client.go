// Package darkvault implements the DarkVault HTTP v1 protocol.
package darkvault

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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

const MaxBody = 2 * 1024 * 1024
const MaxPlaintext = 1536 * 1024

type Client struct {
	URL            string
	token          string
	DefaultBucket  string
	HTTP           *http.Client
	keyMu          sync.Mutex
	serverKey      *ServerKey
	serverKeyUntil time.Time
	serverKeyURL   string
}

// Token returns the bearer token for explicit credential handoff.
func (c *Client) Token() string { return c.token }

// String intentionally omits the bearer token from diagnostic output.
func (c *Client) String() string {
	return fmt.Sprintf("darkvault.Client{URL:%q, DefaultBucket:%q}", c.URL, c.DefaultBucket)
}

// GoString keeps %#v output secret-free as well.
func (c *Client) GoString() string { return c.String() }

type ServerKey struct {
	ProtocolVersion int `json:"protocolVersion"`

	ServerID string `json:"serverId"`

	ServerTime time.Time `json:"serverTime"`

	Kid string `json:"kid"`

	PublicKey jose.JSONWebKey `json:"publicKey"`

	NotAfter time.Time `json:"notAfter"`

	Limits TransportLimits `json:"limits"`
}
type TransportLimits struct {
	MaxBodyBytes int `json:"maxBodyBytes"`

	MaxPlaintextBytes int `json:"maxPlaintextBytes"`
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

func (r *Response) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["error"]; !ok {
		return errors.New("missing response error")
	}
	type responseAlias Response
	var decoded responseAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(fields["error"]), []byte("null")) {
		var errorFields map[string]json.RawMessage
		if err := json.Unmarshal(fields["error"], &errorFields); err != nil || errorFields == nil {
			return errors.New("invalid response error")
		}
		var code, message string
		if err := json.Unmarshal(errorFields["code"], &code); err != nil || json.Unmarshal(errorFields["message"], &message) != nil || code == "" {
			return errors.New("invalid response error")
		}
		if decoded.Error == nil {
			return errors.New("invalid response error")
		}
	}
	*r = Response(decoded)
	return nil
}

type APIError struct {
	Code       string        `json:"code"`
	Status     int           `json:"-"`
	RequestID  string        `json:"-"`
	RetryAfter time.Duration `json:"-"`
}

var errorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

func safeErrorCode(code string) string {
	if errorCodePattern.MatchString(code) {
		return code
	}
	return "server_error"
}
func (e *APIError) Error() string { return "DarkVault request failed (" + safeErrorCode(e.Code) + ")" }
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
	return &Client{URL: server, token: token, HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// NewFromURL accepts https://<token>@host[:port]/bucket-name.
func NewFromURL(connectionString string) (*Client, error) {
	match := regexp.MustCompile(`\Ahttps://(dv1_[A-Za-z0-9_-]{60})@([^/?#@\s\\]+)/([a-z0-9][a-z0-9_-]{0,62})\z`).FindStringSubmatch(connectionString)
	if match == nil {
		return nil, errors.New("invalid DarkVault connection string")
	}
	c, err := New("https://"+match[2], match[1])
	if err != nil {
		return nil, errors.New("invalid DarkVault connection string")
	}
	origin, err := url.Parse(c.URL)
	if err != nil || origin.Hostname() == "" {
		return nil, errors.New("invalid DarkVault connection string")
	}
	if port := origin.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid DarkVault connection string")
		}
	}
	c.DefaultBucket = match[3]
	return c, nil
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

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validateServerKey(key ServerKey) error {
	if key.ProtocolVersion != 1 || !uuidPattern.MatchString(key.ServerID) || !uuidPattern.MatchString(key.Kid) || key.ServerTime.IsZero() || !key.NotAfter.After(time.Now()) {
		return errors.New("invalid server key")
	}
	if key.Limits.MaxBodyBytes < 1 || key.Limits.MaxBodyBytes > MaxBody || key.Limits.MaxPlaintextBytes < 1 || key.Limits.MaxPlaintextBytes > MaxPlaintext {
		return errors.New("invalid server limits")
	}
	pub, ok := key.PublicKey.Key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !key.PublicKey.IsPublic() {
		return errors.New("invalid public key")
	}
	return nil
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
func (c *Client) cachedServerKey() (ServerKey, bool) {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.serverKey == nil || c.serverKeyURL != c.URL || !time.Now().Before(c.serverKeyUntil) || !c.serverKey.NotAfter.After(time.Now()) {
		return ServerKey{}, false
	}
	return *c.serverKey, true
}
func (c *Client) invalidateServerKey() {
	c.keyMu.Lock()
	c.serverKey = nil
	c.serverKeyUntil = time.Time{}
	c.serverKeyURL = ""
	c.keyMu.Unlock()
}
func (c *Client) discoverServerKey(ctx context.Context, transport *http.Client) (ServerKey, error) {
	if key, ok := c.cachedServerKey(); ok {
		return key, nil
	}
	discovery, err := http.NewRequestWithContext(ctx, "GET", c.URL+"/api/v1/crypto/key", nil)
	if err != nil {
		return ServerKey{}, err
	}
	r, err := transport.Do(discovery)
	if err != nil {
		return ServerKey{}, fmt.Errorf("server unavailable: %w", err)
	}
	body, err := readBody(r.Body)
	r.Body.Close()
	if err != nil {
		return ServerKey{}, err
	}
	if r.StatusCode != http.StatusOK {
		return ServerKey{}, plainAPIError(body, r.StatusCode, "", r.Header)
	}
	var key ServerKey
	if err = ValidateJSON(body); err != nil {
		return ServerKey{}, err
	}
	if err = json.Unmarshal(body, &key); err != nil {
		return ServerKey{}, err
	}
	if err = validateServerKey(key); err != nil {
		return ServerKey{}, err
	}
	expires := time.Now().Add(5 * time.Minute)
	if key.NotAfter.Before(expires) {
		expires = key.NotAfter
	}
	c.keyMu.Lock()
	c.serverKey = &key
	c.serverKeyUntil = expires
	c.serverKeyURL = c.URL
	c.keyMu.Unlock()
	return key, nil
}
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return maxDuration(0, time.Until(date))
	}
	return 0
}
func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
func plainAPIError(body []byte, status int, requestID string, headers http.Header) error {
	code := "transport_error"
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if ValidateJSON(body) == nil && json.Unmarshal(body, &envelope) == nil && envelope.Error.Code != "" {
		code = safeErrorCode(envelope.Error.Code)
	}
	return &APIError{Code: code, Status: status, RequestID: requestID, RetryAfter: parseRetryAfter(headers.Get("Retry-After"))}
}
func (c *Client) ExecuteValidated(ctx context.Context, op string, parameters any) (json.RawMessage, error) {
	data, err := c.Execute(ctx, op, parameters)
	if err != nil {
		return nil, err
	}
	if err = validateData(op, data); err != nil {
		return nil, fmt.Errorf("invalid response data: %w", err)
	}
	return data, nil
}

func (c *Client) Execute(ctx context.Context, op string, parameters any) (json.RawMessage, error) {
	if c.HTTP == nil {
		return nil, errors.New("HTTP client is required")
	}
	if _, err := NormalizeServer(c.URL); err != nil {
		return nil, err
	}
	if err := ValidateToken(c.token); err != nil {
		return nil, err
	}
	transport := *c.HTTP
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	timeout := c.HTTP.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	keyRetry := false
	for {
		key, err := c.discoverServerKey(ctx, &transport)
		if err != nil {
			return nil, err
		}
		reply, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		id, err := newID()
		if err != nil {
			return nil, err
		}
		request := Request{1, id, time.Now().UTC(), key.ServerID, "data", op, parameters, jose.JSONWebKey{Key: &reply.PublicKey}}
		plain, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		encrypted, err := Encrypt(plain, key.PublicKey, key.Kid, "darkvault-request+jwe")
		if err != nil {
			return nil, err
		}
		message, err := http.NewRequestWithContext(ctx, "POST", c.URL+"/api/v1/execute", strings.NewReader(encrypted))
		if err != nil {
			return nil, err
		}
		message.Header.Set("Authorization", "Bearer "+c.token)
		message.Header.Set("Content-Type", "application/jose")
		message.Header.Set("Accept", "application/jose")
		r, err := transport.Do(message)
		if err != nil {
			return nil, fmt.Errorf("request outcome unknown; verify state before retrying: %w", err)
		}
		body, err := readBody(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/jose" {
			apiErr := plainAPIError(body, r.StatusCode, id, r.Header)
			if api, ok := apiErr.(*APIError); ok && api.Code == "unknown_key" && !keyRetry {
				c.invalidateServerKey()
				keyRetry = true
				continue
			}
			return nil, apiErr
		}
		plain, err = Decrypt(string(body), reply, id, "darkvault-response+jwe")
		if err != nil {
			return nil, fmt.Errorf("invalid encrypted response: %w", err)
		}
		var response Response
		if err = json.Unmarshal(plain, &response); err != nil {
			return nil, err
		}
		if response.V != 1 || response.RequestID != id || response.ServerID != key.ServerID || response.Audience != "data" || response.Operation != op || response.Status != r.StatusCode {
			return nil, errors.New("mismatched response")
		}
		if response.Error != nil {

			response.Error.Code = safeErrorCode(response.Error.Code)
			response.Error.Status = r.StatusCode
			response.Error.RequestID = id
			return nil, response.Error
		}
		if r.StatusCode < 200 || r.StatusCode >= 300 || len(response.Data) == 0 || bytes.Equal(response.Data, []byte("null")) {
			return nil, fmt.Errorf("invalid response status: %d", r.StatusCode)
		}
		return response.Data, nil
	}
}
func (c *Client) ReadBucket(ctx context.Context, bucket string) (map[string]string, error) {
	snapshot, err := c.ReadBucketSnapshot(ctx, bucket)
	return snapshot.Secrets, err
}
