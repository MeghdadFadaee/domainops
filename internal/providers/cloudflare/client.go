// Package cloudflare implements DomainOps' provider contracts against the
// documented Cloudflare v4 REST API.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

const (
	defaultBaseURL      = "https://api.cloudflare.com/client/v4/"
	defaultUserAgent    = "DomainOps/1"
	defaultRequestLimit = int64(16 << 20)
)

// HTTPDoer is the portion of http.Client used by Client. It is deliberately
// small so callers can inject tracing, rate limiting, or a deterministic test
// transport without changing provider code.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Options customizes a Client. BaseURL and HTTPClient are principally useful
// for integration tests and trusted Cloudflare-compatible gateways.
type Options struct {
	BaseURL    string
	HTTPClient HTTPDoer
	UserAgent  string
	Now        func() time.Time
}

// Client implements the mandatory provider contract and Cloudflare's optional
// batch, DNS-01 recovery, and edge-TLS capabilities.
type Client struct {
	baseURL    string
	httpClient HTTPDoer
	userAgent  string
	now        func() time.Time
}

var (
	_ provider.Provider        = (*Client)(nil)
	_ provider.DNSBatchService = (*Client)(nil)
	_ provider.DNS01Reconciler = (*Client)(nil)
	_ provider.EdgeTLSService  = (*Client)(nil)
)

// New returns a production Cloudflare client.
func New() *Client {
	c, err := NewWithOptions(Options{})
	if err != nil {
		// All defaults are compile-time constants, so this can only indicate a
		// programming error in this package.
		panic(err)
	}
	return c
}

// NewWithOptions returns a Cloudflare client with injectable HTTP behavior.
func NewWithOptions(opts Options) (*Client, error) {
	base := strings.TrimSpace(opts.BaseURL)
	if base == "" {
		base = defaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("cloudflare: base URL must use http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("cloudflare: base URL must include a host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("cloudflare: base URL cannot include user information")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("cloudflare: base URL cannot include a query or fragment")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}

	doer := opts.HTTPClient
	if doer == nil {
		doer = &http.Client{Timeout: 30 * time.Second}
	}
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Client{
		baseURL:    u.String(),
		httpClient: doer,
		userAgent:  userAgent,
		now:        now,
	}, nil
}

type responseEnvelope struct {
	Success    *bool           `json:"success"`
	Errors     []apiMessage    `json:"errors"`
	Messages   []apiMessage    `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo resultInfo      `json:"result_info"`
}

type apiMessage struct {
	Code             int           `json:"code"`
	Message          string        `json:"message"`
	DocumentationURL string        `json:"documentation_url"`
	Source           messageSource `json:"source"`
	ErrorChain       []apiMessage  `json:"error_chain"`
}

type messageSource struct {
	Pointer string `json:"pointer"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
	Cursors    struct {
		Before string `json:"before"`
		After  string `json:"after"`
	} `json:"cursors"`
}

func (c *Client) do(
	ctx context.Context,
	auth provider.Auth,
	method string,
	path string,
	query url.Values,
	body any,
) (json.RawMessage, resultInfo, error) {
	if err := validateAuth(auth); err != nil {
		return nil, resultInfo{}, err
	}

	endpoint := c.baseURL + strings.TrimPrefix(path, "/")
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, resultInfo{}, fmt.Errorf("cloudflare: encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return nil, resultInfo{}, fmt.Errorf("cloudflare: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(auth.Token))
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, resultInfo{}, fmt.Errorf("cloudflare: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, defaultRequestLimit+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, resultInfo{}, fmt.Errorf("cloudflare: read response: %w", err)
	}
	if int64(len(payload)) > defaultRequestLimit {
		return nil, resultInfo{}, fmt.Errorf("cloudflare: response exceeded %d bytes", defaultRequestLimit)
	}

	var env responseEnvelope
	decodeErr := json.Unmarshal(payload, &env)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		apiErr := newAPIError(method, path, resp, env.Errors, env.Messages)
		if decodeErr != nil || len(payload) == 0 {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, resultInfo{}, newRateLimitError(apiErr, resp.Header, c.now())
		}
		return nil, resultInfo{}, apiErr
	}
	if decodeErr != nil {
		return nil, resultInfo{}, fmt.Errorf("cloudflare: decode %s %s response: %w", method, path, decodeErr)
	}
	if env.Success == nil {
		return nil, resultInfo{}, &ResponseError{
			Resource: method + " " + path + " envelope",
			Err:      fmt.Errorf("required success field is missing or null"),
		}
	}
	if !*env.Success {
		return nil, resultInfo{}, newAPIError(method, path, resp, env.Errors, env.Messages)
	}
	return cloneRaw(env.Result), env.ResultInfo, nil
}

func validateAuth(auth provider.Auth) error {
	if strings.TrimSpace(auth.Token) == "" {
		return &ValidationError{Field: "token", Message: "API token is required"}
	}
	switch auth.Kind {
	case domain.CredentialUserToken:
		return nil
	case domain.CredentialAccountToken:
		if strings.TrimSpace(auth.AccountID) == "" {
			return &ValidationError{Field: "account_id", Message: "account-owned tokens require an account ID"}
		}
		return nil
	default:
		return &ValidationError{Field: "kind", Message: "only scoped user and account API tokens are supported"}
	}
}

func apiPath(segments ...string) (string, error) {
	escaped := make([]string, len(segments))
	for i, segment := range segments {
		if strings.TrimSpace(segment) == "" {
			return "", &ValidationError{Field: "identifier", Message: "Cloudflare identifier cannot be empty"}
		}
		escaped[i] = url.PathEscape(segment)
	}
	return strings.Join(escaped, "/"), nil
}

func paginationQuery(req provider.PageRequest, defaultPerPage, maxPerPage int) (url.Values, int) {
	perPage := req.PerPage
	if perPage <= 0 {
		perPage = defaultPerPage
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	page := req.Page
	if page <= 0 {
		page = 1
	}
	q := url.Values{
		"page":     {strconv.Itoa(page)},
		"per_page": {strconv.Itoa(perPage)},
	}
	if req.Cursor != "" {
		if cursorPage, err := strconv.Atoi(req.Cursor); err == nil && cursorPage > 0 {
			page = cursorPage
			q.Set("page", strconv.Itoa(page))
		} else {
			q.Set("cursor", req.Cursor)
		}
	}
	return q, page
}

func nextCursor(info resultInfo, page, resultCount, perPage int) string {
	if info.Cursors.After != "" {
		return info.Cursors.After
	}
	if info.TotalPages > page {
		return strconv.Itoa(page + 1)
	}
	if info.TotalPages == 0 && perPage > 0 && resultCount == perPage {
		return strconv.Itoa(page + 1)
	}
	return ""
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}
