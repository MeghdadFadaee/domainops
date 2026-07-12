package cloudflare

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnauthorized          = errors.New("cloudflare: unauthorized")
	ErrForbidden             = errors.New("cloudflare: forbidden")
	ErrNotFound              = errors.New("cloudflare: resource not found")
	ErrConflict              = errors.New("cloudflare: conflict")
	ErrRateLimited           = errors.New("cloudflare: rate limited")
	ErrUnsupportedRecordType = errors.New("cloudflare: unsupported writable DNS record type")
)

// ValidationError reports an invalid local request without contacting
// Cloudflare. It intentionally never includes secret material.
type ValidationError struct {
	Field   string
	Message string
}

// ResponseError reports a successful HTTP response whose Cloudflare envelope
// or result does not match the documented schema. It usually indicates an
// upstream API change and leaves a mutation's outcome ambiguous.
type ResponseError struct {
	Resource string
	Err      error
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("cloudflare: decode %s response: %v", e.Resource, e.Err)
}

func (e *ResponseError) Unwrap() error { return e.Err }

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return "cloudflare: " + e.Message
	}
	return fmt.Sprintf("cloudflare: invalid %s: %s", e.Field, e.Message)
}

func (e *ValidationError) MutationOutcomeDefinitive() bool { return true }
func (e *ValidationError) MutationNotAttempted() bool      { return true }
func (e *ValidationError) CredentialVerificationAuthoritative() bool {
	return true
}

// ErrorDetail is one structured error returned by the Cloudflare API.
type ErrorDetail struct {
	Code             int
	Message          string
	Pointer          string
	DocumentationURL string
}

// APIError is a redacted, structured Cloudflare API failure.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Code       int
	Message    string
	Details    []ErrorDetail
	RequestID  string
}

func (e *APIError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = http.StatusText(e.StatusCode)
	}
	if e.Code != 0 {
		return fmt.Sprintf("cloudflare API %s %s failed (%d, code %d): %s", e.Method, e.Path, e.StatusCode, e.Code, message)
	}
	return fmt.Sprintf("cloudflare API %s %s failed (%d): %s", e.Method, e.Path, e.StatusCode, message)
}

func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	default:
		return false
	}
}

// MutationOutcomeDefinitive distinguishes a provider rejection from a lost or
// ambiguous response. APIError is also returned for a successful HTTP response
// whose Cloudflare envelope explicitly reports success:false. Server errors can
// occur after processing began and remain ambiguous.
func (e *APIError) MutationOutcomeDefinitive() bool {
	return e.StatusCode > 0 && e.StatusCode < http.StatusInternalServerError
}

// CredentialVerificationAuthoritative only classifies authentication and
// authorization rejections. In particular, 429 and 5xx responses must leave a
// previously valid credential valid, because they describe provider health or
// throttling rather than the token's state.
func (e *APIError) CredentialVerificationAuthoritative() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

func (e *APIError) AccessDenialAuthoritative() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

type mutationNotAttemptedError struct{ err error }

func (e *mutationNotAttemptedError) Error() string              { return e.err.Error() }
func (e *mutationNotAttemptedError) Unwrap() error              { return e.err }
func (e *mutationNotAttemptedError) MutationNotAttempted() bool { return true }

func markMutationNotAttempted(err error) error {
	if err == nil {
		return nil
	}
	return &mutationNotAttemptedError{err: err}
}

// RateLimitError includes Cloudflare's requested retry time where available.
type RateLimitError struct {
	APIError   *APIError
	RetryAfter time.Duration
	RetryAt    time.Time
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%s; retry after %s", e.APIError.Error(), e.RetryAfter)
	}
	return e.APIError.Error()
}

func (e *RateLimitError) Unwrap() error { return e.APIError }

func (e *RateLimitError) Is(target error) bool {
	return target == ErrRateLimited || errors.Is(e.APIError, target)
}

func newAPIError(method, path string, resp *http.Response, errorsList, messages []apiMessage) *APIError {
	details := flattenMessages(errorsList)
	if len(details) == 0 {
		details = flattenMessages(messages)
	}
	result := &APIError{
		Method:     method,
		Path:       path,
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("CF-Ray"),
		Details:    details,
	}
	if len(details) > 0 {
		result.Code = details[0].Code
		result.Message = details[0].Message
	}
	return result
}

func flattenMessages(messages []apiMessage) []ErrorDetail {
	var result []ErrorDetail
	var appendMessage func(apiMessage)
	appendMessage = func(message apiMessage) {
		result = append(result, ErrorDetail{
			Code:             message.Code,
			Message:          message.Message,
			Pointer:          message.Source.Pointer,
			DocumentationURL: message.DocumentationURL,
		})
		for _, child := range message.ErrorChain {
			appendMessage(child)
		}
	}
	for _, message := range messages {
		appendMessage(message)
	}
	return result
}

func newRateLimitError(apiErr *APIError, header http.Header, now time.Time) *RateLimitError {
	retryAt, retryAfter := parseRetryAfter(header.Get("Retry-After"), now)
	if retryAfter == 0 {
		if unix, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil && unix > 0 {
			retryAt = time.Unix(unix, 0)
			retryAfter = retryAt.Sub(now)
			if retryAfter < 0 {
				retryAfter = 0
			}
		}
	}
	return &RateLimitError{APIError: apiErr, RetryAfter: retryAfter, RetryAt: retryAt}
}

func parseRetryAfter(value string, now time.Time) (time.Time, time.Duration) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		delay := time.Duration(seconds) * time.Second
		return now.Add(delay), delay
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return time.Time{}, 0
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return when, delay
}
