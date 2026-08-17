package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	armScope   = "https://management.azure.com/.default"
	graphScope = "https://graph.microsoft.com/.default"
	armBase    = "https://management.azure.com"
	graphBase  = "https://graph.microsoft.com/v1.0"

	maxAttempts = 6
)

// httpClient bounds every request; retries add their own waits on top.
var httpClient = &http.Client{Timeout: 90 * time.Second}

func getJSON(ctx context.Context, token, url string, out any) error {
	return request(ctx, http.MethodGet, token, url, nil, out)
}

func postJSON(ctx context.Context, token, url string, body, out any) error {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	return request(ctx, http.MethodPost, token, url, raw, out)
}

// request sends one call with retry/backoff on throttling (429) and transient
// 5xx / network errors. The body is captured as bytes so each attempt can
// rebuild the request. 4xx (other than 429) fail fast — they won't self-heal.
func request(ctx context.Context, method, token, url string, body []byte, out any) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			if !sleepBackoff(ctx, attempt, 0) {
				return err
			}
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch {
		case resp.StatusCode < 300:
			if out == nil {
				return nil
			}
			return json.Unmarshal(b, out)
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s %s -> %d: %s", method, req.URL.Path, resp.StatusCode, firstLine(string(b)))
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			if !sleepBackoff(ctx, attempt, retryAfter) {
				return lastErr
			}
		default: // other 4xx — fail fast
			return fmt.Errorf("%s %s -> %d: %s", method, req.URL.Path, resp.StatusCode, firstLine(string(b)))
		}
	}
	return fmt.Errorf("exhausted %d attempts: %w", maxAttempts, lastErr)
}

// sleepBackoff waits before the next attempt (honoring Retry-After when given),
// returning false if there are no attempts left or the context is done.
func sleepBackoff(ctx context.Context, attempt int, retryAfter time.Duration) bool {
	if attempt >= maxAttempts {
		return false
	}
	wait := retryAfter
	if wait <= 0 {
		// exponential: 1s, 2s, 4s, 8s ... capped at 30s.
		wait = time.Duration(1<<uint(attempt-1)) * time.Second
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
	}
	select {
	case <-time.After(wait):
		return true
	case <-ctx.Done():
		return false
	}
}

func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// existsGET reports whether a resource exists (404 → false, other errors bubble up).
func existsGET(ctx context.Context, token, url string) (bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("GET %s -> %d: %s", req.URL.Path, resp.StatusCode, firstLine(string(b)))
	}
	return true, nil
}

// del issues a DELETE; a 404 counts as success (already gone / idempotent).
func del(ctx context.Context, token, url string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 404 || resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("DELETE %s -> %d: %s", req.URL.Path, resp.StatusCode, firstLine(string(b)))
}

// pagedValues follows ARM `nextLink` / Graph `@odata.nextLink`, accumulating the
// `value` array across pages (each page uses the retrying request path).
func pagedValues(ctx context.Context, token, url string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for url != "" {
		var page struct {
			Value     []json.RawMessage `json:"value"`
			NextLink  string            `json:"nextLink"`
			ODataNext string            `json:"@odata.nextLink"`
		}
		if err := getJSON(ctx, token, url, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		url = page.NextLink
		if url == "" {
			url = page.ODataNext
		}
	}
	return all, nil
}
