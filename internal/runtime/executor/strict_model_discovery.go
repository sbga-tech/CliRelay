package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const (
	strictModelDiscoveryTimeout           = 30 * time.Second
	strictModelDiscoveryResponseBodyLimit = 4 << 20
)

func readStrictModelDiscoveryResponseBody(r io.Reader) ([]byte, error) {
	body, truncated, err := readBodyAtMost(r, strictModelDiscoveryResponseBodyLimit)
	if err != nil {
		return nil, fmt.Errorf("read model discovery response: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("model discovery response exceeds %s", formatByteLimit(strictModelDiscoveryResponseBodyLimit))
	}
	return body, nil
}

func buildV1ModelsURL(baseURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return strings.TrimSpace(baseURL)
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""

	normalizedPath := strings.TrimRight(parsed.Path, "/")
	lowerPath := strings.ToLower(normalizedPath)
	switch {
	case strings.HasSuffix(lowerPath, "/v1/models"):
	case strings.HasSuffix(lowerPath, "/v1"):
		normalizedPath += "/models"
	case strings.HasSuffix(lowerPath, "/models"):
		normalizedPath = normalizedPath[:len(normalizedPath)-len("/models")] + "/v1/models"
	default:
		normalizedPath += "/v1/models"
	}
	parsed.Path = normalizedPath
	parsed.RawPath = ""
	return parsed.String()
}

func modelsURLHasExactHostname(rawURL, hostname string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	return err == nil && strings.EqualFold(parsed.Hostname(), hostname)
}

func newStrictModelDiscoveryHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) *http.Client {
	client := newProxyAwareHTTPClient(ctx, cfg, auth, strictModelDiscoveryTimeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func applyStoredHostHeader(req *http.Request, auth *cliproxyauth.Auth) {
	if req == nil || auth == nil {
		return
	}
	for key, value := range auth.Attributes {
		if !strings.HasPrefix(key, "header:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(key, "header:"))
		host := strings.TrimSpace(value)
		if strings.EqualFold(name, "Host") && host != "" {
			req.Host = host
			return
		}
	}
}
