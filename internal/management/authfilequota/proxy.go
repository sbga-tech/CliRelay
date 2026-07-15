package authfilequota

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// AuthByIndex resolves only records owned by the Service tenant.
func (s *Service) AuthByIndex(authIndex string) *coreauth.Auth {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" || s == nil || s.authManager == nil {
		return nil
	}
	for _, auth := range s.authManager.ListForTenant(s.tenantID) {
		if auth == nil {
			continue
		}
		auth.EnsureIndex()
		if auth.Index == authIndex {
			return auth
		}
	}
	return nil
}

func (s *Service) quotaTransport(auth *coreauth.Auth) http.RoundTripper {
	var proxyCandidates []string
	if s != nil && s.cfg != nil {
		proxyID, fallbackURL := "", ""
		if auth != nil {
			proxyID, fallbackURL = auth.ProxyID, auth.ProxyURL
		}
		if proxyURL := strings.TrimSpace(s.cfg.ResolveProxyURL(proxyID, fallbackURL)); proxyURL != "" {
			proxyCandidates = append(proxyCandidates, proxyURL)
		}
	} else if auth != nil {
		if proxyURL := strings.TrimSpace(auth.ProxyURL); proxyURL != "" {
			proxyCandidates = append(proxyCandidates, proxyURL)
		}
	}

	var sdkCfg *config.SDKConfig
	if s != nil && s.cfg != nil {
		sdkCfg = &s.cfg.SDKConfig
	}
	for _, proxyURL := range proxyCandidates {
		if transport := buildQuotaProxyTransport(proxyURL, sdkCfg); transport != nil {
			return transport
		}
	}
	return nil
}

func buildQuotaProxyTransport(proxyURL string, sdkCfg *config.SDKConfig) *http.Transport {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		log.WithError(err).Debug("parse quota proxy URL failed")
		return nil
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		log.Debug("quota proxy URL missing scheme/host")
		return nil
	}

	if parsed.Scheme == "socks5" {
		var proxyAuth *proxy.Auth
		if parsed.User != nil {
			password, _ := parsed.User.Password()
			proxyAuth = &proxy.Auth{User: parsed.User.Username(), Password: password}
		}
		dialer, err := proxy.SOCKS5("tcp", parsed.Host, proxyAuth, proxy.Direct)
		if err != nil {
			log.WithError(err).Debug("create quota SOCKS5 dialer failed")
			return nil
		}
		return &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.Dial(network, address)
			},
		}
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		transport := &http.Transport{Proxy: http.ProxyURL(parsed)}
		util.ApplyTLSConfig(transport, sdkCfg)
		return transport
	}
	log.Debugf("unsupported quota proxy scheme: %s", parsed.Scheme)
	return nil
}
