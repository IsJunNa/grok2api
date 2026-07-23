package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	domainegress "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/pkg/signerurl"
	"golang.org/x/net/html"
	"golang.org/x/sync/singleflight"
)

const (
	// 默认指向同 compose 网络中的无头浏览器签名服务；公网默认签名站已受 CF 拦截。
	defaultStatsigSignerURL = "http://statsig-signer:3000/sign"
	statsigCacheTTL         = time.Hour
	statsigCacheMaxEntries  = 4096
	statsigMetaBodyLimit    = 4 << 20
	statsigResponseLimit    = 4 << 10
)

type statsigCacheEntry struct {
	value     string
	expiresAt time.Time
}

type statsigSignResult struct {
	value  string
	source string
}

type statsigWarmTarget struct {
	method string
	target string
}

type statsigSigner struct {
	client           *http.Client
	fetchMeta        func(context.Context, string, string, *infraegress.Lease) (string, error)
	validateEndpoint func(context.Context, string) error
	now              func() time.Time
	mu               sync.Mutex
	entries          map[string]statsigCacheEntry
	refreshes        singleflight.Group
}

func newStatsigSigner() *statsigSigner {
	return &statsigSigner{
		client: &http.Client{
			Timeout:       12 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		fetchMeta:        fetchStatsigMetaContent,
		validateEndpoint: validateStatsigSignerEndpoint,
		now:              time.Now,
		entries:          make(map[string]statsigCacheEntry),
	}
}

func (s *statsigSigner) Sign(ctx context.Context, baseURL, signerURL, token string, lease *infraegress.Lease, method, target string) (string, string, error) {
	key, path, err := statsigSignatureKey(baseURL, signerURL, method, target)
	if err != nil {
		return "", "", err
	}
	if value, ok := s.cached(key, s.now().UTC()); ok {
		return value, "cache", nil
	}
	value, err, _ := s.refreshes.Do(key, func() (any, error) {
		now := s.now().UTC()
		if cached, ok := s.cached(key, now); ok {
			return statsigSignResult{value: cached, source: "cache"}, nil
		}
		fresh, refreshErr := s.freshSignature(ctx, baseURL, signerURL, token, lease, method, path)
		if refreshErr != nil {
			if stale, ok := s.stale(key); ok {
				return statsigSignResult{value: stale, source: "stale"}, nil
			}
			return statsigSignResult{}, refreshErr
		}
		s.store(key, fresh, now.Add(statsigCacheTTL), now)
		return statsigSignResult{value: fresh, source: "refresh"}, nil
	})
	if err != nil {
		return "", "", err
	}
	result := value.(statsigSignResult)
	return result.value, result.source, nil
}

// Warm 预热多个常用签名键。metaContent 为尽力获取：无头浏览器签名机不依赖它，
// 仅部分远程签名服务需要；meta 失败时仍继续签名，避免首页被 CF 拦截后整链不可用。
func (s *statsigSigner) Warm(ctx context.Context, baseURL, signerURL, token string, lease *infraegress.Lease, targets []statsigWarmTarget) (int, error) {
	now := s.now().UTC()
	type pendingTarget struct {
		key    string
		method string
		path   string
	}
	pending := make([]pendingTarget, 0, len(targets))
	for _, target := range targets {
		key, path, err := statsigSignatureKey(baseURL, signerURL, target.method, target.target)
		if err != nil {
			return 0, err
		}
		if _, ok := s.cached(key, now); ok {
			continue
		}
		pending = append(pending, pendingTarget{key: key, method: target.method, path: path})
	}
	if len(pending) == 0 {
		return 0, nil
	}
	meta, _ := s.fetchMeta(ctx, baseURL, token, lease)
	warmed := 0
	for _, target := range pending {
		value, signErr := s.requestSignature(ctx, signerURL, target.method, target.path, meta)
		if signErr != nil && meta != "" {
			// 远程签名失败时再试一次无 meta，兼容只吃 path/method 的无头浏览器签名机。
			value, signErr = s.requestSignature(ctx, signerURL, target.method, target.path, "")
		}
		if signErr != nil {
			return warmed, signErr
		}
		s.store(target.key, value, now.Add(statsigCacheTTL), now)
		warmed++
	}
	return warmed, nil
}

func (s *statsigSigner) freshSignature(ctx context.Context, baseURL, signerURL, token string, lease *infraegress.Lease, method, path string) (string, error) {
	// metaContent 尽力获取：无头浏览器签名机只需要 method/path。
	meta, _ := s.fetchMeta(ctx, baseURL, token, lease)
	signature, err := s.requestSignature(ctx, signerURL, method, path, meta)
	if err == nil {
		return signature, nil
	}
	if meta != "" {
		if signature, retryErr := s.requestSignature(ctx, signerURL, method, path, ""); retryErr == nil {
			return signature, nil
		}
		meta, refreshErr := s.fetchMeta(ctx, baseURL, token, lease)
		if refreshErr == nil {
			signature, retryErr := s.requestSignature(ctx, signerURL, method, path, meta)
			if retryErr == nil {
				return signature, nil
			}
			err = retryErr
		}
	}
	return "", fmt.Errorf("Statsig 签名失败: %w", err)
}

func (s *statsigSigner) Invalidate(baseURL, signerURL, method, target string) {
	key, _, err := statsigSignatureKey(baseURL, signerURL, method, target)
	if err != nil {
		return
	}
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
}

func (s *statsigSigner) Clear() {
	s.mu.Lock()
	clear(s.entries)
	s.mu.Unlock()
}

func (s *statsigSigner) cached(key string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok || entry.value == "" || !now.Before(entry.expiresAt) {
		return "", false
	}
	return entry.value, true
}

func (s *statsigSigner) stale(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	return entry.value, ok && validStatsigID(entry.value)
}

func (s *statsigSigner) store(key, value string, expiresAt, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for existingKey, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, existingKey)
		}
	}
	if len(s.entries) >= statsigCacheMaxEntries {
		oldestKey := ""
		var oldestExpiry time.Time
		for existingKey, entry := range s.entries {
			if oldestKey == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestKey, oldestExpiry = existingKey, entry.expiresAt
			}
		}
		delete(s.entries, oldestKey)
	}
	s.entries[key] = statsigCacheEntry{value: value, expiresAt: expiresAt}
}

func statsigSignatureKey(baseURL, signerURL, method, target string) (string, string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("解析 Statsig 目标地址: %w", err)
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	return strings.TrimRight(baseURL, "/") + "\x00" + strings.TrimSpace(signerURL) + "\x00" + method + "\x00" + path, path, nil
}

func (s *statsigSigner) requestSignature(ctx context.Context, endpoint, method, path, metaContent string) (string, error) {
	if err := s.validateEndpoint(ctx, endpoint); err != nil {
		return "", err
	}
	payload := map[string]any{
		"method": strings.ToUpper(strings.TrimSpace(method)),
		"path":   path,
	}
	// 仅在拿到 meta 时附带 environment，兼容只消费 path/method 的无头浏览器签名机。
	if meta := strings.TrimSpace(metaContent); meta != "" {
		payload["environment"] = map[string]string{"metaContent": meta}
	}
	bodyBytes, _ := json.Marshal(payload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, statsigResponseLimit+1))
	if err != nil {
		return "", err
	}
	if len(body) > statsigResponseLimit {
		return "", fmt.Errorf("签名响应超过安全上限")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("签名服务返回 %d", response.StatusCode)
	}
	statsigID, ok := parseStatsigSignatureResponse(body)
	if !ok {
		return "", fmt.Errorf("签名服务响应无效")
	}
	return statsigID, nil
}

// parseStatsigSignatureResponse 兼容两种签名机响应：
//   - 远程/自建 Go 签名：{"x-statsig-id":"..."}
//   - 无头浏览器签名机：{"statsig":"..."}
func parseStatsigSignatureResponse(body []byte) (string, bool) {
	var value struct {
		StatsigID string `json:"x-statsig-id"`
		Statsig   string `json:"statsig"`
	}
	if json.Unmarshal(body, &value) != nil {
		return "", false
	}
	for _, candidate := range []string{value.StatsigID, value.Statsig} {
		if validStatsigID(candidate) {
			return strings.TrimSpace(candidate), true
		}
	}
	return "", false
}

func validateStatsigSignerEndpoint(ctx context.Context, endpoint string) error {
	_ = ctx
	return signerurl.Validate(endpoint)
}

func fetchStatsigMetaContent(ctx context.Context, baseURL, token string, lease *infraegress.Lease) (string, error) {
	if lease == nil {
		return "", fmt.Errorf("Statsig 获取缺少出口租约")
	}
	requestCtx, cancel := context.WithTimeout(infraegress.WithPhysicalCallStage(ctx, "statsig_meta"), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/index", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Pragma", "no-cache")
	request.Header.Set("Sec-Fetch-Dest", "document")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Upgrade-Insecure-Requests", "1")
	request.Header.Set("User-Agent", lease.UserAgent)
	request.Header.Set("Cookie", infraegress.BuildSSOCookie(token, lease.CFCookies))
	response, err := lease.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Grok index 返回 %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, statsigMetaBodyLimit+1))
	if err != nil {
		return "", err
	}
	if len(body) > statsigMetaBodyLimit {
		return "", fmt.Errorf("Grok index 超过安全上限")
	}
	content, err := extractStatsigMetaContent(body)
	if err != nil {
		return "", err
	}
	return content, nil
}

func extractStatsigMetaContent(body []byte) (string, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return "", fmt.Errorf("Grok index 缺少 grok-site-verification")
			}
			return "", tokenizer.Err()
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttrs := tokenizer.TagName()
			if !strings.EqualFold(string(name), "meta") || !hasAttrs {
				continue
			}
			metaName := ""
			content := ""
			for {
				key, value, more := tokenizer.TagAttr()
				switch strings.ToLower(string(key)) {
				case "name":
					metaName = normalizeStatsigMetaName(string(value))
				case "content":
					content = strings.TrimSpace(string(value))
				}
				if !more {
					break
				}
			}
			if metaName == "grok-site-verification" && content != "" {
				return content, nil
			}
		}
	}
}

func normalizeStatsigMetaName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer("‐", "-", "‑", "-", "‒", "-", "–", "-", "—", "-", "―", "-").Replace(value)
}

func validStatsigID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	return err == nil && len(decoded) == 70
}

func (a *Adapter) applySignedStatsig(ctx context.Context, request *http.Request, token string, lease *infraegress.Lease) {
	if request == nil {
		return
	}
	cfg := a.config()
	request.Header.Del("x-statsig-id")
	if cfg.StatsigMode == "manual" {
		if value := strings.TrimSpace(cfg.StatsigManualValue); validStatsigID(value) {
			request.Header.Set("x-statsig-id", value)
		}
		return
	}
	if a.statsig == nil {
		return
	}
	value, source, err := a.statsig.Sign(ctx, cfg.BaseURL, cfg.StatsigSignerURL, token, lease, request.Method, request.URL.String())
	if err == nil {
		request.Header.Set("x-statsig-id", value)
		if source == "refresh" {
			a.log().Info("web_statsig_refreshed", "method", request.Method, "path", request.URL.EscapedPath())
		} else if source == "stale" {
			a.log().Warn("web_statsig_refresh_failed_using_stale", "method", request.Method, "path", request.URL.EscapedPath())
		}
		return
	}
	a.log().Warn("web_statsig_fetch_failed", "method", request.Method, "path", request.URL.EscapedPath(), "error", err)
}

// WarmStatsig 只使用一个 Web 账号和一个出口租约预热共享签名，不会逐账号访问上游。
func (a *Adapter) WarmStatsig(ctx context.Context, credential account.Credential) (int, error) {
	cfg := a.config()
	if cfg.StatsigMode == "manual" {
		if !validStatsigID(strings.TrimSpace(cfg.StatsigManualValue)) {
			return 0, fmt.Errorf("手动 Statsig 配置无效")
		}
		return 0, nil
	}
	if a.statsig == nil {
		return 0, fmt.Errorf("Statsig 签名器未初始化")
	}
	token, err := a.cipher.Decrypt(credential.EncryptedAccessToken)
	if err != nil {
		return 0, err
	}
	lease, err := a.egress.AcquireCredential(ctx, domainegress.ScopeWeb, credential)
	if err != nil {
		return 0, err
	}
	defer lease.Release()
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	return a.statsig.Warm(ctx, cfg.BaseURL, cfg.StatsigSignerURL, token, lease, []statsigWarmTarget{
		{method: http.MethodPost, target: baseURL + "/rest/app-chat/conversations/new"},
		{method: http.MethodPost, target: baseURL + "/rest/rate-limits"},
		{method: http.MethodPost, target: baseURL + "/rest/media/post/create"},
	})
}

func (a *Adapter) invalidateSignedStatsig(method, target string) bool {
	cfg := a.config()
	if cfg.StatsigMode == "url" && a.statsig != nil {
		a.statsig.Invalidate(cfg.BaseURL, cfg.StatsigSignerURL, method, target)
		if parsed, err := url.Parse(target); err == nil {
			a.log().Info("web_statsig_invalidated", "method", method, "path", parsed.EscapedPath())
		}
		return true
	}
	return false
}
