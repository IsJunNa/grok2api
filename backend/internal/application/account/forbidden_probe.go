package account

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/conversation"
)

// ForbiddenProbeConfig 控制账号 403 真实探测；默认关闭。
type ForbiddenProbeConfig struct {
	Enabled       bool
	Interval      time.Duration
	Concurrency   int
	BatchSize     int
	SkipSuspended bool
}

// ForbiddenProbeResult 是一次手动/自动探测的汇总。
type ForbiddenProbeResult struct {
	Total      int `json:"total"`
	Probed     int `json:"probed"`
	OK         int `json:"ok"`
	Forbidden  int `json:"forbidden"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
	Suspended  int `json:"suspended"`
	Disabled   int `json:"disabled"`
}

const (
	forbiddenProbeLockKey    = "account-forbidden-probe"
	forbiddenProbeLockTTL    = 30 * time.Minute
	forbiddenProbeRunTimeout = 25 * time.Minute
	forbiddenProbeBodyLimit  = 64 << 10
	forbiddenProbeTimeout    = 45 * time.Second
)

// UpdateForbiddenProbeConfig 热更新 403 探测策略；仅在实际变化时唤醒调度器。
func (s *Service) UpdateForbiddenProbeConfig(value ForbiddenProbeConfig) {
	value = normalizeForbiddenProbeConfig(value)
	s.forbiddenProbeMu.Lock()
	if s.forbiddenProbe == value {
		s.forbiddenProbeMu.Unlock()
		return
	}
	s.forbiddenProbe = value
	s.forbiddenProbeRevision++
	s.forbiddenProbeMu.Unlock()
	select {
	case s.forbiddenProbeWake <- struct{}{}:
	default:
	}
}

func normalizeForbiddenProbeConfig(value ForbiddenProbeConfig) ForbiddenProbeConfig {
	if value.Interval < time.Hour {
		value.Interval = time.Hour
	}
	if value.Interval > 24*time.Hour {
		value.Interval = 24 * time.Hour
	}
	if value.Concurrency < 1 {
		value.Concurrency = 1
	}
	if value.Concurrency > 20 {
		value.Concurrency = 20
	}
	if value.BatchSize < 10 {
		value.BatchSize = 10
	}
	if value.BatchSize > 1000 {
		value.BatchSize = 1000
	}
	return value
}

func (s *Service) forbiddenProbeSnapshot() (ForbiddenProbeConfig, uint64) {
	s.forbiddenProbeMu.RLock()
	defer s.forbiddenProbeMu.RUnlock()
	return s.forbiddenProbe, s.forbiddenProbeRevision
}

// ForbiddenProbeConfigSnapshot 返回当前热更新后的 403 探测配置（含手动检测可用的并发与跳过策略）。
func (s *Service) ForbiddenProbeConfigSnapshot() ForbiddenProbeConfig {
	cfg, _ := s.forbiddenProbeSnapshot()
	return normalizeForbiddenProbeConfig(cfg)
}

func forbiddenProbeInterval(cfg ForbiddenProbeConfig) time.Duration {
	if !cfg.Enabled {
		return time.Hour
	}
	return normalizeForbiddenProbeConfig(cfg).Interval
}

// RunForbiddenProbe 在启用时周期性对账号发起真实聊天探测。
func (s *Service) RunForbiddenProbe(ctx context.Context) {
	select {
	case <-s.forbiddenProbeWake:
	default:
	}
	cfg, scheduledRevision := s.forbiddenProbeSnapshot()
	timer := time.NewTimer(forbiddenProbeInterval(cfg))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.forbiddenProbeWake:
			cfg, scheduledRevision = s.forbiddenProbeSnapshot()
			resetTimer(timer, forbiddenProbeInterval(cfg))
		case <-timer.C:
			current, revision := s.forbiddenProbeSnapshot()
			if revision != scheduledRevision {
				cfg, scheduledRevision = current, revision
				resetTimer(timer, forbiddenProbeInterval(cfg))
				continue
			}
			cfg = current
			if cfg.Enabled {
				runCtx, cancel := context.WithTimeout(ctx, forbiddenProbeRunTimeout)
				result, err := s.runScheduledForbiddenProbe(runCtx, cfg)
				cancel()
				if err != nil && ctx.Err() == nil {
					s.logger.Warn("account_forbidden_probe_failed", "error", err)
				} else if err == nil {
					s.logger.Info("account_forbidden_probe_completed",
						"probed", result.Probed, "ok", result.OK, "forbidden", result.Forbidden,
						"failed", result.Failed, "skipped", result.Skipped, "suspended", result.Suspended, "disabled", result.Disabled)
				}
			}
			if latest, rev := s.forbiddenProbeSnapshot(); rev != scheduledRevision {
				cfg, scheduledRevision = latest, rev
			}
			resetTimer(timer, forbiddenProbeInterval(cfg))
		}
	}
}

func (s *Service) runScheduledForbiddenProbe(ctx context.Context, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	if s.refreshLock != nil {
		release, acquired, err := s.refreshLock.Acquire(ctx, forbiddenProbeLockKey, forbiddenProbeLockTTL)
		if err != nil {
			return ForbiddenProbeResult{}, err
		}
		if !acquired {
			return ForbiddenProbeResult{}, nil
		}
		defer release()
	}
	return s.ProbeAllForbidden(ctx, "", cfg)
}

// ProbeForbidden 对指定账号发起真实聊天探测并按结果标记 403 状态。
func (s *Service) ProbeForbidden(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return ForbiddenProbeResult{}, err
	}
	return s.probeForbiddenIDs(ctx, values, providerFilter, cfg)
}

// ProbeAllForbidden 探测某 Provider（空则全部）下启用的账号。
func (s *Service) ProbeAllForbidden(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	ids, err := s.listForbiddenProbeAccountIDs(ctx, providerFilter, cfg)
	if err != nil {
		return ForbiddenProbeResult{}, err
	}
	if len(ids) > cfg.BatchSize {
		ids = ids[:cfg.BatchSize]
	}
	return s.probeForbiddenIDs(ctx, ids, providerFilter, cfg)
}

func (s *Service) listForbiddenProbeAccountIDs(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig) ([]uint64, error) {
	providers := accountdomain.Providers()
	if providerFilter != "" {
		p := accountdomain.Provider(providerFilter)
		if !p.IsValid() {
			return nil, invalidInput("账号来源无效")
		}
		providers = []accountdomain.Provider{p}
	}
	out := make([]uint64, 0)
	now := s.now()
	for _, providerValue := range providers {
		providerIDs, err := s.accounts.ListEnabledAccountIDs(ctx, providerValue, false)
		if err != nil {
			return nil, err
		}
		for _, id := range providerIDs {
			if cfg.SkipSuspended {
				value, getErr := s.accounts.Get(ctx, id)
				if getErr != nil {
					return nil, getErr
				}
				if accountdomain.IsActiveChatForbiddenCooldown(value.LastError, value.CooldownUntil, now) {
					continue
				}
				if value.AuthStatus != accountdomain.AuthStatusActive {
					continue
				}
			}
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *Service) probeForbiddenIDs(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	result := ForbiddenProbeResult{Total: len(ids)}
	if len(ids) == 0 {
		return result, nil
	}
	if s.providers == nil {
		return result, fmt.Errorf("Provider 注册表未初始化")
	}
	concurrency := cfg.Concurrency
	if concurrency > len(ids) {
		concurrency = len(ids)
	}
	type itemResult struct {
		skipped   bool
		ok        bool
		forbidden bool
		failed    bool
		suspended bool
		disabled  bool
	}
	results := make([]itemResult, len(ids))
	sem := make(chan struct{}, concurrency)
	done := make(chan struct{})
	var running int
	for index, id := range ids {
		sem <- struct{}{}
		running++
		go func(i int, accountID uint64) {
			defer func() {
				<-sem
				done <- struct{}{}
			}()
			results[i] = s.probeOneForbidden(ctx, accountID, providerFilter, cfg)
		}(index, id)
	}
	for running > 0 {
		select {
		case <-ctx.Done():
			// 等待已启动的探测结束，避免泄漏；结果仍汇总。
			for running > 0 {
				<-done
				running--
			}
			return result, ctx.Err()
		case <-done:
			running--
		}
	}
	for _, item := range results {
		if item.skipped {
			result.Skipped++
			continue
		}
		result.Probed++
		if item.ok {
			result.OK++
		}
		if item.forbidden {
			result.Forbidden++
		}
		if item.failed {
			result.Failed++
		}
		if item.suspended {
			result.Suspended++
		}
		if item.disabled {
			result.Disabled++
		}
	}
	return result, nil
}

func (s *Service) probeOneForbidden(ctx context.Context, id uint64, providerFilter string, cfg ForbiddenProbeConfig) (out struct {
	skipped   bool
	ok        bool
	forbidden bool
	failed    bool
	suspended bool
	disabled  bool
}) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		out.failed = true
		return out
	}
	if providerFilter != "" && string(value.Provider) != providerFilter {
		out.skipped = true
		return out
	}
	if !value.Enabled || value.AuthStatus != accountdomain.AuthStatusActive {
		out.skipped = true
		return out
	}
	now := s.now()
	if cfg.SkipSuspended && accountdomain.IsActiveChatForbiddenCooldown(value.LastError, value.CooldownUntil, now) {
		out.skipped = true
		return out
	}
	status, body, probeErr := s.executeForbiddenProbe(ctx, value)
	if probeErr != nil {
		// 网络/超时不标记 403，计为失败。
		out.failed = true
		s.logger.Debug("account_forbidden_probe_transport_error", "account_id", id, "provider", value.Provider, "error", probeErr)
		return out
	}
	if status == http.StatusForbidden {
		out.forbidden = true
		permanent, handleErr := s.HandleChatForbidden(ctx, value, forbiddenProbeDetail(body))
		if handleErr != nil {
			out.failed = true
			s.logger.Warn("account_forbidden_probe_mark_failed", "account_id", id, "error", handleErr)
			return out
		}
		if permanent {
			out.disabled = true
		} else {
			out.suspended = true
		}
		return out
	}
	if status >= 200 && status < 300 {
		out.ok = true
		// 成功探测清掉 403 临时标记，与聊天成功路径一致。
		if accountdomain.IsChatForbiddenSuspend(value.LastError) || value.FailureCount > 0 || value.CooldownUntil != nil {
			_ = s.accounts.UpdateHealth(ctx, value.ID, 0, nil, "", true)
		}
		return out
	}
	// 401 等其它错误：不按 403 处理。
	out.failed = true
	s.logger.Debug("account_forbidden_probe_non_forbidden", "account_id", id, "provider", value.Provider, "status", status)
	return out
}

func forbiddenProbeDetail(body []byte) string {
	code, _, message := extractProbeErrorMetadata(body)
	detail := strings.TrimSpace(firstNonEmpty(code, message))
	if detail == "" {
		return "探测请求返回 403"
	}
	return detail
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func extractProbeErrorMetadata(body []byte) (code, errorType, message string) {
	if len(body) == 0 {
		return "", "", ""
	}
	var payload any
	if json.Unmarshal(body, &payload) != nil {
		return "", "", strings.TrimSpace(string(body))
	}
	root, ok := payload.(map[string]any)
	if !ok {
		return "", "", ""
	}
	if nested, ok := root["error"].(map[string]any); ok {
		return firstString(nested, "code", "error_code"), firstString(nested, "type", "error_type"), firstString(nested, "message", "error")
	}
	return firstString(root, "code", "error_code"), firstString(root, "type", "error_type"), firstString(root, "error", "message")
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if raw, ok := values[key]; ok {
			if text, ok := raw.(string); ok {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func (s *Service) executeForbiddenProbe(ctx context.Context, credential accountdomain.Credential) (int, []byte, error) {
	adapter, ok := s.providers.Responses(credential.Provider)
	if !ok {
		return 0, nil, fmt.Errorf("provider %s 不支持 Responses 探测", credential.Provider)
	}
	// 尽量使用可用凭据；Build 可强制刷新。
	ready := credential
	if s.providers.SupportsCredentialRefresh(credential.Provider) && credential.EncryptedRefreshToken != "" {
		if refreshed, err := s.ensureCredential(ctx, credential, false, true, false); err == nil {
			ready = refreshed
		}
	}
	model, err := s.probeModel(ctx, ready)
	if err != nil {
		return 0, nil, err
	}
	body, err := json.Marshal(map[string]any{
		"model": model,
		"input": "403 probe",
		"stream": false,
	})
	if err != nil {
		return 0, nil, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, forbiddenProbeTimeout)
	defer cancel()
	response, err := adapter.ForwardResponse(probeCtx, provider.ResponseResourceRequest{
		Credential:    ready,
		Method:        http.MethodPost,
		Path:          "/responses",
		Body:          body,
		Model:         model,
		Streaming:     false,
		NormalizeBody: true,
		Operation:     conversation.OperationResponses,
	})
	if err != nil {
		if status, ok := provider.ErrorHTTPStatus(err); ok {
			return status, nil, nil
		}
		return 0, nil, err
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, forbiddenProbeBodyLimit))
	if readErr != nil && len(payload) == 0 {
		return response.StatusCode, nil, readErr
	}
	// 丢弃剩余 body。
	_, _ = io.Copy(io.Discard, response.Body)
	_ = bytes.TrimSpace(payload)
	return response.StatusCode, payload, nil
}

func (s *Service) probeModel(ctx context.Context, credential accountdomain.Credential) (string, error) {
	if catalog, ok := s.providers.Models(credential.Provider); ok {
		models, err := catalog.ListModels(ctx, credential)
		if err == nil {
			for _, model := range models {
				if strings.TrimSpace(model) != "" {
					return model, nil
				}
			}
		}
	}
	switch credential.Provider {
	case accountdomain.ProviderWeb:
		return "grok-3", nil
	case accountdomain.ProviderConsole:
		return "grok-3", nil
	default:
		return "grok-4", nil
	}
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
