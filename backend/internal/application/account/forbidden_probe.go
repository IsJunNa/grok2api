package account

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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
	Total     int `json:"total"`
	Probed    int `json:"probed"`
	OK        int `json:"ok"`
	Forbidden int `json:"forbidden"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
	Suspended int `json:"suspended"`
	Disabled  int `json:"disabled"`
}

// ForbiddenProbeJobStatus 是异步 403 探测任务状态（短轮询，避免 Cloudflare 524）。
type ForbiddenProbeJobStatus struct {
	ID        string                `json:"id"`
	State     string                `json:"state"` // queued | running | completed | failed | canceled
	Provider  string                `json:"provider,omitempty"`
	Completed int                   `json:"completed"`
	Total     int                   `json:"total"`
	Result    *ForbiddenProbeResult `json:"result,omitempty"`
	Error     string                `json:"error,omitempty"`
	CreatedAt time.Time             `json:"createdAt"`
	UpdatedAt time.Time             `json:"updatedAt"`
}

type forbiddenProbeJob struct {
	mu        sync.Mutex
	id        string
	state     string
	provider  string
	completed int
	total     int
	result    *ForbiddenProbeResult
	errText   string
	createdAt time.Time
	updatedAt time.Time
	cancel    context.CancelFunc
}

const (
	forbiddenProbeLockKey    = "account-forbidden-probe"
	forbiddenProbeLockTTL    = 30 * time.Minute
	forbiddenProbeRunTimeout = 25 * time.Minute
	forbiddenProbeBodyLimit  = 64 << 10
	forbiddenProbeTimeout    = 45 * time.Second
	forbiddenProbeJobTTL     = 2 * time.Hour
	forbiddenProbeJobMax     = 32
)

var (
	ErrForbiddenProbeJobNotFound = errors.New("403 检测任务不存在或已过期")
	ErrForbiddenProbeBusy        = errors.New("已有 403 检测任务在运行，请稍后再试")
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
	return s.ProbeForbiddenWithProgress(ctx, ids, providerFilter, cfg, nil)
}

// ProbeForbiddenWithProgress 同 ProbeForbidden，并在每个账号完成后回调 progress(completed, total)。
func (s *Service) ProbeForbiddenWithProgress(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver) (ForbiddenProbeResult, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return ForbiddenProbeResult{}, err
	}
	return s.probeForbiddenIDs(ctx, values, providerFilter, cfg, progress)
}

// ProbeAllForbidden 探测某 Provider（空则全部）下启用的账号。
func (s *Service) ProbeAllForbidden(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	return s.ProbeAllForbiddenWithProgress(ctx, providerFilter, cfg, nil)
}

// ProbeAllForbiddenWithProgress 同 ProbeAllForbidden，并报告进度。
func (s *Service) ProbeAllForbiddenWithProgress(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver) (ForbiddenProbeResult, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	ids, err := s.listForbiddenProbeAccountIDs(ctx, providerFilter, cfg)
	if err != nil {
		return ForbiddenProbeResult{}, err
	}
	if len(ids) > cfg.BatchSize {
		ids = ids[:cfg.BatchSize]
	}
	return s.probeForbiddenIDs(ctx, ids, providerFilter, cfg, progress)
}

// StartForbiddenProbeJob 启动异步全量探测，立即返回任务 ID；客户端短轮询 GetForbiddenProbeJob。
// 这样不会被 Cloudflare 代理的 100s 连接超时（524）打断。
func (s *Service) StartForbiddenProbeJob(providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeJobStatus, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	cfg.Enabled = true
	if cfg.BatchSize < 1000 {
		cfg.BatchSize = 1000
	}
	if providerFilter != "" && !accountdomain.Provider(providerFilter).IsValid() {
		return ForbiddenProbeJobStatus{}, invalidInput("账号来源无效")
	}
	if s.hasActiveForbiddenProbeJob() {
		return ForbiddenProbeJobStatus{}, ErrForbiddenProbeBusy
	}
	jobID, err := newForbiddenProbeJobID()
	if err != nil {
		return ForbiddenProbeJobStatus{}, err
	}
	now := s.now()
	runCtx, cancel := context.WithTimeout(context.Background(), forbiddenProbeRunTimeout)
	job := &forbiddenProbeJob{
		id: jobID, state: "queued", provider: providerFilter,
		createdAt: now, updatedAt: now, cancel: cancel,
	}
	s.storeForbiddenProbeJob(job)
	go s.runForbiddenProbeJob(runCtx, job, providerFilter, cfg)
	return job.snapshot(), nil
}

// StartForbiddenProbeJobForIDs 启动指定账号的异步探测。
func (s *Service) StartForbiddenProbeJobForIDs(ids []uint64, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeJobStatus, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	cfg.Enabled = true
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return ForbiddenProbeJobStatus{}, err
	}
	if providerFilter != "" && !accountdomain.Provider(providerFilter).IsValid() {
		return ForbiddenProbeJobStatus{}, invalidInput("账号来源无效")
	}
	if s.hasActiveForbiddenProbeJob() {
		return ForbiddenProbeJobStatus{}, ErrForbiddenProbeBusy
	}
	jobID, err := newForbiddenProbeJobID()
	if err != nil {
		return ForbiddenProbeJobStatus{}, err
	}
	now := s.now()
	runCtx, cancel := context.WithTimeout(context.Background(), forbiddenProbeRunTimeout)
	job := &forbiddenProbeJob{
		id: jobID, state: "queued", provider: providerFilter, total: len(values),
		createdAt: now, updatedAt: now, cancel: cancel,
	}
	s.storeForbiddenProbeJob(job)
	go s.runForbiddenProbeJobForIDs(runCtx, job, values, providerFilter, cfg)
	return job.snapshot(), nil
}

// GetForbiddenProbeJob 返回异步任务进度快照。
func (s *Service) GetForbiddenProbeJob(id string) (ForbiddenProbeJobStatus, error) {
	id = strings.TrimSpace(id)
	s.forbiddenProbeJobsMu.Lock()
	defer s.forbiddenProbeJobsMu.Unlock()
	s.pruneForbiddenProbeJobsLocked(s.now())
	job, ok := s.forbiddenProbeJobs[id]
	if !ok {
		return ForbiddenProbeJobStatus{}, ErrForbiddenProbeJobNotFound
	}
	return job.snapshot(), nil
}

// CancelForbiddenProbeJob 取消仍在运行的任务。
func (s *Service) CancelForbiddenProbeJob(id string) (ForbiddenProbeJobStatus, error) {
	id = strings.TrimSpace(id)
	s.forbiddenProbeJobsMu.Lock()
	job, ok := s.forbiddenProbeJobs[id]
	s.forbiddenProbeJobsMu.Unlock()
	if !ok {
		return ForbiddenProbeJobStatus{}, ErrForbiddenProbeJobNotFound
	}
	job.mu.Lock()
	if job.state == "queued" || job.state == "running" {
		if job.cancel != nil {
			job.cancel()
		}
		job.state = "canceled"
		job.updatedAt = s.now()
	}
	snap := job.snapshotLocked()
	job.mu.Unlock()
	return snap, nil
}

func (s *Service) hasActiveForbiddenProbeJob() bool {
	s.forbiddenProbeJobsMu.Lock()
	defer s.forbiddenProbeJobsMu.Unlock()
	s.pruneForbiddenProbeJobsLocked(s.now())
	for _, job := range s.forbiddenProbeJobs {
		job.mu.Lock()
		active := job.state == "queued" || job.state == "running"
		job.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

func (s *Service) storeForbiddenProbeJob(job *forbiddenProbeJob) {
	s.forbiddenProbeJobsMu.Lock()
	defer s.forbiddenProbeJobsMu.Unlock()
	if s.forbiddenProbeJobs == nil {
		s.forbiddenProbeJobs = make(map[string]*forbiddenProbeJob)
	}
	s.pruneForbiddenProbeJobsLocked(s.now())
	s.forbiddenProbeJobs[job.id] = job
}

func (s *Service) pruneForbiddenProbeJobsLocked(now time.Time) {
	for id, job := range s.forbiddenProbeJobs {
		job.mu.Lock()
		expired := now.Sub(job.updatedAt) > forbiddenProbeJobTTL
		terminal := job.state == "completed" || job.state == "failed" || job.state == "canceled"
		job.mu.Unlock()
		if expired || (terminal && now.Sub(job.updatedAt) > 30*time.Minute) {
			delete(s.forbiddenProbeJobs, id)
		}
	}
	// 硬上限：只保留最近若干任务。
	for len(s.forbiddenProbeJobs) > forbiddenProbeJobMax {
		var oldestID string
		var oldest time.Time
		for id, job := range s.forbiddenProbeJobs {
			job.mu.Lock()
			updated := job.updatedAt
			job.mu.Unlock()
			if oldestID == "" || updated.Before(oldest) {
				oldestID, oldest = id, updated
			}
		}
		delete(s.forbiddenProbeJobs, oldestID)
	}
}

func (s *Service) runForbiddenProbeJob(ctx context.Context, job *forbiddenProbeJob, providerFilter string, cfg ForbiddenProbeConfig) {
	job.mu.Lock()
	job.state = "running"
	job.updatedAt = s.now()
	job.mu.Unlock()

	progress := func(completed, total int) error {
		job.mu.Lock()
		job.completed = completed
		job.total = total
		job.updatedAt = s.now()
		job.mu.Unlock()
		return ctx.Err()
	}
	result, err := s.ProbeAllForbiddenWithProgress(ctx, providerFilter, cfg, progress)
	job.mu.Lock()
	defer job.mu.Unlock()
	job.updatedAt = s.now()
	if job.state == "canceled" {
		return
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		job.state = "failed"
		job.errText = err.Error()
		// 仍附带部分结果，方便前端展示。
		copied := result
		job.result = &copied
		job.completed = result.Probed + result.Skipped
		if job.total == 0 {
			job.total = result.Total
		}
		return
	}
	if errors.Is(err, context.Canceled) {
		job.state = "canceled"
		copied := result
		job.result = &copied
		return
	}
	job.state = "completed"
	copied := result
	job.result = &copied
	job.completed = result.Total
	job.total = result.Total
}

func (s *Service) runForbiddenProbeJobForIDs(ctx context.Context, job *forbiddenProbeJob, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig) {
	job.mu.Lock()
	job.state = "running"
	job.total = len(ids)
	job.updatedAt = s.now()
	job.mu.Unlock()

	progress := func(completed, total int) error {
		job.mu.Lock()
		job.completed = completed
		job.total = total
		job.updatedAt = s.now()
		job.mu.Unlock()
		return ctx.Err()
	}
	result, err := s.ProbeForbiddenWithProgress(ctx, ids, providerFilter, cfg, progress)
	job.mu.Lock()
	defer job.mu.Unlock()
	job.updatedAt = s.now()
	if job.state == "canceled" {
		return
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		job.state = "failed"
		job.errText = err.Error()
		copied := result
		job.result = &copied
		return
	}
	if errors.Is(err, context.Canceled) {
		job.state = "canceled"
		copied := result
		job.result = &copied
		return
	}
	job.state = "completed"
	copied := result
	job.result = &copied
	job.completed = result.Total
	job.total = result.Total
}

func (j *forbiddenProbeJob) snapshot() ForbiddenProbeJobStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.snapshotLocked()
}

func (j *forbiddenProbeJob) snapshotLocked() ForbiddenProbeJobStatus {
	status := ForbiddenProbeJobStatus{
		ID: j.id, State: j.state, Provider: j.provider,
		Completed: j.completed, Total: j.total,
		Error: j.errText, CreatedAt: j.createdAt, UpdatedAt: j.updatedAt,
	}
	if j.result != nil {
		copied := *j.result
		status.Result = &copied
	}
	return status
}

func newForbiddenProbeJobID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
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

func (s *Service) probeForbiddenIDs(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver) (ForbiddenProbeResult, error) {
	result := ForbiddenProbeResult{Total: len(ids)}
	if len(ids) == 0 {
		if progress != nil {
			_ = progress(0, 0)
		}
		return result, nil
	}
	if s.providers == nil {
		return result, fmt.Errorf("Provider 注册表未初始化")
	}
	if progress != nil {
		if err := progress(0, len(ids)); err != nil {
			return result, err
		}
	}
	concurrency := cfg.Concurrency
	if concurrency > len(ids) {
		concurrency = len(ids)
	}
	type itemResult struct {
		done      bool
		skipped   bool
		ok        bool
		forbidden bool
		failed    bool
		suspended bool
		disabled  bool
	}
	results := make([]itemResult, len(ids))
	sem := make(chan struct{}, concurrency)
	done := make(chan int, len(ids))
	var started int
	for index, id := range ids {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		started++
		go func(i int, accountID uint64) {
			defer func() {
				<-sem
				done <- i
			}()
			one := s.probeOneForbidden(ctx, accountID, providerFilter, cfg)
			results[i] = itemResult{
				done: true, skipped: one.skipped, ok: one.ok, forbidden: one.forbidden,
				failed: one.failed, suspended: one.suspended, disabled: one.disabled,
			}
		}(index, id)
	}
	finished := 0
	var progressErr error
	for finished < started {
		select {
		case <-ctx.Done():
			for finished < started {
				<-done
				finished++
				if progress != nil && progressErr == nil {
					if notifyErr := progress(finished, len(ids)); notifyErr != nil {
						progressErr = notifyErr
					}
				}
			}
		case <-done:
			finished++
			if progress != nil && progressErr == nil {
				if notifyErr := progress(finished, len(ids)); notifyErr != nil {
					progressErr = notifyErr
				}
			}
		}
		if ctx.Err() != nil && finished >= started {
			break
		}
	}
	for _, item := range results {
		if !item.done {
			continue
		}
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
	if progressErr != nil {
		return result, progressErr
	}
	// 正常完成时忽略父 ctx 已取消（客户端断开）以外的统计错误；超时则返回错误。
	if ctx.Err() != nil && finished < len(ids) {
		return result, ctx.Err()
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
