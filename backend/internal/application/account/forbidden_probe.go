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
	"github.com/chenyme/grok2api/backend/internal/repository"
)

// ForbiddenProbeConfig 控制账号 403 真实探测与复核终态；默认关闭探测。
type ForbiddenProbeConfig struct {
	Enabled       bool
	Interval      time.Duration
	Concurrency   int
	BatchSize     int
	SkipSuspended bool
	// ReviewCooldown 每次 403 后的临时封禁时长（复核等待）。
	ReviewCooldown time.Duration
	// ReviewMaxHits 累计 403 达到该次数后执行终态动作。
	ReviewMaxHits int
	// ReviewFinalAction: disabled | reauthRequired | delete。
	ReviewFinalAction string
}

const (
	ForbiddenReviewFinalDisabled = "disabled"
	ForbiddenReviewFinalReauth   = "reauthRequired"
	ForbiddenReviewFinalDelete   = "delete"
)

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
	RunID     uint64                `json:"runId,string,omitempty"`
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
	runID     uint64
	state     string
	provider  string
	trigger   string
	completed int
	total     int
	result    *ForbiddenProbeResult
	errText   string
	createdAt time.Time
	updatedAt time.Time
	lastFlush time.Time
	cancel    context.CancelFunc
}

// forbiddenProbeItemObserver 在每个账号探测结束后回调，用于写明细。
type forbiddenProbeItemObserver func(accountID uint64, accountName, provider string, outcome forbiddenProbeOneResult)

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
	if value.ReviewCooldown < time.Hour {
		value.ReviewCooldown = accountdomain.ChatForbiddenCooldown
	}
	if value.ReviewCooldown > 168*time.Hour {
		value.ReviewCooldown = 168 * time.Hour
	}
	if value.ReviewMaxHits < 1 {
		value.ReviewMaxHits = 2
	}
	if value.ReviewMaxHits > 20 {
		value.ReviewMaxHits = 20
	}
	switch value.ReviewFinalAction {
	case ForbiddenReviewFinalDisabled, ForbiddenReviewFinalReauth, ForbiddenReviewFinalDelete:
	default:
		value.ReviewFinalAction = ForbiddenReviewFinalDisabled
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
				result, skipped, err := s.runScheduledForbiddenProbe(runCtx, cfg)
				cancel()
				if skipped {
					// 其他实例已持锁，本轮不写日志。
				} else if err != nil && ctx.Err() == nil {
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

func (s *Service) runScheduledForbiddenProbe(ctx context.Context, cfg ForbiddenProbeConfig) (result ForbiddenProbeResult, skipped bool, err error) {
	if s.refreshLock != nil {
		release, acquired, lockErr := s.refreshLock.Acquire(ctx, forbiddenProbeLockKey, forbiddenProbeLockTTL)
		if lockErr != nil {
			return ForbiddenProbeResult{}, false, lockErr
		}
		if !acquired {
			return ForbiddenProbeResult{}, true, nil
		}
		defer release()
	}
	startedAt := s.now()
	runID := s.createForbiddenProbeRun(context.Background(), accountdomain.ForbiddenProbeRun{
		Trigger: accountdomain.ForbiddenProbeTriggerScheduled,
		State:   accountdomain.ForbiddenProbeStateRunning,
		StartedAt: startedAt, CreatedAt: startedAt, UpdatedAt: startedAt,
	})
	progress, onItem := s.probeLogObservers(runID)
	result, err = s.ProbeAllForbiddenWithProgressAndItems(ctx, "", cfg, progress, onItem)
	finishedAt := s.now()
	state := accountdomain.ForbiddenProbeStateCompleted
	errText := ""
	if err != nil {
		if errors.Is(err, context.Canceled) {
			state = accountdomain.ForbiddenProbeStateCanceled
		} else {
			state = accountdomain.ForbiddenProbeStateFailed
			errText = err.Error()
		}
	}
	s.finalizeForbiddenProbeRun(context.Background(), runID, state, result, errText, finishedAt)
	return result, false, err
}

// ProbeForbidden 对指定账号发起真实聊天探测并按结果标记 403 状态。
func (s *Service) ProbeForbidden(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	return s.ProbeForbiddenWithProgress(ctx, ids, providerFilter, cfg, nil)
}

// ProbeForbiddenWithProgress 同 ProbeForbidden，并在每个账号完成后回调 progress(completed, total)。
func (s *Service) ProbeForbiddenWithProgress(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver) (ForbiddenProbeResult, error) {
	return s.ProbeForbiddenWithProgressAndItems(ctx, ids, providerFilter, cfg, progress, nil)
}

// ProbeForbiddenWithProgressAndItems 同 ProbeForbidden，并报告进度与单账号结果。
func (s *Service) ProbeForbiddenWithProgressAndItems(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver, onItem forbiddenProbeItemObserver) (ForbiddenProbeResult, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return ForbiddenProbeResult{}, err
	}
	return s.probeForbiddenIDs(ctx, values, providerFilter, cfg, progress, onItem)
}

// ProbeAllForbidden 探测某 Provider（空则全部）下启用的账号。
func (s *Service) ProbeAllForbidden(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig) (ForbiddenProbeResult, error) {
	return s.ProbeAllForbiddenWithProgress(ctx, providerFilter, cfg, nil)
}

// ProbeAllForbiddenWithProgress 同 ProbeAllForbidden，并报告进度。
func (s *Service) ProbeAllForbiddenWithProgress(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver) (ForbiddenProbeResult, error) {
	return s.ProbeAllForbiddenWithProgressAndItems(ctx, providerFilter, cfg, progress, nil)
}

// ProbeAllForbiddenWithProgressAndItems 同 ProbeAllForbidden，并报告进度与单账号结果。
func (s *Service) ProbeAllForbiddenWithProgressAndItems(ctx context.Context, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver, onItem forbiddenProbeItemObserver) (ForbiddenProbeResult, error) {
	cfg = normalizeForbiddenProbeConfig(cfg)
	ids, err := s.listForbiddenProbeAccountIDs(ctx, providerFilter, cfg)
	if err != nil {
		return ForbiddenProbeResult{}, err
	}
	if len(ids) > cfg.BatchSize {
		ids = ids[:cfg.BatchSize]
	}
	return s.probeForbiddenIDs(ctx, ids, providerFilter, cfg, progress, onItem)
}

// StartForbiddenProbeJob 启动异步全量探测，立即返回任务 ID；后台执行，进度写入 403 日志。
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
	runID := s.createForbiddenProbeRun(context.Background(), accountdomain.ForbiddenProbeRun{
		JobID: jobID, Trigger: accountdomain.ForbiddenProbeTriggerManualAll, Provider: providerFilter,
		State: accountdomain.ForbiddenProbeStateRunning, StartedAt: now, CreatedAt: now, UpdatedAt: now,
	})
	runCtx, cancel := context.WithTimeout(context.Background(), forbiddenProbeRunTimeout)
	job := &forbiddenProbeJob{
		id: jobID, runID: runID, state: "queued", provider: providerFilter,
		trigger: accountdomain.ForbiddenProbeTriggerManualAll,
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
	runID := s.createForbiddenProbeRun(context.Background(), accountdomain.ForbiddenProbeRun{
		JobID: jobID, Trigger: accountdomain.ForbiddenProbeTriggerManualBatch, Provider: providerFilter,
		State: accountdomain.ForbiddenProbeStateRunning, Total: len(values),
		StartedAt: now, CreatedAt: now, UpdatedAt: now,
	})
	runCtx, cancel := context.WithTimeout(context.Background(), forbiddenProbeRunTimeout)
	job := &forbiddenProbeJob{
		id: jobID, runID: runID, state: "queued", provider: providerFilter, total: len(values),
		trigger: accountdomain.ForbiddenProbeTriggerManualBatch,
		createdAt: now, updatedAt: now, cancel: cancel,
	}
	s.storeForbiddenProbeJob(job)
	go s.runForbiddenProbeJobForIDs(runCtx, job, values, providerFilter, cfg)
	return job.snapshot(), nil
}

// ListForbiddenProbeLogs 分页读取 403 检测运行日志。
func (s *Service) ListForbiddenProbeLogs(ctx context.Context, page, pageSize int, providerFilter, trigger, state, search string) ([]accountdomain.ForbiddenProbeRun, int64, int, int, error) {
	page, pageSize = repository.NormalizePage(page, pageSize, repository.DefaultPageSize)
	if s.forbiddenProbeLogs == nil {
		return []accountdomain.ForbiddenProbeRun{}, 0, page, pageSize, nil
	}
	if providerFilter != "" && !accountdomain.Provider(providerFilter).IsValid() {
		return nil, 0, page, pageSize, invalidInput("账号来源无效")
	}
	switch trigger {
	case "", accountdomain.ForbiddenProbeTriggerManualAll, accountdomain.ForbiddenProbeTriggerManualBatch, accountdomain.ForbiddenProbeTriggerScheduled:
	default:
		return nil, 0, page, pageSize, invalidInput("触发来源无效")
	}
	switch state {
	case "", accountdomain.ForbiddenProbeStateRunning, accountdomain.ForbiddenProbeStateCompleted, accountdomain.ForbiddenProbeStateFailed, accountdomain.ForbiddenProbeStateCanceled:
	default:
		return nil, 0, page, pageSize, invalidInput("任务状态无效")
	}
	items, total, err := s.forbiddenProbeLogs.List(ctx, repository.ForbiddenProbeLogListQuery{
		Page: repository.PageQuery{
			Offset: (page - 1) * pageSize,
			Limit:  pageSize,
			Search: strings.TrimSpace(search),
		},
		Provider: providerFilter,
		Trigger:  trigger,
		State:    state,
	})
	if err != nil {
		return nil, 0, page, pageSize, err
	}
	// 内存中的进行中任务进度覆盖 DB 快照（更实时）。
	for i := range items {
		if items[i].State != accountdomain.ForbiddenProbeStateRunning || items[i].JobID == "" {
			continue
		}
		if live, liveErr := s.GetForbiddenProbeJob(items[i].JobID); liveErr == nil {
			items[i].Completed = live.Completed
			items[i].Total = live.Total
			items[i].UpdatedAt = live.UpdatedAt
		}
	}
	return items, total, page, pageSize, nil
}

// GetForbiddenProbeLog 读取单条运行日志。
func (s *Service) GetForbiddenProbeLog(ctx context.Context, id uint64) (accountdomain.ForbiddenProbeRun, error) {
	if s.forbiddenProbeLogs == nil {
		return accountdomain.ForbiddenProbeRun{}, ErrForbiddenProbeJobNotFound
	}
	run, err := s.forbiddenProbeLogs.Get(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return accountdomain.ForbiddenProbeRun{}, ErrForbiddenProbeJobNotFound
		}
		return accountdomain.ForbiddenProbeRun{}, err
	}
	if run.State == accountdomain.ForbiddenProbeStateRunning && run.JobID != "" {
		if live, liveErr := s.GetForbiddenProbeJob(run.JobID); liveErr == nil {
			run.Completed = live.Completed
			run.Total = live.Total
			run.UpdatedAt = live.UpdatedAt
		}
	}
	return run, nil
}

// ListForbiddenProbeLogItems 分页读取某次运行的账号明细。
func (s *Service) ListForbiddenProbeLogItems(ctx context.Context, runID uint64, page, pageSize int, search string) ([]accountdomain.ForbiddenProbeRunItem, int64, int, int, error) {
	page, pageSize = repository.NormalizePage(page, pageSize, repository.DefaultPageSize)
	if s.forbiddenProbeLogs == nil {
		return []accountdomain.ForbiddenProbeRunItem{}, 0, page, pageSize, nil
	}
	if runID == 0 {
		return nil, 0, page, pageSize, invalidInput("运行 ID 无效")
	}
	if _, err := s.forbiddenProbeLogs.Get(ctx, runID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, 0, page, pageSize, ErrForbiddenProbeJobNotFound
		}
		return nil, 0, page, pageSize, err
	}
	items, total, err := s.forbiddenProbeLogs.ListItems(ctx, runID, repository.PageQuery{
		Offset: (page - 1) * pageSize,
		Limit:  pageSize,
		Search: strings.TrimSpace(search),
	})
	if err != nil {
		return nil, 0, page, pageSize, err
	}
	return items, total, page, pageSize, nil
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

// CancelForbiddenProbeRun 按日志 runID 取消对应任务（若仍在内存中）。
func (s *Service) CancelForbiddenProbeRun(ctx context.Context, runID uint64) (accountdomain.ForbiddenProbeRun, error) {
	run, err := s.GetForbiddenProbeLog(ctx, runID)
	if err != nil {
		return accountdomain.ForbiddenProbeRun{}, err
	}
	if run.State != accountdomain.ForbiddenProbeStateRunning {
		return run, nil
	}
	if run.JobID != "" {
		if _, cancelErr := s.CancelForbiddenProbeJob(run.JobID); cancelErr == nil {
			// 内存任务会在 finish 时落库；此处先标 running→canceled 便于 UI。
			finished := s.now()
			s.finalizeForbiddenProbeRun(ctx, run.ID, accountdomain.ForbiddenProbeStateCanceled, ForbiddenProbeResult{
				Total: run.Total, Probed: run.Probed, OK: run.OK, Forbidden: run.Forbidden,
				Failed: run.Failed, Skipped: run.Skipped, Suspended: run.Suspended, Disabled: run.Disabled,
			}, "已取消", finished)
			return s.GetForbiddenProbeLog(ctx, runID)
		} else if !errors.Is(cancelErr, ErrForbiddenProbeJobNotFound) {
			return run, cancelErr
		}
	}
	// 进程已无内存任务，直接把日志标为 canceled。
	finished := s.now()
	s.finalizeForbiddenProbeRun(ctx, run.ID, accountdomain.ForbiddenProbeStateCanceled, ForbiddenProbeResult{
		Total: run.Total, Probed: run.Probed, OK: run.OK, Forbidden: run.Forbidden,
		Failed: run.Failed, Skipped: run.Skipped, Suspended: run.Suspended, Disabled: run.Disabled,
	}, "已取消", finished)
	return s.GetForbiddenProbeLog(ctx, runID)
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
	runID := job.runID
	job.mu.Unlock()

	progress, onItem := s.jobProgressObservers(job, runID)
	result, err := s.ProbeAllForbiddenWithProgressAndItems(ctx, providerFilter, cfg, progress, onItem)
	s.finishForbiddenProbeJob(job, result, err)
}

func (s *Service) runForbiddenProbeJobForIDs(ctx context.Context, job *forbiddenProbeJob, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig) {
	job.mu.Lock()
	job.state = "running"
	job.total = len(ids)
	job.updatedAt = s.now()
	runID := job.runID
	job.mu.Unlock()

	progress, onItem := s.jobProgressObservers(job, runID)
	result, err := s.ProbeForbiddenWithProgressAndItems(ctx, ids, providerFilter, cfg, progress, onItem)
	s.finishForbiddenProbeJob(job, result, err)
}

func (s *Service) jobProgressObservers(job *forbiddenProbeJob, runID uint64) (BatchProgressObserver, forbiddenProbeItemObserver) {
	logProgress, logItem := s.probeLogObservers(runID)
	progress := func(completed, total int) error {
		job.mu.Lock()
		if total > job.total {
			job.total = total
		}
		if completed > job.completed {
			job.completed = completed
		}
		job.updatedAt = s.now()
		job.mu.Unlock()
		if logProgress != nil {
			_ = logProgress(completed, total)
		}
		return nil
	}
	return progress, logItem
}

// probeLogObservers 写进度（节流）与账号明细到日志表。
func (s *Service) probeLogObservers(runID uint64) (BatchProgressObserver, forbiddenProbeItemObserver) {
	if s.forbiddenProbeLogs == nil || runID == 0 {
		return nil, nil
	}
	var mu sync.Mutex
	var lastFlush time.Time
	progress := func(completed, total int) error {
		mu.Lock()
		defer mu.Unlock()
		now := s.now()
		// 每 2s 或完成时刷一次进度，避免高频写库。
		if !lastFlush.IsZero() && now.Sub(lastFlush) < 2*time.Second && completed < total {
			return nil
		}
		lastFlush = now
		// 进度更新只改 completed/total，其它字段由 finalize 写入。
		_ = s.forbiddenProbeLogs.Update(context.Background(), accountdomain.ForbiddenProbeRun{
			ID: runID, State: accountdomain.ForbiddenProbeStateRunning,
			Total: total, Completed: completed, UpdatedAt: now,
		})
		return nil
	}
	onItem := func(accountID uint64, accountName, provider string, outcome forbiddenProbeOneResult) {
		item := accountdomain.ForbiddenProbeRunItem{
			RunID: runID, AccountID: accountID, AccountName: accountName, Provider: provider,
			Outcome: outcome.outcome, Suspended: outcome.suspended, Disabled: outcome.disabled,
			Detail: outcome.detail, CreatedAt: s.now(),
		}
		if _, err := s.forbiddenProbeLogs.CreateItem(context.Background(), item); err != nil {
			s.logger.Warn("account_forbidden_probe_item_log_failed", "error", err, "run_id", runID, "account_id", accountID)
		}
	}
	return progress, onItem
}

func (s *Service) finishForbiddenProbeJob(job *forbiddenProbeJob, result ForbiddenProbeResult, err error) {
	job.mu.Lock()
	finishedAt := s.now()
	job.updatedAt = finishedAt
	runID := job.runID
	state := accountdomain.ForbiddenProbeStateCompleted
	if job.state == "canceled" || errors.Is(err, context.Canceled) {
		job.state = "canceled"
		state = accountdomain.ForbiddenProbeStateCanceled
	} else if err != nil {
		job.state = "failed"
		job.errText = err.Error()
		state = accountdomain.ForbiddenProbeStateFailed
	} else {
		job.state = "completed"
	}
	copied := result
	job.result = &copied
	if result.Total > 0 {
		job.total = result.Total
		job.completed = result.Probed + result.Skipped
		if job.state == "completed" {
			job.completed = result.Total
		}
	}
	errText := job.errText
	job.mu.Unlock()
	s.finalizeForbiddenProbeRun(context.Background(), runID, state, result, errText, finishedAt)
}

func (s *Service) createForbiddenProbeRun(ctx context.Context, run accountdomain.ForbiddenProbeRun) uint64 {
	if s.forbiddenProbeLogs == nil {
		return 0
	}
	if run.State == "" {
		run.State = accountdomain.ForbiddenProbeStateRunning
	}
	created, err := s.forbiddenProbeLogs.Create(ctx, run)
	if err != nil {
		s.logger.Warn("account_forbidden_probe_log_create_failed", "error", err, "job_id", run.JobID)
		return 0
	}
	return created.ID
}

func (s *Service) finalizeForbiddenProbeRun(ctx context.Context, runID uint64, state string, result ForbiddenProbeResult, errText string, finishedAt time.Time) {
	if s.forbiddenProbeLogs == nil || runID == 0 {
		return
	}
	finished := finishedAt.UTC()
	run := accountdomain.ForbiddenProbeRun{
		ID: runID, State: state,
		Total: result.Total, Completed: result.Probed + result.Skipped,
		Probed: result.Probed, OK: result.OK, Forbidden: result.Forbidden, Failed: result.Failed,
		Skipped: result.Skipped, Suspended: result.Suspended, Disabled: result.Disabled,
		Error: errText, FinishedAt: &finished, UpdatedAt: finished,
	}
	if state == accountdomain.ForbiddenProbeStateCompleted {
		run.Completed = result.Total
	}
	// 保留启动时写入的 job/trigger/provider/started。
	if existing, err := s.forbiddenProbeLogs.Get(ctx, runID); err == nil {
		run.JobID = existing.JobID
		run.Trigger = existing.Trigger
		run.Provider = existing.Provider
		run.StartedAt = existing.StartedAt
		run.CreatedAt = existing.CreatedAt
		if run.Total == 0 {
			run.Total = existing.Total
		}
	}
	if err := s.forbiddenProbeLogs.Update(ctx, run); err != nil {
		s.logger.Warn("account_forbidden_probe_log_update_failed", "error", err, "run_id", runID, "state", state)
	}
}

func (j *forbiddenProbeJob) snapshot() ForbiddenProbeJobStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.snapshotLocked()
}

func (j *forbiddenProbeJob) snapshotLocked() ForbiddenProbeJobStatus {
	status := ForbiddenProbeJobStatus{
		ID: j.id, RunID: j.runID, State: j.state, Provider: j.provider,
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

type forbiddenProbeOneResult struct {
	accountID   uint64
	accountName string
	provider    string
	outcome     string
	ok          bool
	forbidden   bool
	failed      bool
	skipped     bool
	suspended   bool
	disabled    bool
	detail      string
}

func (s *Service) probeForbiddenIDs(ctx context.Context, ids []uint64, providerFilter string, cfg ForbiddenProbeConfig, progress BatchProgressObserver, onItem forbiddenProbeItemObserver) (ForbiddenProbeResult, error) {
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

	// 固定 worker 池 + 任务队列：每完成一个账号立刻上报进度。
	jobs := make(chan uint64)
	results := make(chan forbiddenProbeOneResult, concurrency*2)
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for accountID := range jobs {
				if ctx.Err() != nil {
					continue
				}
				one := s.probeOneForbidden(ctx, accountID, providerFilter, cfg)
				select {
				case results <- one:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, id := range ids {
			select {
			case <-ctx.Done():
				return
			case jobs <- id:
			}
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	finished := 0
	var progressErr error
	for item := range results {
		finished++
		if item.skipped {
			result.Skipped++
		} else {
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
		if onItem != nil {
			onItem(item.accountID, item.accountName, item.provider, item)
		}
		if progress != nil && progressErr == nil {
			if notifyErr := progress(finished, len(ids)); notifyErr != nil {
				progressErr = notifyErr
			}
		}
	}
	if progressErr != nil {
		return result, progressErr
	}
	if ctx.Err() != nil && finished < len(ids) {
		return result, ctx.Err()
	}
	return result, nil
}

func (s *Service) probeOneForbidden(ctx context.Context, id uint64, providerFilter string, cfg ForbiddenProbeConfig) (out forbiddenProbeOneResult) {
	out.accountID = id
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		out.failed = true
		out.outcome = accountdomain.ForbiddenProbeOutcomeFailed
		out.detail = err.Error()
		return out
	}
	out.accountName = value.Name
	out.provider = string(value.Provider)
	if providerFilter != "" && string(value.Provider) != providerFilter {
		out.skipped = true
		out.outcome = accountdomain.ForbiddenProbeOutcomeSkipped
		out.detail = "账号来源不匹配"
		return out
	}
	if !value.Enabled || value.AuthStatus != accountdomain.AuthStatusActive {
		out.skipped = true
		out.outcome = accountdomain.ForbiddenProbeOutcomeSkipped
		out.detail = "账号未启用或需重新授权"
		return out
	}
	now := s.now()
	if cfg.SkipSuspended && accountdomain.IsActiveChatForbiddenCooldown(value.LastError, value.CooldownUntil, now) {
		out.skipped = true
		out.outcome = accountdomain.ForbiddenProbeOutcomeSkipped
		out.detail = "仍在 403 临时封禁窗口"
		return out
	}
	status, body, probeErr := s.executeForbiddenProbe(ctx, value)
	if probeErr != nil {
		out.failed = true
		out.outcome = accountdomain.ForbiddenProbeOutcomeFailed
		out.detail = probeErr.Error()
		s.logger.Debug("account_forbidden_probe_transport_error", "account_id", id, "provider", value.Provider, "error", probeErr)
		return out
	}
	if status == http.StatusForbidden {
		out.forbidden = true
		out.outcome = accountdomain.ForbiddenProbeOutcomeForbidden
		detail := forbiddenProbeDetail(body)
		out.detail = detail
		permanent, handleErr := s.HandleChatForbidden(ctx, value, detail)
		if handleErr != nil {
			out.failed = true
			out.outcome = accountdomain.ForbiddenProbeOutcomeFailed
			out.detail = handleErr.Error()
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
		out.outcome = accountdomain.ForbiddenProbeOutcomeOK
		if accountdomain.IsChatForbiddenSuspend(value.LastError) || value.FailureCount > 0 || value.CooldownUntil != nil {
			_ = s.accounts.UpdateHealth(ctx, value.ID, 0, nil, "", true)
		}
		return out
	}
	out.failed = true
	out.outcome = accountdomain.ForbiddenProbeOutcomeFailed
	out.detail = fmt.Sprintf("上游返回 HTTP %d", status)
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
