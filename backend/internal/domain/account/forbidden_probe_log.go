package account

import "time"

// ForbiddenProbeRun 记录一次 403 检测（手动或自动）的汇总结果。
// 任务启动时即落库（state=running），结束后更新汇总计数。
type ForbiddenProbeRun struct {
	ID         uint64
	JobID      string
	Trigger    string // manual_all | manual_batch | scheduled
	Provider   string
	State      string // running | completed | failed | canceled
	Total      int
	Completed  int
	Probed     int
	OK         int
	Forbidden  int
	Failed     int
	Skipped    int
	Suspended  int
	Disabled   int
	Error      string
	StartedAt  time.Time
	FinishedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ForbiddenProbeRunItem 是一次探测中单个账号的结果明细。
type ForbiddenProbeRunItem struct {
	ID          uint64
	RunID       uint64
	AccountID   uint64
	AccountName string
	Provider    string
	Outcome     string // ok | forbidden | failed | skipped
	Suspended   bool
	Disabled    bool
	Detail      string
	CreatedAt   time.Time
}

const (
	ForbiddenProbeTriggerManualAll   = "manual_all"
	ForbiddenProbeTriggerManualBatch = "manual_batch"
	ForbiddenProbeTriggerScheduled   = "scheduled"

	ForbiddenProbeStateRunning   = "running"
	ForbiddenProbeStateCompleted = "completed"
	ForbiddenProbeStateFailed    = "failed"
	ForbiddenProbeStateCanceled  = "canceled"

	ForbiddenProbeOutcomeOK        = "ok"
	ForbiddenProbeOutcomeForbidden = "forbidden"
	ForbiddenProbeOutcomeFailed    = "failed"
	ForbiddenProbeOutcomeSkipped   = "skipped"
)
