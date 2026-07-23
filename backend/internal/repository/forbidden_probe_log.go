package repository

import (
	"context"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
)

// ForbiddenProbeLogRepository 持久化 403 检测运行记录与账号明细。
type ForbiddenProbeLogRepository interface {
	Create(ctx context.Context, value account.ForbiddenProbeRun) (account.ForbiddenProbeRun, error)
	Update(ctx context.Context, value account.ForbiddenProbeRun) error
	Get(ctx context.Context, id uint64) (account.ForbiddenProbeRun, error)
	GetByJobID(ctx context.Context, jobID string) (account.ForbiddenProbeRun, error)
	List(ctx context.Context, query ForbiddenProbeLogListQuery) ([]account.ForbiddenProbeRun, int64, error)
	CreateItem(ctx context.Context, item account.ForbiddenProbeRunItem) (account.ForbiddenProbeRunItem, error)
	ListItems(ctx context.Context, runID uint64, query PageQuery) ([]account.ForbiddenProbeRunItem, int64, error)
}

// ForbiddenProbeLogListQuery 分页查询 403 检测日志。
type ForbiddenProbeLogListQuery struct {
	Page     PageQuery
	Provider string
	Trigger  string
	State    string
}
