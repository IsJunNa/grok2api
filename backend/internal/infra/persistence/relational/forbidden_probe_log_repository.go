package relational

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"gorm.io/gorm"
)

// ForbiddenProbeLogRepository 持久化 403 检测运行记录与账号明细。
type ForbiddenProbeLogRepository struct {
	db *Database
}

func NewForbiddenProbeLogRepository(db *Database) *ForbiddenProbeLogRepository {
	return &ForbiddenProbeLogRepository{db: db}
}

func (r *ForbiddenProbeLogRepository) Create(ctx context.Context, value account.ForbiddenProbeRun) (account.ForbiddenProbeRun, error) {
	model := forbiddenProbeRunFromDomain(value)
	now := time.Now().UTC()
	if model.CreatedAt.IsZero() {
		model.CreatedAt = now
	}
	if model.UpdatedAt.IsZero() {
		model.UpdatedAt = now
	}
	if model.StartedAt.IsZero() {
		model.StartedAt = now
	}
	if model.State == "" {
		model.State = account.ForbiddenProbeStateRunning
	}
	if err := r.db.db.WithContext(ctx).Create(&model).Error; err != nil {
		return account.ForbiddenProbeRun{}, err
	}
	return forbiddenProbeRunToDomain(model), nil
}

func (r *ForbiddenProbeLogRepository) Update(ctx context.Context, value account.ForbiddenProbeRun) error {
	if value.ID == 0 {
		return gorm.ErrRecordNotFound
	}
	now := time.Now().UTC()
	state := strings.TrimSpace(value.State)
	fields := map[string]any{
		"state":      state,
		"total":      value.Total,
		"completed":  value.Completed,
		"updated_at": now,
	}
	// 运行中的进度刷新只改 total/completed，避免把汇总计数刷成 0。
	if state != account.ForbiddenProbeStateRunning {
		fields["probed"] = value.Probed
		fields["ok"] = value.OK
		fields["forbidden"] = value.Forbidden
		fields["failed"] = value.Failed
		fields["skipped"] = value.Skipped
		fields["suspended"] = value.Suspended
		fields["disabled"] = value.Disabled
		fields["error_message"] = truncateProbeLogText(value.Error, 512)
		fields["provider"] = strings.TrimSpace(value.Provider)
		if jobID := strings.TrimSpace(value.JobID); jobID != "" {
			fields["job_id"] = jobID
		}
		if trigger := strings.TrimSpace(value.Trigger); trigger != "" {
			fields["run_trigger"] = trigger
		}
		if !value.StartedAt.IsZero() {
			fields["started_at"] = value.StartedAt.UTC()
		}
		if value.FinishedAt != nil {
			fields["finished_at"] = value.FinishedAt.UTC()
		}
	}
	result := r.db.db.WithContext(ctx).Model(&forbiddenProbeRunModel{}).Where("id = ?", value.ID).Updates(fields)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *ForbiddenProbeLogRepository) Get(ctx context.Context, id uint64) (account.ForbiddenProbeRun, error) {
	var model forbiddenProbeRunModel
	if err := r.db.db.WithContext(ctx).First(&model, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return account.ForbiddenProbeRun{}, repository.ErrNotFound
		}
		return account.ForbiddenProbeRun{}, err
	}
	return forbiddenProbeRunToDomain(model), nil
}

func (r *ForbiddenProbeLogRepository) GetByJobID(ctx context.Context, jobID string) (account.ForbiddenProbeRun, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return account.ForbiddenProbeRun{}, repository.ErrNotFound
	}
	var model forbiddenProbeRunModel
	if err := r.db.db.WithContext(ctx).Where("job_id = ?", jobID).Order("id DESC").First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return account.ForbiddenProbeRun{}, repository.ErrNotFound
		}
		return account.ForbiddenProbeRun{}, err
	}
	return forbiddenProbeRunToDomain(model), nil
}

func (r *ForbiddenProbeLogRepository) List(ctx context.Context, query repository.ForbiddenProbeLogListQuery) ([]account.ForbiddenProbeRun, int64, error) {
	limit := query.Page.Limit
	if limit < 1 {
		limit = repository.DefaultPageSize
	}
	if limit > repository.MaxPageSize {
		limit = repository.MaxPageSize
	}
	offset := query.Page.Offset
	if offset < 0 {
		offset = 0
	}
	db := r.db.db.WithContext(ctx).Model(&forbiddenProbeRunModel{})
	if provider := strings.TrimSpace(query.Provider); provider != "" {
		db = db.Where("provider = ?", provider)
	}
	if trigger := strings.TrimSpace(query.Trigger); trigger != "" {
		db = db.Where("run_trigger = ?", trigger)
	}
	if state := strings.TrimSpace(query.State); state != "" {
		db = db.Where("state = ?", state)
	}
	if search := strings.TrimSpace(query.Page.Search); search != "" {
		pattern := "%" + strings.ToLower(search) + "%"
		db = db.Where("LOWER(job_id) LIKE ? OR LOWER(error_message) LIKE ?", pattern, pattern)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []forbiddenProbeRunModel
	if err := db.Order("created_at DESC, id DESC").Offset(offset).Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]account.ForbiddenProbeRun, 0, len(rows))
	for _, row := range rows {
		out = append(out, forbiddenProbeRunToDomain(row))
	}
	return out, total, nil
}

func (r *ForbiddenProbeLogRepository) CreateItem(ctx context.Context, item account.ForbiddenProbeRunItem) (account.ForbiddenProbeRunItem, error) {
	model := forbiddenProbeRunItemFromDomain(item)
	if model.CreatedAt.IsZero() {
		model.CreatedAt = time.Now().UTC()
	}
	if err := r.db.db.WithContext(ctx).Create(&model).Error; err != nil {
		return account.ForbiddenProbeRunItem{}, err
	}
	return forbiddenProbeRunItemToDomain(model), nil
}

func (r *ForbiddenProbeLogRepository) ListItems(ctx context.Context, runID uint64, query repository.PageQuery) ([]account.ForbiddenProbeRunItem, int64, error) {
	if runID == 0 {
		return nil, 0, repository.ErrNotFound
	}
	limit := query.Limit
	if limit < 1 {
		limit = repository.DefaultPageSize
	}
	if limit > repository.MaxPageSize {
		limit = repository.MaxPageSize
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	db := r.db.db.WithContext(ctx).Model(&forbiddenProbeRunItemModel{}).Where("run_id = ?", runID)
	if search := strings.TrimSpace(query.Search); search != "" {
		pattern := "%" + strings.ToLower(search) + "%"
		db = db.Where("LOWER(account_name) LIKE ? OR LOWER(detail) LIKE ? OR CAST(account_id AS TEXT) LIKE ?", pattern, pattern, pattern)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []forbiddenProbeRunItemModel
	if err := db.Order("created_at DESC, id DESC").Offset(offset).Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]account.ForbiddenProbeRunItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, forbiddenProbeRunItemToDomain(row))
	}
	return out, total, nil
}

func forbiddenProbeRunFromDomain(value account.ForbiddenProbeRun) forbiddenProbeRunModel {
	return forbiddenProbeRunModel{
		ID:           value.ID,
		JobID:        strings.TrimSpace(value.JobID),
		RunTrigger:   strings.TrimSpace(value.Trigger),
		Provider:     strings.TrimSpace(value.Provider),
		State:        strings.TrimSpace(value.State),
		Total:        value.Total,
		Completed:    value.Completed,
		Probed:       value.Probed,
		OK:           value.OK,
		Forbidden:    value.Forbidden,
		Failed:       value.Failed,
		Skipped:      value.Skipped,
		Suspended:    value.Suspended,
		Disabled:     value.Disabled,
		ErrorMessage: truncateProbeLogText(value.Error, 512),
		StartedAt:    value.StartedAt.UTC(),
		FinishedAt:   cloneTimePtr(value.FinishedAt),
		CreatedAt:    value.CreatedAt.UTC(),
		UpdatedAt:    value.UpdatedAt.UTC(),
	}
}

func forbiddenProbeRunToDomain(value forbiddenProbeRunModel) account.ForbiddenProbeRun {
	return account.ForbiddenProbeRun{
		ID:         value.ID,
		JobID:      value.JobID,
		Trigger:    value.RunTrigger,
		Provider:   value.Provider,
		State:      value.State,
		Total:      value.Total,
		Completed:  value.Completed,
		Probed:     value.Probed,
		OK:         value.OK,
		Forbidden:  value.Forbidden,
		Failed:     value.Failed,
		Skipped:    value.Skipped,
		Suspended:  value.Suspended,
		Disabled:   value.Disabled,
		Error:      value.ErrorMessage,
		StartedAt:  value.StartedAt,
		FinishedAt: cloneTimePtr(value.FinishedAt),
		CreatedAt:  value.CreatedAt,
		UpdatedAt:  value.UpdatedAt,
	}
}

func forbiddenProbeRunItemFromDomain(value account.ForbiddenProbeRunItem) forbiddenProbeRunItemModel {
	return forbiddenProbeRunItemModel{
		ID:          value.ID,
		RunID:       value.RunID,
		AccountID:   value.AccountID,
		AccountName: truncateProbeLogText(value.AccountName, 160),
		Provider:    strings.TrimSpace(value.Provider),
		Outcome:     strings.TrimSpace(value.Outcome),
		Suspended:   value.Suspended,
		Disabled:    value.Disabled,
		Detail:      truncateProbeLogText(value.Detail, 512),
		CreatedAt:   value.CreatedAt.UTC(),
	}
}

func forbiddenProbeRunItemToDomain(value forbiddenProbeRunItemModel) account.ForbiddenProbeRunItem {
	return account.ForbiddenProbeRunItem{
		ID:          value.ID,
		RunID:       value.RunID,
		AccountID:   value.AccountID,
		AccountName: value.AccountName,
		Provider:    value.Provider,
		Outcome:     value.Outcome,
		Suspended:   value.Suspended,
		Disabled:    value.Disabled,
		Detail:      value.Detail,
		CreatedAt:   value.CreatedAt,
	}
}

func truncateProbeLogText(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.UTC()
	return &copied
}
