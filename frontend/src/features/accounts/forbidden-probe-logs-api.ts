import type { AccountProvider } from "@/features/accounts/accounts-api";
import { apiRequest, type PaginatedDTO } from "@/shared/api/client";
import { createObjectDecoder, createPaginatedDecoder, hasShape, isBoolean, isNumber, isOneOf, isOptional, isString } from "@/shared/api/decoder";

export type ForbiddenProbeLogTrigger = "manual_all" | "manual_batch" | "scheduled";
export type ForbiddenProbeLogState = "running" | "completed" | "failed" | "canceled";
export type ForbiddenProbeLogOutcome = "ok" | "forbidden" | "failed" | "skipped";

export type ForbiddenProbeLogDTO = {
  id: string;
  jobId?: string;
  trigger: ForbiddenProbeLogTrigger;
  provider?: AccountProvider | "";
  state: ForbiddenProbeLogState;
  total: number;
  completed: number;
  probed: number;
  ok: number;
  forbidden: number;
  failed: number;
  skipped: number;
  suspended: number;
  disabled: number;
  error?: string;
  startedAt: string;
  finishedAt?: string | null;
  createdAt: string;
  updatedAt: string;
  durationMs: number;
};

export type ForbiddenProbeLogItemDTO = {
  id: string;
  runId: string;
  accountId: string;
  accountName: string;
  provider?: string;
  outcome: ForbiddenProbeLogOutcome;
  suspended: boolean;
  disabled: boolean;
  detail?: string;
  createdAt: string;
};

export type ListForbiddenProbeLogsInput = {
  page: number;
  pageSize: number;
  provider?: AccountProvider | "";
  trigger?: ForbiddenProbeLogTrigger | "";
  state?: ForbiddenProbeLogState | "";
  search?: string;
};

export type ListForbiddenProbeLogItemsInput = {
  runId: string;
  page: number;
  pageSize: number;
  search?: string;
};

const forbiddenProbeLogShape = {
  id: isString,
  jobId: isOptional(isString),
  trigger: isOneOf("manual_all", "manual_batch", "scheduled"),
  provider: isOptional(isString),
  state: isOneOf("running", "completed", "failed", "canceled"),
  total: isNumber,
  completed: isNumber,
  probed: isNumber,
  ok: isNumber,
  forbidden: isNumber,
  failed: isNumber,
  skipped: isNumber,
  suspended: isNumber,
  disabled: isNumber,
  error: isOptional(isString),
  startedAt: isString,
  finishedAt: isOptional((value: unknown) => value === null || isString(value)),
  createdAt: isString,
  updatedAt: isString,
  durationMs: isNumber,
};

const forbiddenProbeLogItemShape = {
  id: isString,
  runId: isString,
  accountId: isString,
  accountName: isString,
  provider: isOptional(isString),
  outcome: isOneOf("ok", "forbidden", "failed", "skipped"),
  suspended: isBoolean,
  disabled: isBoolean,
  detail: isOptional(isString),
  createdAt: isString,
};

const decodeForbiddenProbeLog = createObjectDecoder<ForbiddenProbeLogDTO>("forbidden probe log", forbiddenProbeLogShape);
const decodeForbiddenProbeLogsPage = createPaginatedDecoder<ForbiddenProbeLogDTO>(hasShape(forbiddenProbeLogShape));
const decodeForbiddenProbeLogItemsPage = createPaginatedDecoder<ForbiddenProbeLogItemDTO>(hasShape(forbiddenProbeLogItemShape));

export function listForbiddenProbeLogs(input: ListForbiddenProbeLogsInput): Promise<PaginatedDTO<ForbiddenProbeLogDTO>> {
  const query = new URLSearchParams({
    page: String(input.page),
    pageSize: String(input.pageSize),
  });
  if (input.provider) query.set("provider", input.provider);
  if (input.trigger) query.set("trigger", input.trigger);
  if (input.state) query.set("state", input.state);
  if (input.search?.trim()) query.set("search", input.search.trim());
  return apiRequest(`/api/admin/v1/accounts/probe-forbidden/logs?${query}`, {}, decodeForbiddenProbeLogsPage);
}

export function getForbiddenProbeLog(runId: string): Promise<ForbiddenProbeLogDTO> {
  return apiRequest(`/api/admin/v1/accounts/probe-forbidden/logs/${encodeURIComponent(runId)}`, {}, decodeForbiddenProbeLog);
}

export function listForbiddenProbeLogItems(input: ListForbiddenProbeLogItemsInput): Promise<PaginatedDTO<ForbiddenProbeLogItemDTO>> {
  const query = new URLSearchParams({
    page: String(input.page),
    pageSize: String(input.pageSize),
  });
  if (input.search?.trim()) query.set("search", input.search.trim());
  return apiRequest(
    `/api/admin/v1/accounts/probe-forbidden/logs/${encodeURIComponent(input.runId)}/items?${query}`,
    {},
    decodeForbiddenProbeLogItemsPage,
  );
}

export function cancelForbiddenProbeRun(runId: string): Promise<ForbiddenProbeLogDTO> {
  return apiRequest(
    `/api/admin/v1/accounts/probe-forbidden/logs/${encodeURIComponent(runId)}/cancel`,
    { method: "POST" },
    decodeForbiddenProbeLog,
  );
}
