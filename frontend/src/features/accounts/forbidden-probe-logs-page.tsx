import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ExternalLink, RefreshCw, Search, Square } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router-dom";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AccountProvider } from "@/features/accounts/accounts-api";
import {
  cancelForbiddenProbeRun,
  getForbiddenProbeLog,
  listForbiddenProbeLogItems,
  listForbiddenProbeLogs,
  type ForbiddenProbeLogDTO,
  type ForbiddenProbeLogItemDTO,
  type ForbiddenProbeLogOutcome,
  type ForbiddenProbeLogState,
  type ForbiddenProbeLogTrigger,
} from "@/features/accounts/forbidden-probe-logs-api";
import { EmptyState, ErrorState, TableLoadingRow } from "@/shared/components/data-state";
import { DataTableShell } from "@/shared/components/data-table-shell";
import { PageHeader } from "@/shared/components/page-header";
import { Pagination } from "@/shared/components/pagination";
import { useDebouncedValue } from "@/shared/hooks/use-debounced-value";
import { cn } from "@/shared/lib/cn";
import { formatDateTime, formatDuration, formatNumber } from "@/shared/lib/format";

const ALL = "__all__";

export function ForbiddenProbeLogsPage() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedRunId = searchParams.get("runId")?.trim() || "";

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [search, setSearch] = useState("");
  const [provider, setProvider] = useState<AccountProvider | "">("");
  const [trigger, setTrigger] = useState<ForbiddenProbeLogTrigger | "">("");
  const [state, setState] = useState<ForbiddenProbeLogState | "">("");
  const debouncedSearch = useDebouncedValue(search);

  const [itemPage, setItemPage] = useState(1);
  const [itemPageSize, setItemPageSize] = useState(20);
  const [itemSearch, setItemSearch] = useState("");
  const debouncedItemSearch = useDebouncedValue(itemSearch);
  const [outcomeFilter, setOutcomeFilter] = useState<ForbiddenProbeLogOutcome | "">("");

  const logsQuery = useQuery({
    queryKey: ["forbidden-probe-logs", page, pageSize, provider, trigger, state, debouncedSearch],
    queryFn: () => listForbiddenProbeLogs({
      page,
      pageSize,
      provider: provider || undefined,
      trigger: trigger || undefined,
      state: state || undefined,
      search: debouncedSearch || undefined,
    }),
    placeholderData: (previous) => previous,
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      return items.some((item) => item.state === "running") ? 2_000 : false;
    },
  });

  const detailQuery = useQuery({
    queryKey: ["forbidden-probe-log", selectedRunId],
    queryFn: () => getForbiddenProbeLog(selectedRunId),
    enabled: Boolean(selectedRunId),
    refetchInterval: (query) => (query.state.data?.state === "running" ? 2_000 : false),
  });

  const itemsQuery = useQuery({
    queryKey: ["forbidden-probe-log-items", selectedRunId, itemPage, itemPageSize, debouncedItemSearch],
    queryFn: () => listForbiddenProbeLogItems({
      runId: selectedRunId,
      page: itemPage,
      pageSize: itemPageSize,
      search: debouncedItemSearch || undefined,
    }),
    enabled: Boolean(selectedRunId),
    placeholderData: (previous) => previous,
    refetchInterval: () => (detailQuery.data?.state === "running" ? 2_000 : false),
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelForbiddenProbeRun(selectedRunId),
    onSuccess: () => {
      toast.success(t("forbiddenProbeLogs.canceled"));
      void queryClient.invalidateQueries({ queryKey: ["forbidden-probe-logs"] });
      void queryClient.invalidateQueries({ queryKey: ["forbidden-probe-log", selectedRunId] });
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : t("errors.generic"));
    },
  });

  useEffect(() => {
    setItemPage(1);
    setItemSearch("");
    setOutcomeFilter("");
  }, [selectedRunId]);

  const result = logsQuery.data;
  const items = result?.items ?? [];
  const total = result?.total ?? 0;
  const refreshing = logsQuery.isFetching;
  const detail = detailQuery.data;
  const rawItems = itemsQuery.data?.items ?? [];
  const filteredItems = useMemo(() => {
    if (!outcomeFilter) return rawItems;
    return rawItems.filter((item) => item.outcome === outcomeFilter);
  }, [rawItems, outcomeFilter]);

  function openRun(runId: string): void {
    setSearchParams({ runId });
  }

  function closeRun(): void {
    setSearchParams({});
  }

  function providerLabel(value?: string): string {
    if (!value) return t("forbiddenProbeLogs.allProviders");
    if (value === "grok_build") return "Grok Build";
    if (value === "grok_web") return "Grok Web";
    if (value === "grok_console") return "Grok Console";
    return value;
  }

  if (selectedRunId) {
    return (
      <div className="space-y-5">
        <PageHeader
          title={t("forbiddenProbeLogs.detailTitle")}
          description={t("forbiddenProbeLogs.detailDescription")}
          actions={(
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="secondary" size="sm" onClick={closeRun}>
                <ChevronLeft />
                {t("forbiddenProbeLogs.backToList")}
              </Button>
              {detail?.state === "running" ? (
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={cancelMutation.isPending}
                  onClick={() => cancelMutation.mutate()}
                >
                  {cancelMutation.isPending ? <Spinner /> : <Square className="size-3.5" />}
                  {t("forbiddenProbeLogs.cancelRun")}
                </Button>
              ) : null}
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  void detailQuery.refetch();
                  void itemsQuery.refetch();
                }}
                disabled={detailQuery.isFetching || itemsQuery.isFetching}
              >
                <RefreshCw className={detailQuery.isFetching || itemsQuery.isFetching ? "animate-spin" : undefined} />
                {t("common.refresh")}
              </Button>
            </div>
          )}
        />

        {detailQuery.isPending && !detail ? (
          <div className="flex min-h-40 items-center justify-center"><Spinner /></div>
        ) : detailQuery.isError ? (
          <ErrorState
            message={detailQuery.error instanceof Error ? detailQuery.error.message : t("errors.generic")}
            onRetry={() => void detailQuery.refetch()}
          />
        ) : detail ? (
          <>
            <RunSummaryCard run={detail} locale={i18n.language} providerLabel={providerLabel(detail.provider)} />
            <DataTableShell
              toolbar={(
                <div className="flex w-full flex-wrap items-center gap-2">
                  <div className="relative min-w-[220px] flex-1">
                    <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      className="pl-9"
                      value={itemSearch}
                      onChange={(event) => {
                        setItemPage(1);
                        setItemSearch(event.target.value);
                      }}
                      placeholder={t("forbiddenProbeLogs.itemSearch")}
                    />
                  </div>
                  <Select
                    value={outcomeFilter || ALL}
                    onValueChange={(value) => setOutcomeFilter(value === ALL ? "" : value as ForbiddenProbeLogOutcome)}
                  >
                    <SelectTrigger className="w-[140px]"><SelectValue placeholder={t("forbiddenProbeLogs.outcome")} /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>{t("common.all")}</SelectItem>
                      <SelectItem value="ok">{t("forbiddenProbeLogs.outcomeOk")}</SelectItem>
                      <SelectItem value="forbidden">{t("forbiddenProbeLogs.outcomeForbidden")}</SelectItem>
                      <SelectItem value="failed">{t("forbiddenProbeLogs.outcomeFailed")}</SelectItem>
                      <SelectItem value="skipped">{t("forbiddenProbeLogs.outcomeSkipped")}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              footer={(itemsQuery.data?.total ?? 0) > 0 && !outcomeFilter ? (
                <Pagination
                  page={itemPage}
                  pageSize={itemPageSize}
                  total={itemsQuery.data?.total ?? 0}
                  onPageChange={setItemPage}
                  onPageSizeChange={(size) => {
                    setItemPage(1);
                    setItemPageSize(size);
                  }}
                />
              ) : null}
            >
              <div className="relative overflow-x-auto rounded-xl border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("forbiddenProbeLogs.account")}</TableHead>
                      <TableHead>{t("forbiddenProbeLogs.provider")}</TableHead>
                      <TableHead>{t("forbiddenProbeLogs.outcome")}</TableHead>
                      <TableHead>{t("forbiddenProbeLogs.detail")}</TableHead>
                      <TableHead>{t("forbiddenProbeLogs.itemTime")}</TableHead>
                      <TableHead className="w-[80px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {itemsQuery.isPending && !itemsQuery.data ? (
                      <TableLoadingRow colSpan={6} />
                    ) : itemsQuery.isError ? (
                      <TableRow>
                        <TableCell colSpan={6}>
                          <ErrorState
                            message={itemsQuery.error instanceof Error ? itemsQuery.error.message : t("errors.generic")}
                            onRetry={() => void itemsQuery.refetch()}
                          />
                        </TableCell>
                      </TableRow>
                    ) : filteredItems.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={6}>
                          <EmptyState message={t("forbiddenProbeLogs.itemsEmpty")} />
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredItems.map((item) => (
                        <ItemRow key={item.id} item={item} locale={i18n.language} />
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </DataTableShell>
          </>
        ) : null}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={t("forbiddenProbeLogs.title")}
        description={t("forbiddenProbeLogs.description")}
        actions={(
          <Button variant="secondary" size="sm" onClick={() => void logsQuery.refetch()} disabled={refreshing}>
            <RefreshCw className={refreshing ? "animate-spin" : undefined} />
            {t("common.refresh")}
          </Button>
        )}
      />

      <DataTableShell
        toolbar={(
          <div className="flex w-full flex-wrap items-center gap-2">
            <div className="relative min-w-[220px] flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="pl-9"
                value={search}
                onChange={(event) => {
                  setPage(1);
                  setSearch(event.target.value);
                }}
                placeholder={t("forbiddenProbeLogs.search")}
              />
            </div>
            <Select
              value={provider || ALL}
              onValueChange={(value) => {
                setPage(1);
                setProvider(value === ALL ? "" : value as AccountProvider);
              }}
            >
              <SelectTrigger className="w-[150px]"><SelectValue placeholder={t("forbiddenProbeLogs.provider")} /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>{t("common.all")}</SelectItem>
                <SelectItem value="grok_build">Grok Build</SelectItem>
                <SelectItem value="grok_web">Grok Web</SelectItem>
                <SelectItem value="grok_console">Grok Console</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={trigger || ALL}
              onValueChange={(value) => {
                setPage(1);
                setTrigger(value === ALL ? "" : value as ForbiddenProbeLogTrigger);
              }}
            >
              <SelectTrigger className="w-[150px]"><SelectValue placeholder={t("forbiddenProbeLogs.trigger")} /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>{t("common.all")}</SelectItem>
                <SelectItem value="manual_all">{t("forbiddenProbeLogs.triggerManualAll")}</SelectItem>
                <SelectItem value="manual_batch">{t("forbiddenProbeLogs.triggerManualBatch")}</SelectItem>
                <SelectItem value="scheduled">{t("forbiddenProbeLogs.triggerScheduled")}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={state || ALL}
              onValueChange={(value) => {
                setPage(1);
                setState(value === ALL ? "" : value as ForbiddenProbeLogState);
              }}
            >
              <SelectTrigger className="w-[130px]"><SelectValue placeholder={t("forbiddenProbeLogs.state")} /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>{t("common.all")}</SelectItem>
                <SelectItem value="running">{t("forbiddenProbeLogs.stateRunning")}</SelectItem>
                <SelectItem value="completed">{t("forbiddenProbeLogs.stateCompleted")}</SelectItem>
                <SelectItem value="failed">{t("forbiddenProbeLogs.stateFailed")}</SelectItem>
                <SelectItem value="canceled">{t("forbiddenProbeLogs.stateCanceled")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}
        footer={total > 0 ? (
          <Pagination
            page={page}
            pageSize={pageSize}
            total={total}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPage(1);
              setPageSize(size);
            }}
          />
        ) : null}
      >
        <div className="relative overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("forbiddenProbeLogs.startedAt")}</TableHead>
                <TableHead>{t("forbiddenProbeLogs.trigger")}</TableHead>
                <TableHead>{t("forbiddenProbeLogs.provider")}</TableHead>
                <TableHead>{t("forbiddenProbeLogs.state")}</TableHead>
                <TableHead className="text-right">{t("forbiddenProbeLogs.progress")}</TableHead>
                <TableHead className="text-right">{t("forbiddenProbeLogs.ok")}</TableHead>
                <TableHead className="text-right">{t("forbiddenProbeLogs.forbidden")}</TableHead>
                <TableHead className="text-right">{t("forbiddenProbeLogs.failed")}</TableHead>
                <TableHead className="text-right">{t("forbiddenProbeLogs.suspended")}</TableHead>
                <TableHead className="text-right">{t("forbiddenProbeLogs.disabled")}</TableHead>
                <TableHead>{t("forbiddenProbeLogs.duration")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logsQuery.isPending && !result ? (
                <TableLoadingRow colSpan={11} />
              ) : logsQuery.isError ? (
                <TableRow>
                  <TableCell colSpan={11}>
                    <ErrorState
                      message={logsQuery.error instanceof Error ? logsQuery.error.message : t("errors.generic")}
                      onRetry={() => void logsQuery.refetch()}
                    />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11}>
                    <EmptyState message={t("forbiddenProbeLogs.empty")} />
                  </TableCell>
                </TableRow>
              ) : (
                items.map((item) => (
                  <RunRow
                    key={item.id}
                    item={item}
                    locale={i18n.language}
                    providerLabel={providerLabel(item.provider)}
                    onOpen={() => openRun(item.id)}
                  />
                ))
              )}
            </TableBody>
          </Table>
          {logsQuery.isFetching && result ? (
            <div className="pointer-events-none absolute inset-x-0 top-0 flex justify-end p-3">
              <Spinner className="size-4" />
            </div>
          ) : null}
        </div>
      </DataTableShell>
    </div>
  );
}

function RunSummaryCard({
  run,
  locale,
  providerLabel,
}: {
  run: ForbiddenProbeLogDTO;
  locale: string;
  providerLabel: string;
}) {
  const { t } = useTranslation();
  const progressText = run.total > 0
    ? `${formatNumber(run.completed, locale, 0)} / ${formatNumber(run.total, locale, 0)}`
    : formatNumber(run.completed, locale, 0);
  return (
    <div className="grid gap-3 rounded-xl border bg-card p-4 sm:grid-cols-2 lg:grid-cols-4">
      <SummaryItem label={t("forbiddenProbeLogs.state")} value={stateLabel(t, run.state)} />
      <SummaryItem label={t("forbiddenProbeLogs.provider")} value={providerLabel} />
      <SummaryItem label={t("forbiddenProbeLogs.progress")} value={progressText} />
      <SummaryItem label={t("forbiddenProbeLogs.duration")} value={formatDuration(run.durationMs)} />
      <SummaryItem label={t("forbiddenProbeLogs.ok")} value={formatNumber(run.ok, locale, 0)} />
      <SummaryItem label={t("forbiddenProbeLogs.forbidden")} value={formatNumber(run.forbidden, locale, 0)} />
      <SummaryItem label={t("forbiddenProbeLogs.failed")} value={formatNumber(run.failed, locale, 0)} />
      <SummaryItem label={t("forbiddenProbeLogs.skipped")} value={formatNumber(run.skipped, locale, 0)} />
      <SummaryItem label={t("forbiddenProbeLogs.suspended")} value={formatNumber(run.suspended, locale, 0)} />
      <SummaryItem label={t("forbiddenProbeLogs.disabled")} value={formatNumber(run.disabled, locale, 0)} />
      <SummaryItem label={t("forbiddenProbeLogs.startedAt")} value={formatDateTime(run.startedAt, locale)} />
      <SummaryItem label={t("forbiddenProbeLogs.trigger")} value={triggerLabel(t, run.trigger)} />
      {run.error ? (
        <div className="sm:col-span-2 lg:col-span-4">
          <div className="text-xs text-muted-foreground">{t("forbiddenProbeLogs.error")}</div>
          <div className="mt-1 text-sm text-red-600 dark:text-red-400">{run.error}</div>
        </div>
      ) : null}
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-medium tabular-nums">{value}</div>
    </div>
  );
}

function RunRow({
  item,
  locale,
  providerLabel,
  onOpen,
}: {
  item: ForbiddenProbeLogDTO;
  locale: string;
  providerLabel: string;
  onOpen: () => void;
}) {
  const { t } = useTranslation();
  const stateClass = item.state === "completed"
    ? "text-emerald-600 dark:text-emerald-400"
    : item.state === "failed"
      ? "text-red-600 dark:text-red-400"
      : item.state === "running"
        ? "text-sky-600 dark:text-sky-400"
        : "text-muted-foreground";
  const progress = item.total > 0
    ? `${formatNumber(item.completed, locale, 0)} / ${formatNumber(item.total, locale, 0)}`
    : formatNumber(item.completed, locale, 0);

  return (
    <TableRow className="cursor-pointer" onClick={onOpen}>
      <TableCell className="whitespace-nowrap align-top">
        <div className="font-medium">{formatDateTime(item.startedAt, locale)}</div>
        {item.error ? (
          <div className="mt-1 max-w-[240px] truncate text-xs text-red-600 dark:text-red-400" title={item.error}>
            {item.error}
          </div>
        ) : null}
      </TableCell>
      <TableCell className="align-top">{triggerLabel(t, item.trigger)}</TableCell>
      <TableCell className="align-top">{providerLabel}</TableCell>
      <TableCell className={cn("align-top font-medium", stateClass)}>
        {item.state === "running" ? (
          <span className="inline-flex items-center gap-1.5">
            <Spinner className="size-3.5" />
            {stateLabel(t, item.state)}
          </span>
        ) : stateLabel(t, item.state)}
      </TableCell>
      <TableCell className="text-right align-top tabular-nums">{progress}</TableCell>
      <TableCell className="text-right align-top tabular-nums">{formatNumber(item.ok, locale, 0)}</TableCell>
      <TableCell className="text-right align-top tabular-nums font-medium text-amber-700 dark:text-amber-400">
        {formatNumber(item.forbidden, locale, 0)}
      </TableCell>
      <TableCell className="text-right align-top tabular-nums">{formatNumber(item.failed, locale, 0)}</TableCell>
      <TableCell className="text-right align-top tabular-nums">{formatNumber(item.suspended, locale, 0)}</TableCell>
      <TableCell className="text-right align-top tabular-nums">{formatNumber(item.disabled, locale, 0)}</TableCell>
      <TableCell className="align-top whitespace-nowrap text-muted-foreground">{formatDuration(item.durationMs)}</TableCell>
    </TableRow>
  );
}

function ItemRow({ item, locale }: { item: ForbiddenProbeLogItemDTO; locale: string }) {
  const { t } = useTranslation();
  const outcomeClass = item.outcome === "ok"
    ? "text-emerald-600 dark:text-emerald-400"
    : item.outcome === "forbidden"
      ? "text-amber-700 dark:text-amber-400"
      : item.outcome === "failed"
        ? "text-red-600 dark:text-red-400"
        : "text-muted-foreground";
  const mark = item.disabled
    ? t("forbiddenProbeLogs.markDisabled")
    : item.suspended
      ? t("forbiddenProbeLogs.markSuspended")
      : "";

  return (
    <TableRow>
      <TableCell className="align-top">
        <div className="font-medium">{item.accountName || `#${item.accountId}`}</div>
        <div className="text-xs text-muted-foreground">#{item.accountId}</div>
      </TableCell>
      <TableCell className="align-top">{item.provider || "-"}</TableCell>
      <TableCell className={cn("align-top font-medium", outcomeClass)}>
        <div>{outcomeLabel(t, item.outcome)}</div>
        {mark ? <div className="mt-0.5 text-xs text-muted-foreground">{mark}</div> : null}
      </TableCell>
      <TableCell className="align-top max-w-[320px] truncate text-muted-foreground" title={item.detail}>
        {item.detail || "-"}
      </TableCell>
      <TableCell className="align-top whitespace-nowrap text-muted-foreground">
        {formatDateTime(item.createdAt, locale)}
      </TableCell>
      <TableCell className="align-top">
        <Button asChild variant="ghost" size="sm" className="h-8 px-2">
          <Link to={`/accounts?search=${encodeURIComponent(item.accountId)}`} title={t("forbiddenProbeLogs.openAccount")}>
            <ExternalLink className="size-3.5" />
          </Link>
        </Button>
      </TableCell>
    </TableRow>
  );
}

function triggerLabel(t: (key: string) => string, trigger: ForbiddenProbeLogTrigger): string {
  if (trigger === "manual_all") return t("forbiddenProbeLogs.triggerManualAll");
  if (trigger === "manual_batch") return t("forbiddenProbeLogs.triggerManualBatch");
  return t("forbiddenProbeLogs.triggerScheduled");
}

function stateLabel(t: (key: string) => string, state: ForbiddenProbeLogState): string {
  if (state === "running") return t("forbiddenProbeLogs.stateRunning");
  if (state === "completed") return t("forbiddenProbeLogs.stateCompleted");
  if (state === "failed") return t("forbiddenProbeLogs.stateFailed");
  return t("forbiddenProbeLogs.stateCanceled");
}

function outcomeLabel(t: (key: string) => string, outcome: ForbiddenProbeLogOutcome): string {
  if (outcome === "ok") return t("forbiddenProbeLogs.outcomeOk");
  if (outcome === "forbidden") return t("forbiddenProbeLogs.outcomeForbidden");
  if (outcome === "failed") return t("forbiddenProbeLogs.outcomeFailed");
  return t("forbiddenProbeLogs.outcomeSkipped");
}
