import { memo, useEffect, useMemo, useRef } from 'react'

import type { LiveEventItem } from '@/store/events'
import { useEventsStore } from '@/store/events'

type AlertFeedProps = {
  alerts: LiveEventItem[]
  isLoading?: boolean
  connectionState?: 'idle' | 'connecting' | 'open' | 'closed' | 'error'
  onSelectEvent?: (eventId: string) => void
  selectedEventId?: string | null
  maxItems?: number
  compact?: boolean
  className?: string
}

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function formatTimestamp(value?: string | null) {
  if (!value) return 'Unknown time'

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

function formatRelative(value?: string | null) {
  if (!value) return 'unknown'
  const target = new Date(value).getTime()
  if (Number.isNaN(target)) return 'unknown'

  const diffMs = target - Date.now()
  const diffSeconds = Math.round(diffMs / 1000)
  const abs = Math.abs(diffSeconds)

  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

  if (abs < 60) return rtf.format(diffSeconds, 'second')
  if (abs < 3600) return rtf.format(Math.round(diffSeconds / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diffSeconds / 3600), 'hour')
  return rtf.format(Math.round(diffSeconds / 86400), 'day')
}

function severityClasses(severity?: string | null) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return {
        chip: 'border-rose-500/30 bg-rose-500/15 text-rose-200',
        dot: 'bg-rose-500 shadow-[0_0_16px_rgba(244,63,94,0.65)]',
        card: 'border-rose-500/20',
      }
    case 'HIGH':
      return {
        chip: 'border-orange-500/30 bg-orange-500/15 text-orange-200',
        dot: 'bg-orange-400 shadow-[0_0_16px_rgba(251,146,60,0.55)]',
        card: 'border-orange-500/20',
      }
    case 'MEDIUM':
      return {
        chip: 'border-amber-500/30 bg-amber-500/15 text-amber-200',
        dot: 'bg-amber-400 shadow-[0_0_14px_rgba(250,204,21,0.5)]',
        card: 'border-amber-500/20',
      }
    case 'LOW':
      return {
        chip: 'border-sky-500/30 bg-sky-500/15 text-sky-200',
        dot: 'bg-sky-400 shadow-[0_0_14px_rgba(56,189,248,0.45)]',
        card: 'border-sky-500/20',
      }
    default:
      return {
        chip: 'border-slate-700 bg-slate-800/80 text-slate-300',
        dot: 'bg-slate-500',
        card: 'border-slate-800',
      }
  }
}

function connectionBadgeClasses(
  state: 'idle' | 'connecting' | 'open' | 'closed' | 'error' = 'idle',
) {
  switch (state) {
    case 'open':
      return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
    case 'connecting':
      return 'border-amber-500/20 bg-amber-500/10 text-amber-300'
    case 'error':
      return 'border-rose-500/20 bg-rose-500/10 text-rose-300'
    case 'closed':
      return 'border-slate-700 bg-slate-800/80 text-slate-300'
    default:
      return 'border-slate-700 bg-slate-800/80 text-slate-400'
  }
}

function connectionLabel(
  state: 'idle' | 'connecting' | 'open' | 'closed' | 'error' = 'idle',
) {
  switch (state) {
    case 'open':
      return 'Live stream active'
    case 'connecting':
      return 'Connecting'
    case 'error':
      return 'Stream error'
    case 'closed':
      return 'Stream closed'
    default:
      return 'Idle'
  }
}

function compactValue(value?: string | number | null) {
  if (value === null || value === undefined || value === '') return '—'
  return String(value)
}

function topCves(cves?: string[]) {
  if (!Array.isArray(cves) || cves.length === 0) return []
  return cves.slice(0, 3)
}

function AlertFeedComponent({
  alerts,
  isLoading = false,
  connectionState = 'idle',
  onSelectEvent,
  selectedEventId = null,
  maxItems = 20,
  compact = false,
  className,
}: AlertFeedProps) {
  const clearFlash = useEventsStore((state) => state.clearFlash)
  const markAllSeen = useEventsStore((state) => state.markAllSeen)
  const timeoutRegistryRef = useRef<Record<string, number>>({})

  const visibleAlerts = useMemo(
    () => alerts.slice(0, Math.max(1, maxItems)),
    [alerts, maxItems],
  )

  useEffect(() => {
    markAllSeen()
  }, [markAllSeen])

  useEffect(() => {
    for (const alert of visibleAlerts) {
      if (!alert.flash || timeoutRegistryRef.current[alert.id]) {
        continue
      }

      timeoutRegistryRef.current[alert.id] = window.setTimeout(() => {
        clearFlash(alert.id)
        delete timeoutRegistryRef.current[alert.id]
      }, 4500)
    }

    return () => {
      for (const timer of Object.values(timeoutRegistryRef.current)) {
        window.clearTimeout(timer)
      }
      timeoutRegistryRef.current = {}
    }
  }, [visibleAlerts, clearFlash])

  return (
    <section
      className={cx(
        'rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg shadow-black/20',
        className,
      )}
    >
      <div className="flex flex-col gap-3 border-b border-slate-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
            Real-time monitoring
          </div>
          <h3 className="mt-1 text-lg font-semibold text-slate-50">
            Live Alert Feed
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            Streaming events from the ACCC event channel with enriched severity and threat context.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={cx(
              'rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.16em]',
              connectionBadgeClasses(connectionState),
            )}
          >
            {connectionLabel(connectionState)}
          </span>

          <span className="rounded-full border border-slate-700 bg-slate-800/80 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-300">
            {visibleAlerts.length} shown
          </span>
        </div>
      </div>

      <div className={cx(compact ? 'max-h-[420px]' : 'max-h-[720px]', 'overflow-y-auto')}>
        {isLoading && visibleAlerts.length === 0 ? (
          <div className="space-y-3 p-5">
            {Array.from({ length: compact ? 4 : 6 }).map((_, index) => (
              <div
                key={index}
                className="animate-pulse rounded-2xl border border-slate-800 bg-slate-950/50 p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="h-3 w-3 rounded-full bg-slate-800" />
                  <div className="h-4 w-28 rounded bg-slate-800" />
                  <div className="h-4 w-20 rounded bg-slate-800" />
                </div>
                <div className="mt-4 h-4 w-2/3 rounded bg-slate-800" />
                <div className="mt-2 h-3 w-1/2 rounded bg-slate-800" />
              </div>
            ))}
          </div>
        ) : visibleAlerts.length === 0 ? (
          <div className="p-8 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-800 bg-slate-950/70 text-slate-400">
              !
            </div>
            <h4 className="mt-4 text-base font-semibold text-slate-100">
              No alerts available
            </h4>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              When new events arrive through the live stream or event queries, they will appear here automatically.
            </p>
          </div>
        ) : (
          <div className="space-y-3 p-4">
            {visibleAlerts.map((alert) => {
              const severity = severityClasses(alert.severity)
              const isSelected = selectedEventId === alert.id
              const isEnrichmentUpdate = alert.update_type === 'enrichment_complete'
              const cves = topCves(alert.relevant_cves)

              return (
                <button
                  key={alert.id}
                  type="button"
                  onClick={() => onSelectEvent?.(alert.id)}
                  className={cx(
                    'w-full rounded-2xl border bg-slate-950/55 p-4 text-left transition',
                    'hover:border-slate-700 hover:bg-slate-950/80',
                    severity.card,
                    isSelected && 'ring-1 ring-cyan-400/40 border-cyan-500/30',
                    alert.flash && 'animate-[pulse_1.6s_ease-in-out_2]',
                  )}
                >
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={cx('h-2.5 w-2.5 rounded-full', severity.dot)} />
                        <span
                          className={cx(
                            'rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]',
                            severity.chip,
                          )}
                        >
                          {compactValue(alert.severity)}
                        </span>

                        {isEnrichmentUpdate && (
                          <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">
                            Enriched
                          </span>
                        )}

                        {alert.is_placeholder && (
                          <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                            Pending details
                          </span>
                        )}

                        {alert.triage_status && (
                          <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                            {alert.triage_status}
                          </span>
                        )}
                      </div>

                      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1">
                        <h4 className="text-base font-semibold text-slate-50">
                          {alert.event_type || 'Unknown event type'}
                        </h4>
                        <span className="text-sm text-slate-500">
                          {alert.source_identifier || 'unknown source'}
                        </span>
                      </div>

                      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-2 text-sm text-slate-400">
                        <span>
                          <span className="text-slate-500">Source IP:</span>{' '}
                          {compactValue(alert.src_ip)}
                        </span>
                        <span>
                          <span className="text-slate-500">User:</span>{' '}
                          {compactValue(alert.username)}
                        </span>
                        <span>
                          <span className="text-slate-500">Host:</span>{' '}
                          {compactValue(alert.hostname)}
                        </span>
                        <span>
                          <span className="text-slate-500">Geo:</span>{' '}
                          {alert.geo_city || alert.geo_country
                            ? `${alert.geo_city || 'Unknown city'}, ${alert.geo_country || 'Unknown country'}`
                            : '—'}
                        </span>
                      </div>

                      {!compact && (
                        <div className="mt-3 grid grid-cols-1 gap-2 text-sm text-slate-400 md:grid-cols-2 xl:grid-cols-4">
                          <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-3 py-2">
                            <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                              Severity score
                            </div>
                            <div className="mt-1 font-semibold text-slate-100">
                              {alert.severity_score ?? '—'}
                            </div>
                          </div>

                          <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-3 py-2">
                            <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                              Abuse score
                            </div>
                            <div className="mt-1 font-semibold text-slate-100">
                              {alert.abuse_score ?? '—'}
                            </div>
                          </div>

                          <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-3 py-2">
                            <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                              Destination
                            </div>
                            <div className="mt-1 font-semibold text-slate-100">
                              {alert.dst_ip
                                ? `${alert.dst_ip}${alert.dst_port ? `:${alert.dst_port}` : ''}`
                                : '—'}
                            </div>
                          </div>

                          <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-3 py-2">
                            <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                              Protocol
                            </div>
                            <div className="mt-1 font-semibold text-slate-100">
                              {compactValue(alert.protocol)}
                            </div>
                          </div>
                        </div>
                      )}

                      {cves.length > 0 && (
                        <div className="mt-3 flex flex-wrap items-center gap-2">
                          <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                            CVEs
                          </span>
                          {cves.map((cve) => (
                            <span
                              key={cve}
                              className="rounded-full border border-violet-500/20 bg-violet-500/10 px-2.5 py-1 text-[11px] font-semibold tracking-wide text-violet-200"
                            >
                              {cve}
                            </span>
                          ))}
                        </div>
                      )}

                      {alert.ai_triage_notes && !compact && (
                        <p className="mt-3 line-clamp-2 text-sm leading-6 text-slate-400">
                          {alert.ai_triage_notes}
                        </p>
                      )}
                    </div>

                    <div className="shrink-0 text-right">
                      <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                        Received
                      </div>
                      <div className="mt-1 text-sm font-medium text-slate-200">
                        {formatTimestamp(alert.received_at || alert.timestamp || alert.ingested_at)}
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        {formatRelative(alert.received_at || alert.timestamp || alert.ingested_at)}
                      </div>
                      <div className="mt-3 text-[11px] text-slate-500">
                        ID: <span className="font-mono text-slate-400">{alert.id.slice(0, 8)}</span>
                      </div>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </div>
    </section>
  )
}

const AlertFeed = memo(AlertFeedComponent)
export default AlertFeed