import { useMemo } from 'react'
import {
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import AlertFeed from '@/components/AlertFeed'
import GeoThreatMap from '@/components/GeoThreatMap'
import KpiCard from '@/components/dashboard/KpiCard'
import { useEvents } from '@/hooks/useEvents'
import { useAuth } from '@/hooks/useAuth'
import type { EventRecord } from '@/lib/api'

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function formatNumber(value: number | null | undefined) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '—'
  }

  return new Intl.NumberFormat().format(value)
}

function formatMinutes(value: number | null | undefined) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '—'
  }

  if (value < 1) {
    return '<1 min'
  }

  if (value >= 60) {
    const hours = Math.floor(value / 60)
    const minutes = Math.round(value % 60)
    return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`
  }

  return `${Math.round(value)} min`
}

function formatTimestamp(value?: string | null) {
  if (!value) return '—'
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

function formatChartBucket(value?: string | null) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function severityTone(
  severity?: string | null,
): 'default' | 'critical' | 'high' | 'warning' | 'success' | 'info' {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'high'
    case 'MEDIUM':
      return 'warning'
    case 'LOW':
      return 'info'
    default:
      return 'default'
  }
}

function severityColor(severity: string) {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return '#ef4444'
    case 'HIGH':
      return '#f97316'
    case 'MEDIUM':
      return '#facc15'
    case 'LOW':
      return '#38bdf8'
    case 'INFO':
      return '#94a3b8'
    default:
      return '#64748b'
  }
}

function eventTypeColor(index: number) {
  const palette = [
    '#22d3ee',
    '#38bdf8',
    '#818cf8',
    '#a78bfa',
    '#f472b6',
    '#fb7185',
    '#f97316',
    '#facc15',
    '#4ade80',
    '#2dd4bf',
  ]

  return palette[index % palette.length]
}

function topLocation(events: EventRecord[]) {
  const counts = new Map<string, number>()

  for (const event of events) {
    if (event.geo_lat == null || event.geo_lon == null) continue
    const key = `${event.geo_city || 'Unknown city'}, ${event.geo_country || 'Unknown country'}`
    counts.set(key, (counts.get(key) || 0) + 1)
  }

  let winner = 'No geo data'
  let winnerCount = 0

  for (const [key, count] of counts.entries()) {
    if (count > winnerCount) {
      winner = key
      winnerCount = count
    }
  }

  return {
    label: winner,
    count: winnerCount,
  }
}

function topEventType(events: EventRecord[]) {
  const counts = new Map<string, number>()

  for (const event of events) {
    const key = (event.event_type || 'unknown').trim() || 'unknown'
    counts.set(key, (counts.get(key) || 0) + 1)
  }

  let winner = 'unknown'
  let winnerCount = 0

  for (const [key, count] of counts.entries()) {
    if (count > winnerCount) {
      winner = key
      winnerCount = count
    }
  }

  return {
    label: winner,
    count: winnerCount,
  }
}

function EmptyPanel({
  title,
  message,
}: {
  title: string
  message: string
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 text-center">
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-800 bg-slate-950/70 text-slate-400">
        •
      </div>
      <h4 className="mt-4 text-base font-semibold text-slate-100">{title}</h4>
      <p className="mt-2 text-sm leading-6 text-slate-400">{message}</p>
    </div>
  )
}

function SectionFrame({
  title,
  eyebrow,
  description,
  children,
  actions,
  className,
}: {
  title: string
  eyebrow?: string
  description?: string
  children: React.ReactNode
  actions?: React.ReactNode
  className?: string
}) {
  return (
    <section
      className={cx(
        'rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg shadow-black/20',
        className,
      )}
    >
      <div className="flex flex-col gap-3 border-b border-slate-800 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          {eyebrow && (
            <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
              {eyebrow}
            </div>
          )}
          <h3 className="mt-1 text-lg font-semibold text-slate-50">{title}</h3>
          {description && (
            <p className="mt-1 text-sm leading-6 text-slate-400">
              {description}
            </p>
          )}
        </div>
        {actions && <div>{actions}</div>}
      </div>
      <div className="p-4">{children}</div>
    </section>
  )
}

export default function DashboardPage() {
  const auth = useAuth()

  const {
    filters,
    liveFeed,
    selectedEventId,
    connectionState,
    socketError,
    setSelectedEventId,
    setFilters,
    summaryQuery,
    statsQuery,
    geoEventsQuery,
    selectedEventQuery,
    kpis,
    baseline,
    anomalies,
    chartData,
    distributionData,
    geoEvents,
  } = useEvents()

  const summaryLoading = summaryQuery.isLoading
  const statsLoading = statsQuery.isLoading
  const geoLoading = geoEventsQuery.isLoading
  const selectedEvent = selectedEventQuery.data

  const chartSeries = useMemo(
    () =>
      (chartData || []).map((item) => ({
        ...item,
        label: formatChartBucket(item.bucket),
      })),
    [chartData],
  )

  const distributionSeries = useMemo(
    () =>
      (distributionData || [])
        .filter((item) => item.value > 0)
        .slice(0, 8)
        .map((item, index) => ({
          ...item,
          fill: eventTypeColor(index),
        })),
    [distributionData],
  )

  const mappedOrigins = useMemo(() => {
    const locations = new Set<string>()

    for (const event of geoEvents) {
      if (event.geo_lat == null || event.geo_lon == null) continue
      locations.add(`${event.geo_lat}:${event.geo_lon}`)
    }

    return locations.size
  }, [geoEvents])

  const locationLeader = useMemo(() => topLocation(geoEvents), [geoEvents])
  const eventTypeLeader = useMemo(() => topEventType(liveFeed), [liveFeed])

  const baselineSummary = baseline?.summary
  const currentUserLabel =
    auth.displayName || auth.username || 'Authenticated analyst'

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg shadow-black/20">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-4xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-cyan-300">
              <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 shadow-[0_0_14px_rgba(34,211,238,0.7)]" />
              Phase 4 · Real-time Dashboard
            </div>

            <h1 className="mt-4 text-3xl font-semibold tracking-tight text-slate-50">
              Welcome back, {currentUserLabel}
            </h1>

            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
              The ACCC dashboard is now using protected backend APIs for KPIs and charts, live
              WebSocket streaming for alert updates, geo-enriched event data for the threat map,
              and behavioral baseline output from the scheduled baseline engine.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:min-w-[420px]">
            <div className="rounded-2xl border border-slate-800 bg-slate-950/65 px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                Feed state
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-100">
                {connectionState.toUpperCase()}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/65 px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                Geo origins
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-100">
                {formatNumber(mappedOrigins)}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/65 px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                Top type
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-100">
                {eventTypeLeader.label}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/65 px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
                Baseline anomalies
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-100">
                {formatNumber(baselineSummary?.anomalies_detected ?? anomalies.length)}
              </div>
            </div>
          </div>
        </div>

        {socketError && (
          <div className="mt-5 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            Live event stream issue: {socketError}
          </div>
        )}
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          title="Total Events"
          value={kpis?.total_events ?? 0}
          subtitle="Events observed in the current dashboard window"
          helperText="Derived from /api/v1/dashboard/summary"
          badge="24h"
          tone="info"
          loading={summaryLoading}
        />

        <KpiCard
          title="Critical Alerts"
          value={kpis?.critical_events ?? 0}
          subtitle="Highest-priority events requiring immediate review"
          helperText="Critical severity count in current window"
          badge="P1"
          tone="critical"
          loading={summaryLoading}
        />

        <KpiCard
          title="Open Incidents"
          value={kpis?.open_incidents ?? 0}
          subtitle="Incidents still open or under investigation"
          helperText="Incident status metric from dashboard summary"
          badge="Casework"
          tone="warning"
          loading={summaryLoading}
        />

        <KpiCard
          title="Mean Time to Respond"
          value={formatMinutes(kpis?.mean_time_to_respond_minutes)}
          subtitle="Average response/resolution time from incident data"
          helperText="Calculated by backend dashboard summary"
          badge="MTTR"
          tone="success"
          loading={summaryLoading}
        />
      </section>

      <div className="grid gap-6 2xl:grid-cols-[1.6fr_1fr]">
        <SectionFrame
          eyebrow="Operational telemetry"
          title="Severity Trend"
          description="Hourly event volume by severity, sourced from the protected events statistics endpoint."
          actions={
            <div className="flex items-center gap-2">
              <label
                htmlFor="dashboard-time-range"
                className="text-xs font-medium uppercase tracking-[0.16em] text-slate-500"
              >
                Window
              </label>
              <select
                id="dashboard-time-range"
                value={filters.time_range}
                onChange={(event) => setFilters({ time_range: event.target.value })}
                className="rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/30"
              >
                <option value="60m">60m</option>
                <option value="6h">6h</option>
                <option value="12h">12h</option>
                <option value="24h">24h</option>
                <option value="7d">7d</option>
              </select>
            </div>
          }
        >
          {statsLoading && chartSeries.length === 0 ? (
            <div className="h-[320px] animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
          ) : chartSeries.length === 0 ? (
            <EmptyPanel
              title="No trend data available"
              message="Severity trend data will appear here once events exist in the selected dashboard time window."
            />
          ) : (
            <div className="h-[340px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    axisLine={{ stroke: '#334155' }}
                    tickLine={{ stroke: '#334155' }}
                  />
                  <YAxis
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    axisLine={{ stroke: '#334155' }}
                    tickLine={{ stroke: '#334155' }}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#020617',
                      border: '1px solid #1e293b',
                      borderRadius: 16,
                      color: '#e2e8f0',
                    }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                  <Legend wrapperStyle={{ color: '#cbd5e1' }} />
                  <Line type="monotone" dataKey="CRITICAL" stroke="#ef4444" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="HIGH" stroke="#f97316" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="MEDIUM" stroke="#facc15" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="LOW" stroke="#38bdf8" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="INFO" stroke="#94a3b8" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </SectionFrame>

        <SectionFrame
          eyebrow="Event composition"
          title="Event Type Distribution"
          description="Top event types in the active dashboard window."
        >
          {statsLoading && distributionSeries.length === 0 ? (
            <div className="h-[320px] animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
          ) : distributionSeries.length === 0 ? (
            <EmptyPanel
              title="No event distribution available"
              message="Once events are present, the top event-type distribution will render here."
            />
          ) : (
            <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
              <div className="h-[320px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#020617',
                        border: '1px solid #1e293b',
                        borderRadius: 16,
                        color: '#e2e8f0',
                      }}
                    />
                    <Pie
                      data={distributionSeries}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={70}
                      outerRadius={110}
                      paddingAngle={2}
                    >
                      {distributionSeries.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-2">
                {distributionSeries.map((item) => (
                  <div
                    key={item.name}
                    className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-950/55 px-4 py-3"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <span
                        className="h-3 w-3 rounded-full"
                        style={{ backgroundColor: item.fill }}
                      />
                      <span className="truncate text-sm text-slate-200">
                        {item.name}
                      </span>
                    </div>
                    <span className="text-sm font-semibold text-slate-100">
                      {formatNumber(item.value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </SectionFrame>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.25fr_0.95fr]">
        <AlertFeed
          alerts={liveFeed}
          isLoading={summaryLoading && liveFeed.length === 0}
          connectionState={connectionState}
          selectedEventId={selectedEventId}
          onSelectEvent={setSelectedEventId}
          maxItems={18}
          className="min-h-[560px]"
        />

        <SectionFrame
          eyebrow="Selected event"
          title="Event Investigation Panel"
          description="Click any live alert to inspect its full enriched event record and current triage context."
        >
          {!selectedEventId ? (
            <EmptyPanel
              title="No event selected"
              message="Select an alert from the live feed to inspect its geo context, CVEs, severity score, and triage status."
            />
          ) : selectedEventQuery.isLoading && !selectedEvent ? (
            <div className="space-y-3">
              <div className="h-16 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
              <div className="h-16 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
              <div className="h-44 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
            </div>
          ) : !selectedEvent ? (
            <EmptyPanel
              title="Event details unavailable"
              message="The selected event could not be loaded from the backend. Try selecting another alert."
            />
          ) : (
            <div className="space-y-4">
              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={cx(
                      'rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]',
                      severityTone(selectedEvent.severity) === 'critical'
                        ? 'border-rose-500/20 bg-rose-500/10 text-rose-200'
                        : severityTone(selectedEvent.severity) === 'high'
                        ? 'border-orange-500/20 bg-orange-500/10 text-orange-200'
                        : severityTone(selectedEvent.severity) === 'warning'
                        ? 'border-amber-500/20 bg-amber-500/10 text-amber-200'
                        : 'border-slate-700 bg-slate-800/80 text-slate-300',
                    )}
                  >
                    {selectedEvent.severity || 'UNKNOWN'}
                  </span>

                  {selectedEvent.triage_status && (
                    <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                      {selectedEvent.triage_status}
                    </span>
                  )}

                  {selectedEvent.is_false_positive && (
                    <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                      False positive
                    </span>
                  )}
                </div>

                <h4 className="mt-3 text-xl font-semibold text-slate-50">
                  {selectedEvent.event_type || 'Unknown event type'}
                </h4>

                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Source
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100">
                      {selectedEvent.src_ip || '—'}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Destination
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100">
                      {selectedEvent.dst_ip
                        ? `${selectedEvent.dst_ip}${selectedEvent.dst_port ? `:${selectedEvent.dst_port}` : ''}`
                        : '—'}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Geo
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100">
                      {selectedEvent.geo_city || selectedEvent.geo_country
                        ? `${selectedEvent.geo_city || 'Unknown city'}, ${selectedEvent.geo_country || 'Unknown country'}`
                        : '—'}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Severity score
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100">
                      {selectedEvent.severity_score ?? '—'}
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                  <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                    Abuse score
                  </div>
                  <div className="mt-2 text-lg font-semibold text-slate-100">
                    {selectedEvent.abuse_score ?? '—'}
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    Backend reputation enrichment result
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                  <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                    Event time
                  </div>
                  <div className="mt-2 text-sm font-semibold text-slate-100">
                    {formatTimestamp(selectedEvent.timestamp || selectedEvent.ingested_at)}
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    Event ID: <span className="font-mono">{selectedEvent.id}</span>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                  Relevant CVEs
                </div>

                {selectedEvent.relevant_cves && selectedEvent.relevant_cves.length > 0 ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {selectedEvent.relevant_cves.map((cve) => (
                      <span
                        key={cve}
                        className="rounded-full border border-violet-500/20 bg-violet-500/10 px-2.5 py-1 text-[11px] font-semibold tracking-wide text-violet-200"
                      >
                        {cve}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-sm text-slate-400">
                    No relevant CVEs attached to this event.
                  </p>
                )}
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                  AI triage notes
                </div>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-300">
                  {selectedEvent.ai_triage_notes || 'No AI triage notes available yet.'}
                </p>
              </div>
            </div>
          )}
        </SectionFrame>
      </div>

      <GeoThreatMap
        events={geoEvents}
        isLoading={geoLoading}
        className="min-h-[560px]"
      />

      <div className="grid gap-6 2xl:grid-cols-[1.1fr_0.9fr]">
        <SectionFrame
          eyebrow="Behavioral baseline engine"
          title="Baseline Snapshot"
          description="Redis-backed rolling baseline state rebuilt by the scheduled baseline refresh job."
          actions={
            <span className="rounded-full border border-slate-700 bg-slate-800/80 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300">
              Refreshed {baselineSummary?.refreshed_at ? formatTimestamp(baselineSummary.refreshed_at) : '—'}
            </span>
          }
        >
          {summaryLoading && !baseline ? (
            <div className="grid gap-3 md:grid-cols-2">
              <div className="h-24 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
              <div className="h-24 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
              <div className="h-24 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
              <div className="h-24 animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60" />
            </div>
          ) : (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 px-4 py-4">
                <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                  Entities processed
                </div>
                <div className="mt-2 text-2xl font-semibold text-slate-100">
                  {formatNumber(baselineSummary?.entities_processed ?? 0)}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 px-4 py-4">
                <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                  Anomalies detected
                </div>
                <div className="mt-2 text-2xl font-semibold text-slate-100">
                  {formatNumber(baselineSummary?.anomalies_detected ?? anomalies.length)}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 px-4 py-4">
                <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                  Events scanned
                </div>
                <div className="mt-2 text-2xl font-semibold text-slate-100">
                  {formatNumber(baselineSummary?.events_scanned ?? 0)}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 px-4 py-4">
                <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                  Rolling window
                </div>
                <div className="mt-2 text-2xl font-semibold text-slate-100">
                  {baselineSummary?.window_hours ?? 2}h
                </div>
              </div>
            </div>
          )}
        </SectionFrame>

        <SectionFrame
          eyebrow="Geo overview"
          title="Threat Geography Highlights"
          description="Quick summary derived from the current geo-filtered dashboard data set."
        >
          <div className="space-y-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
              <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                Top origin
              </div>
              <div className="mt-2 text-lg font-semibold text-slate-100">
                {locationLeader.label}
              </div>
              <div className="mt-1 text-sm text-slate-400">
                {locationLeader.count > 0
                  ? `${locationLeader.count} mapped event${locationLeader.count === 1 ? '' : 's'}`
                  : 'No mapped events yet'}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
              <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                Active geo events
              </div>
              <div className="mt-2 text-lg font-semibold text-slate-100">
                {formatNumber(geoEvents.length)}
              </div>
              <div className="mt-1 text-sm text-slate-400">
                Current geo-filtered event sample rendered on the map
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
              <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                Stream status
              </div>
              <div className="mt-2 text-lg font-semibold text-slate-100">
                {connectionState.toUpperCase()}
              </div>
              <div className="mt-1 text-sm text-slate-400">
                WebSocket channel for new alerts and enrichment updates
              </div>
            </div>
          </div>
        </SectionFrame>
      </div>

      <SectionFrame
        eyebrow="Anomaly review"
        title="Baseline Anomalies"
        description="Entities whose current activity materially exceeds their recent behavioral baseline."
      >
        {anomalies.length === 0 ? (
          <EmptyPanel
            title="No anomalies flagged"
            message="The baseline engine has not flagged any entities above the current threshold yet."
          />
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {anomalies.slice(0, 8).map((anomaly) => (
              <article
                key={`${anomaly.entity_type}:${anomaly.entity_value}`}
                className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-rose-500/20 bg-rose-500/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-rose-200">
                    Anomaly
                  </span>
                  <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-300">
                    {anomaly.entity_type}
                  </span>
                </div>

                <h4 className="mt-3 text-lg font-semibold text-slate-50">
                  {anomaly.entity_value}
                </h4>

                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Typically {anomaly.baseline_hourly_rate} events/hour — currently {anomaly.current_hourly_rate} events/hour (
                  {anomaly.anomaly_ratio}× baseline).
                </p>

                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Recent events
                    </div>
                    <div className="mt-1 text-sm font-semibold text-slate-100">
                      {formatNumber(anomaly.recent_events)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Total in window
                    </div>
                    <div className="mt-1 text-sm font-semibold text-slate-100">
                      {formatNumber(anomaly.total_events)}
                    </div>
                  </div>
                </div>

                {anomaly.common_event_types && anomaly.common_event_types.length > 0 && (
                  <div className="mt-4">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">
                      Common event types
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {anomaly.common_event_types.slice(0, 4).map((item) => (
                        <span
                          key={`${anomaly.entity_value}-${item.name}`}
                          className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-semibold text-cyan-200"
                        >
                          {item.name} · {item.count}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-4 text-xs text-slate-500">
                  Last seen: {formatTimestamp(anomaly.last_seen)}
                </div>
              </article>
            ))}
          </div>
        )}
      </SectionFrame>
    </div>
  )
}
