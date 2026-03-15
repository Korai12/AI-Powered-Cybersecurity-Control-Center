import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import DeepInvestigatePanel from '@/components/DeepInvestigatePanel'
import ConfidenceMeter from '@/components/ConfidenceMeter'
import KillChainGraph from '@/components/KillChainGraph'
import AnalystCopilotPanel from '@/components/AnalystCopilotPanel'
import {
  ApiError,
  api,
  type IncidentDetailResponse,
  type IncidentReportResponse,
  type IncidentTimelineResponse,
} from '@/lib/api'

function FullPageState({
  title,
  message,
}: {
  title: string
  message: string
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-8">
      <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
      <p className="mt-2 text-sm text-slate-400">{message}</p>
    </div>
  )
}

function formatDate(value?: string | null) {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(d)
}

export default function IncidentDetailPage() {
  const { incidentId = '' } = useParams()
  const navigate = useNavigate()

  const [incident, setIncident] = useState<IncidentDetailResponse | null>(null)
  const [timeline, setTimeline] = useState<IncidentTimelineResponse | null>(null)
  const [report, setReport] = useState<IncidentReportResponse | null>(null)

  const [isLoading, setIsLoading] = useState(true)
  const [isLoadingReport, setIsLoadingReport] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      if (!incidentId) {
        setError('Missing incident id.')
        setIsLoading(false)
        return
      }

      try {
        setIsLoading(true)
        setError(null)

        const [incidentData, timelineData] = await Promise.all([
          api.getIncident(incidentId),
          api.getIncidentTimeline(incidentId),
        ])

        if (cancelled) return
        setIncident(incidentData)
        setTimeline(timelineData)
      } catch (err) {
        if (cancelled) return
        const message =
          err instanceof ApiError ? err.message : 'Failed to load incident details.'
        setError(message)
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }

    load()

    return () => {
      cancelled = true
    }
  }, [incidentId])

  async function handleGenerateReport() {
    if (!incidentId) return

    try {
      setIsLoadingReport(true)
      const result = await api.getIncidentReport(incidentId)
      setReport(result)
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to generate incident report.'
      setError(message)
    } finally {
      setIsLoadingReport(false)
    }
  }

  const evidence = useMemo(() => {
    if (!incident) {
      return { logLines: [], reasoningSteps: [] }
    }

    return {
      logLines: (incident.events || [])
        .map((event) => event.raw_log)
        .filter((value): value is string => Boolean(value))
        .slice(0, 6),
      reasoningSteps: [
        incident.ai_summary,
        ...(incident.events || []).map((event) => event.ai_triage_notes),
      ]
        .filter((value): value is string => Boolean(value))
        .slice(0, 6),
    }
  }, [incident])

  const sortedRecommendations = useMemo(() => {
    const order: Record<string, number> = {
      IMMEDIATE: 0,
      SHORT_TERM: 1,
      LONG_TERM: 2,
    }

    return [...(incident?.ai_recommendations || [])].sort((a, b) => {
      const aRank = order[String(a.priority || '').toUpperCase()] ?? 99
      const bRank = order[String(b.priority || '').toUpperCase()] ?? 99
      return aRank - bRank
    })
  }, [incident?.ai_recommendations])
    const copilotContext = useMemo(() => {
    return {
      page: 'incident_detail',
      incident_id: incident?.id,
      title: incident?.title,
      severity: incident?.severity,
      status: incident?.status,
      attack_type: incident?.attack_type,
      kill_chain_stage: incident?.kill_chain_stage,
      ai_summary: incident?.ai_summary,
      confidence_score: incident?.confidence_score,
      false_positive_probability: incident?.false_positive_probability,
      recommendations: incident?.ai_recommendations || [],
      affected_assets: incident?.affected_assets || [],
      affected_users: incident?.affected_users || [],
      ioc_ips: incident?.ioc_ips || [],
      mitre_tactics: incident?.mitre_tactics || [],
      mitre_techniques: incident?.mitre_techniques || [],
      recent_events: (incident?.events || []).slice(0, 10).map((event) => ({
        id: event.id,
        timestamp: event.timestamp,
        event_type: event.event_type,
        severity: event.severity,
        hostname: event.hostname,
        username: event.username,
        src_ip: event.src_ip,
        dst_ip: event.dst_ip,
        rule_id: event.rule_id,
        mitre_tactic: event.mitre_tactic,
        mitre_technique: event.mitre_technique,
        abuse_score: event.abuse_score,
        relevant_cves: event.relevant_cves || [],
      })),
    }
  }, [incident])


  function handleCreateResponseAction(recommendation: {
    priority?: string
    action?: string
    rationale?: string
    timeframe?: string
  }) {
    navigate('/actions', {
      state: {
        incidentId: incident?.id,
        prefillRecommendation: recommendation,
      },
    })
  }

  if (isLoading) {
    return (
      <FullPageState
        title="Loading incident"
        message="Fetching incident details, timeline, and AI context."
      />
    )
  }

  if (error) {
    return <FullPageState title="Incident load failed" message={error} />
  }

  if (!incident || !timeline) {
    return (
      <FullPageState
        title="Incident unavailable"
        message="The incident data could not be loaded."
      />
    )
  }

  return (
    <div className="space-y-6">
                <AnalystCopilotPanel
            mode="incident"
            title="Incident Copilot"
            contextPayload={copilotContext}
            autoRefreshMs={45000}
          />
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              Incident Detail
            </div>
            <h1 className="mt-1 text-2xl font-semibold text-slate-100">
              {incident.title}
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              {incident.description || incident.ai_summary || 'No description available.'}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">Severity</div>
              <div className="mt-1 text-sm font-semibold text-slate-100">
                {incident.severity}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">Status</div>
              <div className="mt-1 text-sm font-semibold text-slate-100">
                {incident.status}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">Events</div>
              <div className="mt-1 text-sm font-semibold text-slate-100">
                {incident.event_count ?? incident.events.length}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">Attack Type</div>
              <div className="mt-1 text-sm font-semibold text-slate-100">
                {incident.attack_type || '—'}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">Kill Chain</div>
              <div className="mt-1 text-sm font-semibold text-slate-100">
                {incident.kill_chain_stage || '—'}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">Updated</div>
              <div className="mt-1 text-sm font-semibold text-slate-100">
                {formatDate(incident.updated_at)}
              </div>
            </div>
          </div>
        </div>
      </section>

      <ConfidenceMeter
        confidence={incident.confidence_score}
        evidence={evidence}
        title="Incident Correlation Confidence"
        sourceLabel="Correlation Result"
      />

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
          Mitigation Recommendations
        </div>
        <h2 className="mt-1 text-lg font-semibold text-slate-100">
          Ranked response guidance
        </h2>
        <p className="mt-2 text-sm text-slate-400">
          AI-generated mitigation recommendations ranked from immediate containment to longer-term hardening.
        </p>

        {sortedRecommendations.length === 0 ? (
          <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-5 text-sm text-slate-400">
            No mitigation recommendations available for this incident yet.
          </div>
        ) : (
          <div className="mt-5 grid gap-4">
            {sortedRecommendations.map((recommendation, index) => (
              <div
                key={`${recommendation.priority}-${recommendation.action}-${index}`}
                className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5"
              >
                <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-cyan-300">
                        {recommendation.priority || 'UNSPECIFIED'}
                      </span>
                      <span className="text-xs uppercase tracking-wide text-slate-500">
                        {recommendation.timeframe || '—'}
                      </span>
                    </div>

                    <h3 className="mt-3 text-base font-semibold text-slate-100">
                      {recommendation.action || 'Unnamed recommendation'}
                    </h3>

                    <p className="mt-2 text-sm leading-6 text-slate-300">
                      {recommendation.rationale || 'No rationale provided.'}
                    </p>
                  </div>

                  <div className="shrink-0">
                    <button
                      type="button"
                      onClick={() => handleCreateResponseAction(recommendation)}
                      className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20"
                    >
                      Create Response Action
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

<DeepInvestigatePanel
  incidentId={incident.id}
  incidentTitle={incident.title}
/>
      <KillChainGraph timeline={timeline} />

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
                AI Incident Report
              </div>
              <h2 className="mt-1 text-lg font-semibold text-slate-100">
                Narrative report
              </h2>
            </div>

            <button
              type="button"
              onClick={handleGenerateReport}
              disabled={isLoadingReport}
              className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isLoadingReport ? 'Generating...' : 'Generate Report'}
            </button>
          </div>

          {!report ? (
            <p className="mt-4 text-sm text-slate-400">
              Generate the AI narrative report to view the executive summary, timeline,
              IOC inventory, MITRE mapping, and recommended actions.
            </p>
          ) : (
            <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-5">
              <div className="mb-3 text-xs text-slate-500">
                Generated: {formatDate(report.report_generated_at)}
              </div>
              <div className="prose prose-invert max-w-none whitespace-pre-wrap text-sm">
                {report.report}
              </div>
            </div>
          )}
        </div>

        <aside className="space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              Affected Assets
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {(incident.affected_assets || []).length === 0 ? (
                <span className="text-sm text-slate-500">No assets listed.</span>
              ) : (
                incident.affected_assets?.map((item) => (
                  <span
                    key={item}
                    className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-sm text-slate-200"
                  >
                    {item}
                  </span>
                ))
              )}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              Affected Users
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {(incident.affected_users || []).length === 0 ? (
                <span className="text-sm text-slate-500">No users listed.</span>
              ) : (
                incident.affected_users?.map((item) => (
                  <span
                    key={item}
                    className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-sm text-slate-200"
                  >
                    {item}
                  </span>
                ))
              )}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              IOC IPs
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {(incident.ioc_ips || []).length === 0 ? (
                <span className="text-sm text-slate-500">No IOC IPs listed.</span>
              ) : (
                incident.ioc_ips?.map((item) => (
                  <span
                    key={item}
                    className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-sm text-slate-200"
                  >
                    {item}
                  </span>
                ))
              )}
            </div>
          </div>
        </aside>
      </section>
    </div>
  ) 
}    