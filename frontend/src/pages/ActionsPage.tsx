// Stub — implemented in its phase
import { useEffect, useMemo, useState } from 'react'
import { useLocation } from 'react-router-dom'

import { ApiError, api, type ResponseActionRecord } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'
const { role } = useAuth()
type RecommendationState = {
  incidentId?: string
  prefillRecommendation?: {
    priority?: string
    action?: string
    rationale?: string
    timeframe?: string
  }
}

const ACTION_OPTIONS = [
  'block_ip',
  'unblock_ip',
  'isolate_host',
  'restore_host',
  'disable_user',
  'enable_user',
  'force_mfa',
  'reset_password',
  'block_domain',
  'kill_process',
  'collect_forensics',
  'rate_limit_ip',
  'notify_analyst',
  'create_ticket',
]

function inferActionType(actionText?: string | null): string {
  const text = (actionText || '').toLowerCase()

  if (text.includes('block ip')) return 'block_ip'
  if (text.includes('unblock ip')) return 'unblock_ip'
  if (text.includes('isolate')) return 'isolate_host'
  if (text.includes('restore host')) return 'restore_host'
  if (text.includes('disable user')) return 'disable_user'
  if (text.includes('enable user')) return 'enable_user'
  if (text.includes('mfa')) return 'force_mfa'
  if (text.includes('password')) return 'reset_password'
  if (text.includes('domain')) return 'block_domain'
  if (text.includes('kill process')) return 'kill_process'
  if (text.includes('forensic')) return 'collect_forensics'
  if (text.includes('rate limit')) return 'rate_limit_ip'
  if (text.includes('ticket')) return 'create_ticket'

  return 'notify_analyst'
}

const ROLE_LEVELS: Record<string, number> = {
  analyst: 0,
  senior_analyst: 1,
  soc_manager: 2,
}

function hasMinRole(role: string | null, minimumRole: string) {
  if (!role) return false
  return (ROLE_LEVELS[role] ?? -1) >= (ROLE_LEVELS[minimumRole] ?? 0)
}

function canCreateResponseActions(role: string | null) {
  return hasMinRole(role, 'senior_analyst')
  
}


function canApproveByRisk(role: string | null, riskLevel: string) {
  const risk = (riskLevel || '').toUpperCase()
  if (risk === 'LOW') return hasMinRole(role, 'analyst')
  if (risk === 'MEDIUM') return hasMinRole(role, 'senior_analyst')
  if (risk === 'HIGH') return hasMinRole(role, 'soc_manager')
  return false
}

function defaultParamsForActionType(actionType: string, incidentId?: string) {
  switch (actionType) {
    case 'block_ip':
      return { ip: '1.2.3.4', duration_hours: 24 }
    case 'unblock_ip':
      return { ip: '1.2.3.4' }
    case 'isolate_host':
      return { hostname: 'srv-01', reason: 'Containment from incident recommendation' }
    case 'restore_host':
      return { hostname: 'srv-01' }
    case 'disable_user':
      return { username: 'jdoe', reason: 'Suspicious account activity' }
    case 'enable_user':
      return { username: 'jdoe' }
    case 'force_mfa':
      return { username: 'jdoe' }
    case 'reset_password':
      return { username: 'jdoe' }
    case 'block_domain':
      return { domain: 'evil.example', duration_hours: 72 }
    case 'kill_process':
      return { hostname: 'srv-01', pid: 1234, process_name: 'malware.exe' }
    case 'collect_forensics':
      return { hostname: 'srv-01', scope: 'memory|logs|processes' }
    case 'rate_limit_ip':
      return { ip: '1.2.3.4', requests_per_min: 10 }
    case 'notify_analyst':
      return { analyst_id: '', message: 'Review incident response queue', severity: 'HIGH' }
    case 'create_ticket':
      return {
        title: 'SOC escalation',
        severity: 'HIGH',
        incident_id: incidentId || '',
      }
    default:
      return {}
  }
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
    second: '2-digit',
  }).format(d)
}

function getCountdownLabel(vetoDeadline?: string | null, nowMs?: number) {
  if (!vetoDeadline) return '—'
  const remainingMs = new Date(vetoDeadline).getTime() - (nowMs || Date.now())
  if (remainingMs <= 0) return 'Expired'
  const totalSeconds = Math.ceil(remainingMs / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}

function statusClasses(status: string) {
  switch (status) {
    case 'completed':
      return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200'
    case 'executing':
      return 'border-cyan-500/20 bg-cyan-500/10 text-cyan-200'
    case 'pending':
      return 'border-amber-500/20 bg-amber-500/10 text-amber-200'
    case 'approved':
      return 'border-sky-500/20 bg-sky-500/10 text-sky-200'
    case 'vetoed':
      return 'border-rose-500/20 bg-rose-500/10 text-rose-200'
    case 'rolled_back':
      return 'border-fuchsia-500/20 bg-fuchsia-500/10 text-fuchsia-200'
    case 'failed':
      return 'border-red-500/20 bg-red-500/10 text-red-200'
    default:
      return 'border-slate-700 bg-slate-800/70 text-slate-300'
  }
}

export default function ActionsPage() {
  const location = useLocation()
  const { role } = useAuth()

  const navState = (location.state || {}) as RecommendationState
  const inferredActionType = inferActionType(navState.prefillRecommendation?.action)
  const initialParams = defaultParamsForActionType(inferredActionType, navState.incidentId)

  const [incidentId, setIncidentId] = useState(navState.incidentId || '')
  const [actionType, setActionType] = useState(inferredActionType)
  const [createdBy, setCreatedBy] = useState<'ai' | 'analyst'>(
    navState.prefillRecommendation ? 'ai' : 'analyst',
  )
  const [paramsText, setParamsText] = useState(JSON.stringify(initialParams, null, 2))
  const [actions, setActions] = useState<ResponseActionRecord[]>([])
  const [statusFilter, setStatusFilter] = useState('')
  const [errorText, setErrorText] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [nowMs, setNowMs] = useState(Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  async function loadActions() {
    try {
      const response = await api.listActions({
        status: statusFilter || undefined,
        limit: 50,
      })
      setActions(response.items || [])
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to load actions queue.'
      setErrorText(message)
    }
  }

  useEffect(() => {
    void loadActions()
  }, [statusFilter])

  const canSubmit = useMemo(
    () => incidentId.trim().length > 0 && actionType.trim().length > 0 && !isSubmitting,
    [incidentId, actionType, isSubmitting],
  )

  async function handleCreateAction() {
    if (!canCreateResponseActions(role)) {
  setErrorText('Only senior analysts and SOC managers can create response actions.')
  return
}

    let parsedParams: Record<string, unknown> = {}

    try {
      parsedParams = JSON.parse(paramsText || '{}')
    } catch {
      setErrorText('Action params must be valid JSON.')
      return
    }

    try {
      setErrorText(null)
      setIsSubmitting(true)

      await api.createAction({
        incident_id: incidentId,
        action_type: actionType,
        action_params: parsedParams,
        created_by: createdBy,
      })

      await loadActions()
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to create response action.'
      setErrorText(message)
    } finally {
      setIsSubmitting(false)
    }
  }

  async function handleApprove(actionId: string) {
    try {
      setErrorText(null)
      await api.approveAction(actionId)
      await loadActions()
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to approve action.'
      setErrorText(message)
    }
  }

  async function handleVeto(actionId: string) {
    try {
      setErrorText(null)
      await api.vetoAction(actionId)
      await loadActions()
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to veto action.'
      setErrorText(message)
    }
  }

  async function handleRollback(actionId: string) {
    try {
      setErrorText(null)
      await api.rollbackAction(actionId)
      await loadActions()
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to roll back action.'
      setErrorText(message)
    }
  }

  function resetParamsForAction(nextActionType: string) {
    setActionType(nextActionType)
    setParamsText(
      JSON.stringify(defaultParamsForActionType(nextActionType, incidentId), null, 2),
    )
  }

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              Autonomous Response Actions
            </div>
            <h1 className="mt-1 text-2xl font-semibold text-slate-100">
              Response Actions Queue
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Create simulated response actions, review pending approvals, monitor medium-risk veto windows, and roll back completed reversible actions.
            </p>
          </div>

          <div className="rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-300">
            Role: {role || 'unknown'}
          </div>
        </div>

        <div className="mt-6 grid gap-4 xl:grid-cols-2">
          <label className="text-sm text-slate-300">
            <div className="mb-2 font-medium">Incident ID</div>
            <input
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="Incident UUID"
            />
          </label>

          <label className="text-sm text-slate-300">
            <div className="mb-2 font-medium">Created By</div>
            <select
              value={createdBy}
              onChange={(e) => setCreatedBy(e.target.value as 'ai' | 'analyst')}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none"
            >
              <option value="analyst">analyst</option>
              <option value="ai">ai</option>
            </select>
          </label>

          <label className="text-sm text-slate-300">
            <div className="mb-2 font-medium">Action Type</div>
            <select
              value={actionType}
              onChange={(e) => resetParamsForAction(e.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none"
            >
              {ACTION_OPTIONS.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>

          <label className="text-sm text-slate-300">
            <div className="mb-2 font-medium">Queue Filter</div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none"
            >
              <option value="">all</option>
              <option value="pending">pending</option>
              <option value="approved">approved</option>
              <option value="executing">executing</option>
              <option value="completed">completed</option>
              <option value="vetoed">vetoed</option>
              <option value="rolled_back">rolled_back</option>
              <option value="failed">failed</option>
            </select>
          </label>
        </div>

        <div className="mt-4">
          <div className="mb-2 text-sm font-medium text-slate-200">Action Params JSON</div>
          <textarea
            rows={10}
            value={paramsText}
            onChange={(e) => setParamsText(e.target.value)}
            className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none"
          />
        </div>

        {navState.prefillRecommendation ? (
          <div className="mt-4 rounded-xl border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-200">
            Prefilled from incident recommendation: {navState.prefillRecommendation.action || '—'}
          </div>
        ) : null}

        {errorText ? (
          <div className="mt-4 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {errorText}
          </div>
        ) : null}

        <div className="mt-4">
          <button
            type="button"
            onClick={handleCreateAction}
            disabled={!canSubmit}
            className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting ? 'Creating Action...' : 'Create Response Action'}
          </button>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
          Queue
        </div>
        <h2 className="mt-1 text-lg font-semibold text-slate-100">
          Current Response Actions
        </h2>

        <div className="mt-5 space-y-4">
          {actions.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-400">
              No response actions yet.
            </div>
          ) : (
            actions.map((action) => {
              const showCountdown =
                action.risk_level === 'MEDIUM' &&
                action.status === 'pending' &&
                action.veto_deadline

              return (
                <div
                  key={action.id}
                  className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5"
                >
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${statusClasses(action.status)}`}>
                          {action.status}
                        </span>
                        <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-300">
                          {action.risk_level}
                        </span>
                        <span className="text-xs uppercase tracking-wide text-slate-500">
                          {action.action_type}
                        </span>
                      </div>

                      <div className="mt-3 text-sm text-slate-300">
                        Incident: <span className="text-slate-100">{action.incident_id}</span>
                      </div>
                      <div className="mt-2 text-sm text-slate-300">
                        Created: {formatDate(action.created_at)} · Source: {action.created_by}
                      </div>

                      {showCountdown ? (
                        <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
                          MEDIUM-risk veto window: {getCountdownLabel(action.veto_deadline, nowMs)}
                        </div>
                      ) : null}

                      <div className="mt-4">
                        <div className="text-sm font-medium text-slate-100">Parameters</div>
                        <pre className="mt-2 overflow-x-auto rounded-xl bg-slate-950/90 p-3 text-xs text-slate-300">
                          {JSON.stringify(action.action_params || {}, null, 2)}
                        </pre>
                      </div>

                      {action.result ? (
                        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-300">
                          <div className="font-medium text-slate-100">Result</div>
                          <div className="mt-2">{action.result}</div>
                        </div>
                      ) : null}

                      <div className="mt-4">
                        <div className="text-sm font-medium text-slate-100">Audit Log</div>
                        <pre className="mt-2 overflow-x-auto rounded-xl bg-slate-950/90 p-3 text-xs text-slate-300">
                          {JSON.stringify(action.audit_log || [], null, 2)}
                        </pre>
                      </div>
                    </div>

                    <div className="shrink-0 space-y-2">
                      {(action.risk_level === 'MEDIUM' || action.risk_level === 'HIGH') &&
                      action.status === 'pending' ? (
                        <button
                          type="button"
                          onClick={() => handleApprove(action.id)}
                          className="block w-full rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20"
                        >
                          Approve
                        </button>
                      ) : null}

                      {action.risk_level === 'MEDIUM' && action.status === 'pending' ? (
                        <button
                          type="button"
                          onClick={() => handleVeto(action.id)}
                          className="block w-full rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm font-medium text-rose-300 transition hover:bg-rose-500/20"
                        >
                          Veto
                        </button>
                      ) : null}

                      {action.status === 'completed' && action.rollback_available ? (
                        <button
                          type="button"
                          onClick={() => handleRollback(action.id)}
                          className="block w-full rounded-xl border border-fuchsia-500/30 bg-fuchsia-500/10 px-4 py-2 text-sm font-medium text-fuchsia-300 transition hover:bg-fuchsia-500/20"
                        >
                          Rollback
                        </button>
                      ) : null}
                    </div>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </section>
    </div>
  )
}