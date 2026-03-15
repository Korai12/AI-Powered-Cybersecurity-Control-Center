// Stub — implemented in its phase
import { useEffect, useMemo, useRef, useState } from 'react'

import { api, ApiError, type HuntJobsResponse, type HuntResultRecord } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'

type HuntMessage =
  | {
      type: 'connected'
      channel?: string
      hunt_id?: string
      user?: string
    }
  | {
      type: 'progress'
      stage?: string
      hunt_id?: string
      hypothesis?: string
      triggered_by?: string
      started_at?: string
      events_examined?: number
      candidate_events?: number
    }
  | {
      type: 'complete'
      stage?: string
      hunt_id?: string
      status?: string
      findings_count?: number
      events_examined?: number
      completed_at?: string
    }
  | {
      type: 'error'
      stage?: string
      hunt_id?: string
      status?: string
      error?: string
    }

function toPrettyJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export default function HuntPage() {
  const { accessToken } = useAuth()

  const [hypothesis, setHypothesis] = useState('Detect lateral movement patterns')
  const [lookbackHours, setLookbackHours] = useState(2)
  const [huntId, setHuntId] = useState<string | null>(null)
  const [messages, setMessages] = useState<HuntMessage[]>([])
  const [results, setResults] = useState<HuntResultRecord[]>([])
  const [jobs, setJobs] = useState<HuntJobsResponse['jobs']>([])
  const [isRunning, setIsRunning] = useState(false)
  const [errorText, setErrorText] = useState<string | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const endRef = useRef<HTMLDivElement | null>(null)

  const canRun = useMemo(
    () => hypothesis.trim().length >= 5 && !isRunning,
    [hypothesis, isRunning],
  )

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function loadResults() {
    try {
      const response = await api.listHuntResults({ limit: 20 })
      setResults(response.items || [])
    } catch {
      // keep page usable even if list fails
    }
  }

  async function loadJobs() {
    try {
      const response = await api.getHuntJobs()
      setJobs(response.jobs || [])
    } catch {
      // optional helper endpoint
    }
  }

  useEffect(() => {
    void loadResults()
    void loadJobs()
  }, [])

  useEffect(() => {
    if (!huntId || !accessToken) return

    const url = api.getHuntWebSocketUrl(huntId, accessToken)
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as HuntMessage

        if ((msg as any).type === 'ping') {
          ws.send(JSON.stringify({ type: 'ping' }))
          return
        }

        setMessages((prev) => [...prev, msg])

        if (msg.type === 'complete' || msg.type === 'error') {
          setIsRunning(false)
          void loadResults()
        }
      } catch (err) {
        console.error('Invalid hunt websocket message', err)
      }
    }

    ws.onerror = () => {
      setErrorText('WebSocket error while streaming hunt progress.')
      setIsRunning(false)
    }

    ws.onclose = () => {
      wsRef.current = null
    }

    return () => {
      ws.close()
    }
  }, [huntId, accessToken])

  async function handleRunHunt() {
    try {
      setErrorText(null)
      setMessages([])
      setIsRunning(true)

      const result = await api.runHunt({
        hypothesis,
        lookback_hours: lookbackHours,
      })

      setHuntId(result.hunt_id)
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to start hunt.'
      setErrorText(message)
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              Proactive Threat Hunting
            </div>
            <h1 className="mt-1 text-2xl font-semibold text-slate-100">
              Hunt Workspace
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Launch manual hunts, follow live hunt progress, and review recent AI hunt findings.
            </p>
          </div>

          <div
            className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${
              isRunning
                ? 'border border-amber-500/30 bg-amber-500/10 text-amber-300'
                : 'border border-slate-700 bg-slate-800/70 text-slate-300'
            }`}
          >
            {isRunning ? 'Running' : 'Idle'}
          </div>
        </div>

        <div className="mt-6 grid gap-3">
          <label className="text-sm font-medium text-slate-200">Hypothesis</label>
          <textarea
            rows={4}
            value={hypothesis}
            onChange={(e) => setHypothesis(e.target.value)}
            className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none placeholder:text-slate-500"
          />

          <div className="flex flex-wrap items-end gap-4">
            <label className="text-sm text-slate-300">
              <div className="mb-1 font-medium">Lookback Hours</div>
              <input
                type="number"
                min={1}
                max={24}
                value={lookbackHours}
                onChange={(e) => setLookbackHours(Number(e.target.value))}
                className="w-32 rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 outline-none"
              />
            </label>

            <button
              type="button"
              onClick={handleRunHunt}
              disabled={!canRun}
              className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isRunning ? 'Hunt Running...' : 'Run Hunt'}
            </button>

            {huntId ? (
              <span className="text-xs text-slate-500">Hunt ID: {huntId}</span>
            ) : null}
          </div>

          {errorText ? (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
              {errorText}
            </div>
          ) : null}
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
          Scheduler
        </div>
        <h2 className="mt-1 text-lg font-semibold text-slate-100">
          Registered Hunt Jobs
        </h2>

        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {jobs.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-400">
              No scheduler job data available yet.
            </div>
          ) : (
            jobs.map((job) => (
              <div
                key={job.id}
                className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"
              >
                <div className="text-sm font-semibold text-slate-100">{job.id}</div>
                <div className="mt-2 text-xs text-slate-500">
                  Next run: {job.next_run_time || '—'}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,1fr)]">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Live Hunt Progress
          </div>

          <div className="mt-4 max-h-[560px] space-y-3 overflow-y-auto pr-1">
            {messages.length === 0 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-400">
                No live hunt stream yet.
              </div>
            ) : null}

            {messages.map((msg, index) => (
              <div
                key={`${msg.type}-${index}`}
                className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"
              >
                <div className="text-[11px] font-semibold uppercase tracking-wide text-cyan-400">
                  {msg.type}
                </div>
                <pre className="mt-3 overflow-x-auto rounded-xl bg-slate-950/90 p-3 text-xs text-slate-300">
                  {toPrettyJson(msg)}
                </pre>
              </div>
            ))}

            <div ref={endRef} />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Recent Hunt Results
          </div>

          <div className="mt-4 space-y-4">
            {results.length === 0 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-400">
                No hunt results yet.
              </div>
            ) : (
              results.map((item) => (
                <div
                  key={item.id}
                  className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-semibold text-slate-100">
                      {item.hypothesis}
                    </div>
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      {item.status}
                    </div>
                  </div>

                  <div className="mt-2 text-xs text-slate-500">
                    Triggered by: {item.triggered_by}
                  </div>
                  <div className="mt-2 text-sm text-slate-300">
                    Events Examined: {item.events_examined} · Findings: {item.findings_count}
                  </div>

                  <div className="mt-3 text-sm leading-6 text-slate-300">
                    {item.ai_narrative || 'No narrative available.'}
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    {(item.technique_coverage || []).map((technique) => (
                      <span
                        key={technique}
                        className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-200"
                      >
                        {technique}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </section>
    </div>
  )
}