import { useEffect, useMemo, useRef, useState } from 'react'

import { api, type DeepInvestigateResponse, type ApiError } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'

type AgentMessage =
  | {
      type: 'connected'
      run_id?: string
      channel?: string
      user?: string
      status?: string
      started_at?: string
    }
  | {
      type: 'thought'
      run_id?: string
      iteration: number
      timestamp: string
      content: string
    }
  | {
      type: 'action'
      run_id?: string
      iteration: number
      timestamp: string
      tool_name: string
      tool_input: unknown
    }
  | {
      type: 'observation'
      run_id?: string
      iteration: number
      timestamp: string
      tool_name: string
      content: unknown
    }
  | {
      type: 'complete'
      run_id?: string
      status?: 'completed' | 'max_iterations_reached' | 'timed_out' | 'failed'
      result?: {
        run_id: string
        status: string
        summary: string
        confidence: number
        evidence: string[]
        recommended_actions: string[]
        transcript: unknown[]
        started_at: string
        completed_at: string
      }
    }

type Props = {
  incidentId: string
  incidentTitle?: string
}

function toPrettyJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export default function DeepInvestigatePanel({
  incidentId,
  incidentTitle,
}: Props) {
  const { accessToken } = useAuth()

  const [query, setQuery] = useState(
    'Investigate this incident deeply. Identify the likely attack chain, highest-risk indicators, and best next actions.'
  )
  const [runId, setRunId] = useState<string | null>(null)
  const [messages, setMessages] = useState<AgentMessage[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [errorText, setErrorText] = useState<string | null>(null)
  const [finalResult, setFinalResult] = useState<AgentMessage extends { type: 'complete'; result?: infer R } ? R : never | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const endRef = useRef<HTMLDivElement | null>(null)

  const canRun = useMemo(() => query.trim().length >= 5 && !isRunning, [query, isRunning])

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, finalResult])

  useEffect(() => {
    if (!runId || !accessToken) return

    const url = api.getAgentWebSocketUrl(runId, accessToken)
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as AgentMessage
        if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'ping' }))
          return
        }

        setMessages((prev) => [...prev, msg])

        if (msg.type === 'complete') {
          setFinalResult(msg.result || null)
          setIsRunning(false)
        }
      } catch (err) {
        console.error('Invalid agent websocket message', err)
      }
    }

    ws.onerror = () => {
      setErrorText('WebSocket error while streaming investigation steps.')
      setIsRunning(false)
    }

    ws.onclose = () => {
      wsRef.current = null
    }

    return () => {
      ws.close()
    }
  }, [runId, accessToken])

  async function handleStart() {
    try {
      setErrorText(null)
      setMessages([])
      setFinalResult(null)
      setIsRunning(true)

      const result: DeepInvestigateResponse = await api.startDeepInvestigate(incidentId, {
        analyst_query: query,
      })

      setRunId(result.run_id)
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Failed to start deep investigation.'
      setErrorText(message)
      setIsRunning(false)
    }
  }

  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Agentic ReAct Investigation
          </div>
          <h2 className="mt-1 text-lg font-semibold text-slate-100">
            Deep Investigate
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-slate-400">
            Launch the Phase 6.1 agent on this incident and follow the thought, action, and observation transcript live.
          </p>
          {incidentTitle ? (
            <p className="mt-2 text-sm text-slate-500">Incident: {incidentTitle}</p>
          ) : null}
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
        <label className="text-sm font-medium text-slate-200">Analyst Query</label>
        <textarea
          rows={5}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500"
          placeholder="Ask the ReAct agent what to investigate..."
        />

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleStart}
            disabled={!canRun}
            className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isRunning ? 'Investigation Running...' : 'Start Deep Investigation'}
          </button>

          {runId ? (
            <span className="text-xs text-slate-500">Run ID: {runId}</span>
          ) : null}
        </div>

        {errorText ? (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {errorText}
          </div>
        ) : null}
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(320px,1fr)]">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Live Transcript
          </div>

          <div className="mt-4 max-h-[580px] space-y-3 overflow-y-auto pr-1">
            {messages.length === 0 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
                No transcript yet.
              </div>
            ) : null}

            {messages.map((msg, index) => {
              if (msg.type === 'connected') {
                return (
                  <div
                    key={`${msg.type}-${index}`}
                    className="rounded-xl border border-sky-500/20 bg-sky-500/10 p-4 text-sm text-sky-200"
                  >
                    Connected to agent stream {msg.run_id ? `(${msg.run_id})` : ''}
                  </div>
                )
              }

              if (msg.type === 'thought') {
                return (
                  <div
                    key={`${msg.type}-${index}`}
                    className="rounded-xl border border-slate-800 bg-slate-900/70 p-4"
                  >
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-cyan-400">
                      Step {msg.iteration} · Thought
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-200">{msg.content}</p>
                  </div>
                )
              }

              if (msg.type === 'action') {
                return (
                  <div
                    key={`${msg.type}-${index}`}
                    className="rounded-xl border border-slate-800 bg-slate-900/70 p-4"
                  >
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-cyan-400">
                      Step {msg.iteration} · Action
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-100">
                      {msg.tool_name}
                    </div>
                    <pre className="mt-3 overflow-x-auto rounded-xl bg-slate-950/90 p-3 text-xs text-slate-300">
                      {toPrettyJson(msg.tool_input)}
                    </pre>
                  </div>
                )
              }

              if (msg.type === 'observation') {
                return (
                  <div
                    key={`${msg.type}-${index}`}
                    className="rounded-xl border border-slate-800 bg-slate-900/70 p-4"
                  >
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-cyan-400">
                      Step {msg.iteration} · Observation
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-100">
                      {msg.tool_name}
                    </div>
                    <pre className="mt-3 overflow-x-auto rounded-xl bg-slate-950/90 p-3 text-xs text-slate-300">
                      {toPrettyJson(msg.content)}
                    </pre>
                  </div>
                )
              }

              if (msg.type === 'complete') {
                return (
                  <div
                    key={`${msg.type}-${index}`}
                    className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-sm text-emerald-200"
                  >
                    Investigation finished with status: <strong>{msg.status}</strong>
                  </div>
                )
              }

              return null
            })}

            <div ref={endRef} />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Final Summary
          </div>

          {!finalResult ? (
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
              No final result yet.
            </div>
          ) : (
            <div className="mt-4 space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-sm text-slate-300">
                  <span className="font-semibold text-slate-100">Status:</span>{' '}
                  {finalResult.status}
                </div>
                <div className="mt-2 text-sm text-slate-300">
                  <span className="font-semibold text-slate-100">Confidence:</span>{' '}
                  {Math.round((finalResult.confidence || 0) * 100)}%
                </div>
                <p className="mt-3 text-sm leading-6 text-slate-200">
                  {finalResult.summary}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-sm font-semibold text-slate-100">Evidence</div>
                <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-300">
                  {(finalResult.evidence || []).map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-sm font-semibold text-slate-100">
                  Recommended Actions
                </div>
                <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-300">
                  {(finalResult.recommended_actions || []).map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}