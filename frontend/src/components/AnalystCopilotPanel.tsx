import { useEffect, useMemo, useRef, useState } from 'react'

import { ApiError, api } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'

type CopilotMode = 'incident' | 'dashboard'

type ChatWsMessage =
  | {
      type: 'connected'
      channel?: string
      session_id?: string
    }
  | {
      type: 'token'
      content: string
      session_id?: string
    }
  | {
      type: 'complete'
      session_id?: string
      confidence?: number
      evidence?: string[]
      suggested_actions?: string[]
    }
  | {
      type: 'error'
      error?: string
      session_id?: string
    }
  | {
      type: 'pong'
    }

type Props = {
  mode: CopilotMode
  title?: string
  contextPayload: Record<string, unknown>
  autoRefreshMs?: number
}

function createSessionId() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `copilot-${Date.now()}-${Math.random().toString(16).slice(2)}`
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

function buildCopilotPrompt(
  mode: CopilotMode,
  contextPayload: Record<string, unknown>,
): string {
  const contextJson = JSON.stringify(contextPayload, null, 2)

  const focus =
    mode === 'incident'
      ? 'Focus on next investigation steps, containment ideas, unusual patterns, and threat intel that matters right now for this incident.'
      : 'Focus on dashboard-level priorities, unusual environment-wide patterns, top threats, and what the analyst should investigate next.'

  return `
You are the ACCC Analyst Copilot Mode.

Your job is to proactively help the analyst without waiting for a question.

${focus}

Use the provided context and return structured JSON with:
{
  "response_text": "concise but useful analyst-facing summary",
  "confidence": 0.0,
  "evidence": ["evidence item 1", "evidence item 2"],
  "suggested_actions": ["action 1", "action 2", "action 3"]
}

Current context:
${contextJson}
`.trim()
}

export default function AnalystCopilotPanel({
  mode,
  title,
  contextPayload,
  autoRefreshMs = 60000,
}: Props) {
  const { accessToken } = useAuth()

  const [sessionId] = useState(() => createSessionId())
  const [streamedText, setStreamedText] = useState('')
  const [confidence, setConfidence] = useState<number | null>(null)
  const [evidence, setEvidence] = useState<string[]>([])
  const [suggestedActions, setSuggestedActions] = useState<string[]>([])
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [errorText, setErrorText] = useState<string | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const pendingRunRef = useRef(false)

  const contextKey = useMemo(
    () => JSON.stringify(contextPayload),
    [contextPayload],
  )

  useEffect(() => {
    if (!accessToken) return

    const ws = new WebSocket(api.getChatWebSocketUrl(sessionId, accessToken))
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as ChatWsMessage

        if (msg.type === 'token') {
          setStreamedText((prev) => prev + (msg.content || ''))
          return
        }

        if (msg.type === 'complete') {
          setConfidence(
            typeof msg.confidence === 'number' ? msg.confidence : null,
          )
          setEvidence(Array.isArray(msg.evidence) ? msg.evidence : [])
          setSuggestedActions(
            Array.isArray(msg.suggested_actions) ? msg.suggested_actions : [],
          )
          setLastRunAt(new Date().toISOString())
          setIsRunning(false)
          pendingRunRef.current = false
          return
        }

        if (msg.type === 'error') {
          setErrorText(msg.error || 'Copilot stream failed.')
          setIsRunning(false)
          pendingRunRef.current = false
        }
      } catch (err) {
        console.error('Invalid copilot websocket message', err)
      }
    }

    ws.onerror = () => {
      setErrorText('Copilot WebSocket connection error.')
      setIsRunning(false)
      pendingRunRef.current = false
    }

    ws.onclose = () => {
      wsRef.current = null
    }

    return () => {
      ws.close()
    }
  }, [sessionId, accessToken])

  async function triggerCopilotRun() {
    if (pendingRunRef.current) return

    try {
      pendingRunRef.current = true
      setIsRunning(true)
      setErrorText(null)
      setStreamedText('')
      setConfidence(null)
      setEvidence([])
      setSuggestedActions([])

      await api.sendChatMessage({
        session_id: sessionId,
        query: buildCopilotPrompt(mode, contextPayload),
      })
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Failed to trigger copilot.'
      setErrorText(message)
      setIsRunning(false)
      pendingRunRef.current = false
    }
  }

  useEffect(() => {
    if (!accessToken) return
    void triggerCopilotRun()
  }, [accessToken, contextKey])

  useEffect(() => {
    if (!accessToken || autoRefreshMs <= 0) return

    const timer = window.setInterval(() => {
      void triggerCopilotRun()
    }, autoRefreshMs)

    return () => window.clearInterval(timer)
  }, [accessToken, autoRefreshMs, contextKey])

  const confidencePercent =
    typeof confidence === 'number' ? Math.max(0, Math.min(100, Math.round(confidence * 100))) : null

  const confidenceTone =
    confidencePercent === null
      ? 'bg-slate-800'
      : confidencePercent >= 75
      ? 'bg-emerald-500'
      : confidencePercent >= 40
      ? 'bg-amber-500'
      : 'bg-rose-500'

  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Analyst Copilot
          </div>
          <h2 className="mt-1 text-lg font-semibold text-slate-100">
            {title || (mode === 'incident' ? 'Incident Copilot' : 'Dashboard Copilot')}
          </h2>
          <p className="mt-2 text-sm text-slate-400">
            Proactive AI guidance refreshed automatically from the current context.
          </p>
        </div>

        <div className="flex flex-col items-end gap-2">
          <button
            type="button"
            onClick={() => void triggerCopilotRun()}
            disabled={isRunning}
            className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isRunning ? 'Refreshing…' : 'Refresh'}
          </button>
          <div className="text-[11px] text-slate-500">
            Last update: {formatDate(lastRunAt)}
          </div>
        </div>
      </div>

      {errorText ? (
        <div className="mt-4 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {errorText}
        </div>
      ) : null}

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-500">
          Proactive Summary
        </div>
        <div className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-200">
          {streamedText || (isRunning ? 'Copilot is analyzing the current context…' : 'No copilot output yet.')}
        </div>
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-500">
          Confidence
        </div>
        <div className="mt-3 h-3 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className={`h-full ${confidenceTone}`}
            style={{ width: `${confidencePercent ?? 0}%` }}
          />
        </div>
        <div className="mt-2 text-sm text-slate-300">
          {confidencePercent === null ? 'No confidence score yet.' : `${confidencePercent}%`}
        </div>
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-500">
          Evidence
        </div>
        {evidence.length === 0 ? (
          <div className="mt-3 text-sm text-slate-400">No evidence items yet.</div>
        ) : (
          <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-200">
            {evidence.map((item, index) => (
              <li key={`${item}-${index}`}>{item}</li>
            ))}
          </ul>
        )}
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-500">
          Suggested Actions
        </div>
        {suggestedActions.length === 0 ? (
          <div className="mt-3 text-sm text-slate-400">No suggested actions yet.</div>
        ) : (
          <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-200">
            {suggestedActions.map((item, index) => (
              <li key={`${item}-${index}`}>{item}</li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}