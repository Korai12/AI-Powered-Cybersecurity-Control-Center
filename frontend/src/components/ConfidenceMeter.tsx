// Stub — implemented in its phase
import { useMemo } from 'react'

type XaiEvidence = {
  logLines?: string[]
  reasoningSteps?: string[]
}

type ConfidenceMeterProps = {
  confidence: number | null | undefined
  evidence?: XaiEvidence
  title?: string
  sourceLabel?: string
  className?: string
}

type ConfidenceBand = {
  key: 'high' | 'moderate' | 'low'
  label: string
  message: string
  barClass: string
  chipClass: string
  panelClass: string
}

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function normalizeConfidence(value: number | null | undefined): number {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 0
  }
  if (value < 0) return 0
  if (value > 1) return 1
  return value
}

function getConfidenceBand(confidence: number): ConfidenceBand {
  if (confidence >= 0.75) {
    return {
      key: 'high',
      label: 'High confidence',
      message: 'High confidence. Proceed with recommendations.',
      barClass: 'bg-emerald-500',
      chipClass: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
      panelClass: 'border-emerald-500/20',
    }
  }

  if (confidence >= 0.4) {
    return {
      key: 'moderate',
      label: 'Moderate confidence',
      message: 'Moderate confidence. Review evidence before acting.',
      barClass: 'bg-amber-400',
      chipClass: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
      panelClass: 'border-amber-400/20',
    }
  }

  return {
    key: 'low',
    label: 'Low confidence',
    message: 'Low confidence. Manual analyst review strongly recommended.',
    barClass: 'bg-rose-500',
    chipClass: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
    panelClass: 'border-rose-500/20',
  }
}

function formatPercent(confidence: number): string {
  return `${Math.round(confidence * 100)}%`
}

function cleanEvidence(values?: string[]): string[] {
  if (!values) return []
  return values.map((item) => item.trim()).filter(Boolean)
}

export default function ConfidenceMeter({
  confidence,
  evidence,
  title = 'AI Confidence Assessment',
  sourceLabel,
  className,
}: ConfidenceMeterProps) {
  const normalized = normalizeConfidence(confidence)

  const band = useMemo(() => getConfidenceBand(normalized), [normalized])
  const percentage = useMemo(() => formatPercent(normalized), [normalized])

  const logLines = useMemo(() => cleanEvidence(evidence?.logLines), [evidence?.logLines])
  const reasoningSteps = useMemo(
    () => cleanEvidence(evidence?.reasoningSteps),
    [evidence?.reasoningSteps],
  )

  return (
    <section
      className={cx(
        'rounded-2xl border bg-slate-900/70 p-5 shadow-[0_12px_32px_rgba(2,6,23,0.22)]',
        band.panelClass,
        className,
      )}
    >
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            XAI Evidence Panel
          </div>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">{title}</h3>
          <p className="mt-1 text-sm text-slate-400">
            Analyst-facing confidence display for AI output and supporting evidence chain.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {sourceLabel ? (
            <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-300">
              {sourceLabel}
            </span>
          ) : null}
          <span
            className={cx(
              'rounded-full border px-3 py-1 text-xs font-medium',
              band.chipClass,
            )}
          >
            {band.label}
          </span>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="flex items-end justify-between gap-4">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-slate-400">
              Model confidence
            </div>
            <div className="mt-1 text-3xl font-semibold text-slate-100">{percentage}</div>
          </div>
          <div className="max-w-sm text-right text-sm text-slate-300">{band.message}</div>
        </div>

        <div className="mt-4 h-3 overflow-hidden rounded-full bg-slate-800">
          <div
            className={cx('h-full rounded-full transition-all duration-300', band.barClass)}
            style={{ width: `${normalized * 100}%` }}
            aria-hidden="true"
          />
        </div>
      </div>

      <div className="mt-5 grid gap-4 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="text-[11px] uppercase tracking-wide text-slate-400">
            Specific log lines
          </div>

          {logLines.length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No specific log lines available.</p>
          ) : (
            <div className="mt-3 space-y-2">
              {logLines.map((line, index) => (
                <pre
                  key={`${line}-${index}`}
                  className="overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-slate-200"
                >
                  {line}
                </pre>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="text-[11px] uppercase tracking-wide text-slate-400">
            Reasoning steps
          </div>

          {reasoningSteps.length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No reasoning steps available.</p>
          ) : (
            <ol className="mt-3 space-y-2">
              {reasoningSteps.map((step, index) => (
                <li
                  key={`${step}-${index}`}
                  className="rounded-xl border border-slate-800 bg-slate-900 px-3 py-3 text-sm text-slate-200"
                >
                  <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-700 text-[11px] text-slate-300">
                    {index + 1}
                  </span>
                  {step}
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </section>
  )
}