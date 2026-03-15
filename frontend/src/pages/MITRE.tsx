// Stub — implemented in its phase
import { useEffect, useMemo, useState } from 'react'

import { ApiError, api, type MitreHeatmapCell, type MitreHeatmapResponse } from '@/lib/api'

const COLUMN_WIDTH = 92
const CELL_WIDTH = 72
const CELL_HEIGHT = 18
const CELL_GAP = 4
const HEADER_HEIGHT = 56
const SVG_PADDING_X = 18
const SVG_PADDING_Y = 14

function splitWords(text: string) {
  return text.split(' ')
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

function getCellFill(cell: MitreHeatmapCell, maxCount: number) {
  if (cell.coverage_gap) {
    return '#7f1d1d'
  }

  if (maxCount <= 0) {
    return '#164e63'
  }

  const ratio = Math.max(0, Math.min(1, cell.detection_count / maxCount))

  if (ratio >= 0.75) return '#06b6d4'
  if (ratio >= 0.5) return '#0891b2'
  if (ratio >= 0.25) return '#155e75'
  return '#164e63'
}

export default function MITREPage() {
  const [heatmap, setHeatmap] = useState<MitreHeatmapResponse | null>(null)
  const [selected, setSelected] = useState<MitreHeatmapCell | null>(null)
  const [loading, setLoading] = useState(true)
  const [errorText, setErrorText] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true

    async function load() {
      try {
        setLoading(true)
        setErrorText(null)

        const response = await api.getMitreHeatmap()
        if (!mounted) return

        setHeatmap(response)

        const firstInteresting =
          response.cells.find((item) => item.detection_count > 0) ||
          response.cells[0] ||
          null

        setSelected(firstInteresting)
      } catch (err) {
        const message =
          err instanceof ApiError ? err.message : 'Failed to load MITRE heatmap.'
        if (mounted) {
          setErrorText(message)
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    void load()

    return () => {
      mounted = false
    }
  }, [])

  const grouped = useMemo(() => {
    const map = new Map<string, MitreHeatmapCell[]>()

    for (const tactic of heatmap?.tactics || []) {
      map.set(tactic, [])
    }

    for (const cell of heatmap?.cells || []) {
      if (!map.has(cell.tactic)) {
        map.set(cell.tactic, [])
      }
      map.get(cell.tactic)!.push(cell)
    }

    return map
  }, [heatmap])

  const maxRows = useMemo(() => {
    let max = 0
    for (const cells of grouped.values()) {
      max = Math.max(max, cells.length)
    }
    return max
  }, [grouped])

  const svgWidth =
    SVG_PADDING_X * 2 + (heatmap?.tactics.length || 0) * COLUMN_WIDTH

  const svgHeight =
    SVG_PADDING_Y * 2 + HEADER_HEIGHT + maxRows * (CELL_HEIGHT + CELL_GAP)

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
              MITRE ATT&CK Heatmap
            </div>
            <h1 className="mt-1 text-2xl font-semibold text-slate-100">
              Detection Coverage Grid
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Interactive SVG heatmap of ATT&CK techniques using live detection counts from the events table. Techniques with zero detections are coverage gaps and appear in red.
            </p>
          </div>

          {heatmap ? (
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-3 text-xs text-slate-400">
              Generated: {formatDate(heatmap.generated_at)}<br />
              Source: {heatmap.catalog_source}
            </div>
          ) : null}
        </div>

        {errorText ? (
          <div className="mt-6 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {errorText}
          </div>
        ) : null}

        {loading ? (
          <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-6 text-sm text-slate-400">
            Loading heatmap...
          </div>
        ) : null}

        {heatmap ? (
          <>
            <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">Total techniques</div>
                <div className="mt-2 text-2xl font-semibold text-slate-100">{heatmap.total_techniques}</div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">Covered techniques</div>
                <div className="mt-2 text-2xl font-semibold text-emerald-300">{heatmap.covered_techniques}</div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">Coverage gaps</div>
                <div className="mt-2 text-2xl font-semibold text-rose-300">{heatmap.coverage_gap_count}</div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">Max detections</div>
                <div className="mt-2 text-2xl font-semibold text-cyan-300">{heatmap.max_detection_count}</div>
              </div>
            </div>

            <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="mb-4 flex flex-wrap gap-4 text-xs text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="inline-block h-3 w-3 rounded-sm bg-[#7f1d1d]" />
                  Coverage gap
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-block h-3 w-3 rounded-sm bg-[#164e63]" />
                  Low detections
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-block h-3 w-3 rounded-sm bg-[#06b6d4]" />
                  High detections
                </div>
              </div>

              <div className="overflow-x-auto">
                <svg width={svgWidth} height={svgHeight} role="img">
                  {heatmap.tactics.map((tactic, columnIndex) => {
                    const cells = grouped.get(tactic) || []
                    const x = SVG_PADDING_X + columnIndex * COLUMN_WIDTH

                    return (
                      <g key={tactic} transform={`translate(${x}, ${SVG_PADDING_Y})`}>
                        <text
                          x={CELL_WIDTH / 2}
                          y={0}
                          textAnchor="middle"
                          className="fill-slate-300 text-[10px] font-semibold"
                        >
                          {splitWords(tactic).map((word, idx) => (
                            <tspan
                              key={`${tactic}-${idx}`}
                              x={CELL_WIDTH / 2}
                              dy={idx === 0 ? 12 : 11}
                            >
                              {word}
                            </tspan>
                          ))}
                        </text>

                        {cells.map((cell, rowIndex) => {
                          const y = HEADER_HEIGHT + rowIndex * (CELL_HEIGHT + CELL_GAP)
                          const isSelected = selected?.technique_id === cell.technique_id

                          return (
                            <g
                              key={cell.technique_id}
                              transform={`translate(0, ${y})`}
                              onClick={() => setSelected(cell)}
                              className="cursor-pointer"
                            >
                              <rect
                                width={CELL_WIDTH}
                                height={CELL_HEIGHT}
                                rx={4}
                                fill={getCellFill(cell, heatmap.max_detection_count)}
                                stroke={isSelected ? '#f8fafc' : '#1e293b'}
                                strokeWidth={isSelected ? 2 : 1}
                              />
                              <title>
                                {cell.technique_id} — {cell.name} — detections: {cell.detection_count}
                              </title>
                            </g>
                          )
                        })}
                      </g>
                    )
                  })}
                </svg>
              </div>
            </div>
          </>
        ) : null}
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
          Technique Details
        </div>
        <h2 className="mt-1 text-lg font-semibold text-slate-100">
          {selected ? `${selected.technique_id} — ${selected.name}` : 'Select a technique'}
        </h2>

        {!selected ? (
          <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-400">
            Click a heatmap cell to inspect technique details.
          </div>
        ) : (
          <div className="mt-4 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(360px,420px)]">
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300">
                    {selected.tactic}
                  </span>
                  <span
                    className={`rounded-full border px-3 py-1 text-xs ${
                      selected.coverage_gap
                        ? 'border-rose-500/20 bg-rose-500/10 text-rose-200'
                        : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200'
                    }`}
                  >
                    {selected.coverage_gap ? 'Coverage gap' : 'Detection coverage present'}
                  </span>
                </div>

                <div className="mt-4 text-sm text-slate-300">
                  <span className="font-semibold text-slate-100">Detections:</span>{' '}
                  {selected.detection_count}
                </div>

                <div className="mt-4 text-sm leading-6 text-slate-300">
                  <div className="font-semibold text-slate-100">Description</div>
                  <p className="mt-2">
                    {selected.description || 'No bundled ATT&CK description available for this technique.'}
                  </p>
                </div>

                <div className="mt-4 text-sm leading-6 text-slate-300">
                  <div className="font-semibold text-slate-100">Detection Notes</div>
                  <p className="mt-2">
                    {selected.detection || 'No bundled detection notes available for this technique.'}
                  </p>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="font-semibold text-slate-100">Triggering Events</div>

                {selected.events.length === 0 ? (
                  <div className="mt-3 rounded-xl border border-rose-500/20 bg-rose-500/10 p-4 text-sm text-rose-200">
                    No events currently map to this technique. This cell is an active coverage gap.
                  </div>
                ) : (
                  <div className="mt-4 space-y-3">
                    {selected.events.map((event) => (
                      <div
                        key={event.id}
                        className="rounded-xl border border-slate-800 bg-slate-900/70 p-4"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-300">
                            {event.severity || 'UNKNOWN'}
                          </span>
                          <span className="text-xs text-slate-500">
                            {formatDate(event.timestamp)}
                          </span>
                        </div>

                        <div className="mt-3 text-sm font-medium text-slate-100">
                          {event.event_type || 'Security event'}
                        </div>

                        <div className="mt-2 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
                          <div>Host: {event.hostname || '—'}</div>
                          <div>User: {event.username || '—'}</div>
                          <div>Src IP: {event.src_ip || '—'}</div>
                          <div>Dst IP: {event.dst_ip || '—'}</div>
                          <div>Rule: {event.rule_id || '—'}</div>
                          <div>Incident: {event.incident_id || '—'}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="font-semibold text-slate-100">Coverage Summary</div>

              <div className="mt-4 grid gap-3">
                <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Technique ID</div>
                  <div className="mt-2 text-sm font-medium text-slate-100">{selected.technique_id}</div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Gap status</div>
                  <div className="mt-2 text-sm font-medium text-slate-100">
                    {selected.coverage_gap ? 'No detections mapped' : 'At least one detection mapped'}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Global coverage gaps</div>
                  <div className="mt-2 text-sm font-medium text-slate-100">
                    {heatmap?.coverage_gap_count ?? 0}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Catalog source</div>
                  <div className="mt-2 text-sm font-medium text-slate-100">
                    {heatmap?.catalog_source || '—'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}