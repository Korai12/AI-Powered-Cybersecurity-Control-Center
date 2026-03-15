//Phase 5.3 
import { useEffect, useMemo, useState } from 'react'
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  type Edge,
  type Node,
  type NodeMouseHandler,
} from 'reactflow'
import 'reactflow/dist/style.css'

type EventRecord = {
  id: string
  timestamp?: string | null
  ingested_at?: string | null
  source_format?: string | null
  source_identifier?: string | null
  event_type?: string | null
  severity?: string | null
  raw_log?: string | null
  src_ip?: string | null
  dst_ip?: string | null
  src_port?: number | null
  dst_port?: number | null
  protocol?: string | null
  username?: string | null
  hostname?: string | null
  process_name?: string | null
  file_hash?: string | null
  action?: string | null
  rule_id?: string | null
  geo_country?: string | null
  geo_city?: string | null
  geo_lat?: number | null
  geo_lon?: number | null
  abuse_score?: number | null
  relevant_cves?: string[]
  mitre_tactic?: string | null
  mitre_technique?: string | null
  severity_score?: number | null
  is_false_positive?: boolean | null
  incident_id?: string | null
  triage_status?: string | null
  ai_triage_notes?: string | null
  tags?: string[]
}

type TimelineNodeData = {
  label: string
  timestamp?: string | null
  severity?: string | null
  mitre_tactic?: string | null
  mitre_technique?: string | null
  kill_chain_stage?: string | null
  event: EventRecord
}

type TimelineNode = {
  id: string
  position: { x: number; y: number }
  data: TimelineNodeData
}

type TimelineEdge = {
  id: string
  source: string
  target: string
  animated?: boolean
}

type IncidentTimeline = {
  incident_id: string
  incident_title: string
  kill_chain_stage?: string | null
  nodes: TimelineNode[]
  edges: TimelineEdge[]
  event_count: number
}

type KillChainGraphProps = {
  timeline: IncidentTimeline
}

const PHASE_COLORS: Record<string, string> = {
  Reconnaissance: '#9ca3af',
  'Initial Access': '#facc15',
  Execution: '#f97316',
  Persistence: '#f59e0b',
  'Privilege Escalation': '#ea580c',
  'Lateral Movement': '#dc2626',
  Exfiltration: '#7f1d1d',
  Impact: '#7f1d1d',
}

function getPhaseColor(phase?: string | null): string {
  if (!phase) return '#64748b'
  return PHASE_COLORS[phase] || '#64748b'
}

function formatTimestamp(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

function DetailRow({
  label,
  value,
}: {
  label: string
  value: string | number | null | undefined
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-sm text-slate-100">{value ?? '—'}</div>
    </div>
  )
}

export default function KillChainGraph({ timeline }: KillChainGraphProps) {
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null)

  const nodes: Node[] = useMemo(() => {
    return timeline.nodes.map((node) => {
      const phase = node.data.kill_chain_stage || 'Unknown'
      const color = getPhaseColor(phase)

      return {
        id: node.id,
        position: node.position,
        data: {
          ...node.data,
          label: node.data.label || 'event',
        },
        draggable: false,
        style: {
          width: 220,
          borderRadius: 16,
          border: `1px solid ${color}`,
          background: '#0f172a',
          color: '#e2e8f0',
          boxShadow: `0 0 0 1px ${color}20, 0 8px 24px rgba(2, 6, 23, 0.45)`,
          padding: 0,
          overflow: 'hidden',
        },
      }
    })
  }, [timeline.nodes])

  const edges: Edge[] = useMemo(() => {
    return timeline.edges.map((edge) => ({
      ...edge,
      type: 'smoothstep',
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 18,
        height: 18,
        color: '#64748b',
      },
      style: {
        stroke: '#64748b',
        strokeWidth: 2,
      },
    }))
  }, [timeline.edges])

  const selectedNodeId = selectedEvent?.id ?? null

  const graphNodes: Node[] = useMemo(() => {
    return nodes.map((node) => {
      const phase = (node.data as TimelineNodeData).kill_chain_stage || 'Unknown'
      const color = getPhaseColor(phase)
      const isSelected = node.id === selectedNodeId

      return {
        ...node,
        style: {
          ...node.style,
          border: `1px solid ${isSelected ? '#22d3ee' : color}`,
          boxShadow: isSelected
            ? '0 0 0 1px rgba(34, 211, 238, 0.45), 0 0 24px rgba(34, 211, 238, 0.2)'
            : `0 0 0 1px ${color}20, 0 8px 24px rgba(2, 6, 23, 0.45)`,
        },
        data: {
          ...(node.data as TimelineNodeData),
          label: (
            <div className="min-h-[108px]">
              <div
                className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-950"
                style={{ backgroundColor: color }}
              >
                {phase}
              </div>
              <div className="space-y-2 px-3 py-3">
                <div className="text-sm font-semibold text-slate-100">
                  {(node.data as TimelineNodeData).label || 'event'}
                </div>
                <div className="text-xs text-slate-400">
                  {formatTimestamp((node.data as TimelineNodeData).timestamp)}
                </div>
                <div className="flex flex-wrap gap-2 text-[11px] text-slate-300">
                  <span className="rounded-full border border-slate-700 px-2 py-1">
                    {(node.data as TimelineNodeData).severity || 'UNKNOWN'}
                  </span>
                  <span className="rounded-full border border-slate-700 px-2 py-1">
                    {(node.data as TimelineNodeData).mitre_tactic || 'No tactic'}
                  </span>
                </div>
              </div>
            </div>
          ),
        },
      }
    })
  }, [nodes, selectedNodeId])

  const handleNodeClick: NodeMouseHandler = (_, node) => {
    const data = node.data as TimelineNodeData
    setSelectedEvent(data.event)
  }

  useEffect(() => {
    if (!selectedEvent && timeline.nodes.length > 0) {
      setSelectedEvent(timeline.nodes[0].data.event)
    }
  }, [selectedEvent, timeline.nodes])

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
      <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70">
        <div className="border-b border-slate-800 px-5 py-4">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Kill-Chain Timeline
          </div>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">
            {timeline.incident_title}
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            {timeline.event_count} correlated events • Furthest stage:{' '}
            {timeline.kill_chain_stage || 'Unknown'}
          </p>
        </div>

        <div className="h-[620px] bg-slate-950">
          <ReactFlow
            nodes={graphNodes}
            edges={edges}
            fitView
            onNodeClick={handleNodeClick}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
            proOptions={{ hideAttribution: true }}
          >
            <MiniMap
              pannable
              zoomable
              nodeStrokeWidth={3}
              nodeColor={(node) =>
                getPhaseColor((node.data as TimelineNodeData)?.kill_chain_stage)
              }
              style={{ backgroundColor: '#020617' }}
            />
            <Controls />
            <Background gap={18} size={1} color="#1e293b" />
          </ReactFlow>
        </div>
      </section>

      <aside className="rounded-2xl border border-slate-800 bg-slate-900/70">
        <div className="border-b border-slate-800 px-5 py-4">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            Event Details
          </div>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">
            {selectedEvent?.event_type || 'Select a node'}
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            Click a graph node to inspect the full event details.
          </p>
        </div>

        {!selectedEvent ? (
          <div className="px-5 py-6 text-sm text-slate-400">
            No event selected.
          </div>
        ) : (
          <div className="space-y-4 px-5 py-5">
            <div className="grid gap-3">
              <DetailRow label="Timestamp" value={formatTimestamp(selectedEvent.timestamp)} />
              <DetailRow label="Severity" value={selectedEvent.severity || '—'} />
              <DetailRow label="Source IP" value={selectedEvent.src_ip || '—'} />
              <DetailRow label="Destination IP" value={selectedEvent.dst_ip || '—'} />
              <DetailRow label="Username" value={selectedEvent.username || '—'} />
              <DetailRow label="Hostname" value={selectedEvent.hostname || '—'} />
              <DetailRow label="MITRE Tactic" value={selectedEvent.mitre_tactic || '—'} />
              <DetailRow label="MITRE Technique" value={selectedEvent.mitre_technique || '—'} />
              <DetailRow label="Action" value={selectedEvent.action || '—'} />
              <DetailRow label="Process" value={selectedEvent.process_name || '—'} />
              <DetailRow label="Rule ID" value={selectedEvent.rule_id || '—'} />
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">
                Raw Log
              </div>
              <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words text-xs text-slate-200">
                {selectedEvent.raw_log || '—'}
              </pre>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="text-[11px] uppercase tracking-wide text-slate-400">
                AI Triage Notes
              </div>
              <p className="mt-2 whitespace-pre-wrap text-sm text-slate-200">
                {selectedEvent.ai_triage_notes || 'No AI triage notes available.'}
              </p>
            </div>
          </div>
        )}
      </aside>
    </div>
  )
}