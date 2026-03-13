import { create } from 'zustand'

import type { EventQueryParams, EventRecord, LiveEventMessage } from '@/lib/api'

type ConnectionState = 'idle' | 'connecting' | 'open' | 'closed' | 'error'

export interface EventFilters {
  severity?: string
  event_type?: string
  triage_status?: string
  source?: string
  time_range: string
  geo: boolean
  limit: number
  offset: number
}

export interface LiveEventItem extends EventRecord {
  received_at: string
  update_type?: string
  is_live: boolean
  is_placeholder: boolean
  flash: boolean
}

type EventsState = {
  liveFeed: LiveEventItem[]
  filters: EventFilters
  selectedEventId: string | null

  connectionState: ConnectionState
  socketError: string | null
  lastMessageAt: string | null
  unseenCount: number

  setFilters: (patch: Partial<EventFilters>) => void
  resetFilters: () => void

  setSelectedEventId: (eventId: string | null) => void

  setConnectionState: (state: ConnectionState) => void
  setSocketError: (message: string | null) => void
  markAllSeen: () => void

  replaceLiveFeed: (events: EventRecord[]) => void
  mergeFetchedEvents: (events: EventRecord[]) => void
  mergeFetchedEvent: (event: EventRecord) => void
  applyLiveMessage: (message: LiveEventMessage | EventRecord | Record<string, unknown>) => void
  clearFlash: (eventId: string) => void
  clearLiveFeed: () => void
}

const MAX_LIVE_FEED_ITEMS = 200

const DEFAULT_FILTERS: EventFilters = {
  time_range: '24h',
  geo: false,
  limit: 50,
  offset: 0,
}

function normalizeSeverity(value?: string | null): string | undefined {
  if (!value) return undefined
  return String(value).trim().toUpperCase()
}

function normalizeString(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined
  const text = String(value).trim()
  return text || undefined
}

function normalizeNumber(value: unknown): number | null | undefined {
  if (value === null || value === undefined || value === '') return undefined
  const num = Number(value)
  return Number.isFinite(num) ? num : undefined
}

function getEventSortTimestamp(event: Partial<LiveEventItem>): number {
  const candidates = [
    event.timestamp,
    event.ingested_at,
    event.received_at,
  ]

  for (const value of candidates) {
    if (!value) continue
    const ms = Date.parse(value)
    if (!Number.isNaN(ms)) {
      return ms
    }
  }

  return 0
}

function sortFeed(events: LiveEventItem[]): LiveEventItem[] {
  return [...events].sort((a, b) => getEventSortTimestamp(b) - getEventSortTimestamp(a))
}

function trimFeed(events: LiveEventItem[]): LiveEventItem[] {
  return events.slice(0, MAX_LIVE_FEED_ITEMS)
}

function toLiveEventItem(event: Partial<EventRecord> & { id: string }, options?: {
  receivedAt?: string
  updateType?: string
  isPlaceholder?: boolean
  flash?: boolean
}): LiveEventItem {
  return {
    id: event.id,
    timestamp: event.timestamp ?? null,
    ingested_at: event.ingested_at ?? null,
    source_format: event.source_format ?? null,
    source_identifier: event.source_identifier ?? null,
    event_type: event.event_type ?? null,
    severity: normalizeSeverity(event.severity) ?? null,
    raw_log: event.raw_log ?? null,
    src_ip: event.src_ip ?? null,
    dst_ip: event.dst_ip ?? null,
    src_port: event.src_port ?? null,
    dst_port: event.dst_port ?? null,
    protocol: event.protocol ?? null,
    username: event.username ?? null,
    hostname: event.hostname ?? null,
    process_name: event.process_name ?? null,
    file_hash: event.file_hash ?? null,
    action: event.action ?? null,
    rule_id: event.rule_id ?? null,
    geo_country: event.geo_country ?? null,
    geo_city: event.geo_city ?? null,
    geo_lat: event.geo_lat ?? null,
    geo_lon: event.geo_lon ?? null,
    abuse_score: event.abuse_score ?? null,
    relevant_cves: event.relevant_cves ?? [],
    mitre_tactic: event.mitre_tactic ?? null,
    mitre_technique: event.mitre_technique ?? null,
    severity_score: event.severity_score ?? null,
    is_false_positive: event.is_false_positive ?? null,
    incident_id: event.incident_id ?? null,
    triage_status: event.triage_status ?? null,
    ai_triage_notes: event.ai_triage_notes ?? null,
    tags: event.tags ?? [],
    received_at: options?.receivedAt ?? new Date().toISOString(),
    update_type: options?.updateType,
    is_live: true,
    is_placeholder: options?.isPlaceholder ?? false,
    flash: options?.flash ?? true,
  }
}

function mergeEvent(existing: LiveEventItem | undefined, incoming: LiveEventItem): LiveEventItem {
  if (!existing) {
    return incoming
  }

  return {
    ...existing,
    ...incoming,
    severity: normalizeSeverity(incoming.severity) ?? existing.severity ?? null,
    relevant_cves:
      incoming.relevant_cves && incoming.relevant_cves.length > 0
        ? incoming.relevant_cves
        : existing.relevant_cves ?? [],
    tags:
      incoming.tags && incoming.tags.length > 0
        ? incoming.tags
        : existing.tags ?? [],
    received_at: incoming.received_at || existing.received_at,
    update_type: incoming.update_type ?? existing.update_type,
    is_live: true,
    is_placeholder: existing.is_placeholder && !incoming.is_placeholder ? false : incoming.is_placeholder,
    flash: true,
  }
}

function upsertIntoFeed(feed: LiveEventItem[], incoming: LiveEventItem): LiveEventItem[] {
  const index = feed.findIndex((item) => item.id === incoming.id)

  if (index === -1) {
    return trimFeed(sortFeed([incoming, ...feed]))
  }

  const next = [...feed]
  next[index] = mergeEvent(next[index], incoming)
  return trimFeed(sortFeed(next))
}

function eventFromLiveMessage(message: LiveEventMessage | Record<string, unknown>): LiveEventItem | null {
  const eventId = normalizeString(message.event_id ?? message.id)
  if (!eventId) {
    return null
  }

  const receivedAt =
    normalizeString(message.published_at) ||
    normalizeString(message.received_at) ||
    new Date().toISOString()

  return toLiveEventItem(
    {
      id: eventId,
      timestamp: normalizeString(message.timestamp) ?? null,
      ingested_at: normalizeString(message.ingested_at) ?? null,
      source_identifier: normalizeString(message.source_identifier) ?? null,
      event_type: normalizeString(message.event_type) ?? null,
      severity: normalizeSeverity(normalizeString(message.severity)) ?? null,
      src_ip: normalizeString(message.src_ip) ?? null,
      dst_ip: normalizeString(message.dst_ip) ?? null,
      username: normalizeString(message.username) ?? null,
      hostname: normalizeString(message.hostname) ?? null,
      geo_country: normalizeString(message.geo_country) ?? null,
      geo_city: normalizeString(message.geo_city) ?? null,
      geo_lat: normalizeNumber(message.geo_lat) ?? null,
      geo_lon: normalizeNumber(message.geo_lon) ?? null,
      abuse_score: normalizeNumber(message.abuse_score) ?? null,
      severity_score: normalizeNumber(message.severity_score) ?? null,
      triage_status: normalizeString(message.triage_status) ?? null,
      ai_triage_notes: normalizeString(message.ai_triage_notes) ?? null,
      incident_id: normalizeString(message.incident_id) ?? null,
      relevant_cves: Array.isArray(message.relevant_cves)
        ? message.relevant_cves.map((item) => String(item))
        : [],
      tags: Array.isArray(message.tags) ? message.tags.map((item) => String(item)) : [],
    },
    {
      receivedAt,
      updateType: normalizeString(message.update_type),
      isPlaceholder:
        !('raw_log' in message) &&
        !('geo_country' in message) &&
        !('abuse_score' in message) &&
        !('severity_score' in message),
      flash: true,
    },
  )
}

function matchesFilters(event: EventRecord, filters: EventFilters): boolean {
  if (filters.severity) {
    const wanted = filters.severity
      .split(',')
      .map((value) => value.trim().toUpperCase())
      .filter(Boolean)

    if (wanted.length > 0 && !wanted.includes(normalizeSeverity(event.severity) || '')) {
      return false
    }
  }

  if (filters.event_type) {
    const wanted = filters.event_type
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)

    if (wanted.length > 0 && !wanted.includes(event.event_type || '')) {
      return false
    }
  }

  if (filters.triage_status && event.triage_status !== filters.triage_status) {
    return false
  }

  if (filters.source) {
    const source = (event.source_identifier || '').toLowerCase()
    if (!source.includes(filters.source.toLowerCase())) {
      return false
    }
  }

  if (filters.geo && (event.geo_lat == null || event.geo_lon == null)) {
    return false
  }

  return true
}

export function getEventQueryParamsFromFilters(filters: EventFilters): EventQueryParams {
  return {
    severity: filters.severity,
    event_type: filters.event_type,
    triage_status: filters.triage_status,
    source: filters.source,
    time_range: filters.time_range,
    geo: filters.geo,
    limit: filters.limit,
    offset: filters.offset,
  }
}

export const useEventsStore = create<EventsState>((set, get) => ({
  liveFeed: [],
  filters: DEFAULT_FILTERS,
  selectedEventId: null,

  connectionState: 'idle',
  socketError: null,
  lastMessageAt: null,
  unseenCount: 0,

  setFilters: (patch) =>
    set((state) => ({
      filters: {
        ...state.filters,
        ...patch,
        offset: patch.offset ?? (Object.keys(patch).some((key) => key !== 'offset') ? 0 : state.filters.offset),
      },
    })),

  resetFilters: () =>
    set({
      filters: DEFAULT_FILTERS,
    }),

  setSelectedEventId: (eventId) =>
    set({
      selectedEventId: eventId,
    }),

  setConnectionState: (stateValue) =>
    set({
      connectionState: stateValue,
      socketError: stateValue === 'open' ? null : get().socketError,
    }),

  setSocketError: (message) =>
    set({
      socketError: message,
      connectionState: message ? 'error' : get().connectionState,
    }),

  markAllSeen: () =>
    set({
      unseenCount: 0,
    }),

  replaceLiveFeed: (events) =>
    set(() => {
      const filtered = events
        .filter((event) => matchesFilters(event, get().filters))
        .map((event) =>
          toLiveEventItem(
            {
              ...event,
              id: event.id,
            },
            {
              receivedAt: event.ingested_at || event.timestamp || new Date().toISOString(),
              isPlaceholder: false,
              flash: false,
            },
          ),
        )

      return {
        liveFeed: trimFeed(sortFeed(filtered)),
      }
    }),

  mergeFetchedEvents: (events) =>
    set((state) => {
      let nextFeed = [...state.liveFeed]

      for (const event of events) {
        if (!matchesFilters(event, state.filters)) {
          continue
        }

        const incoming = toLiveEventItem(
          {
            ...event,
            id: event.id,
          },
          {
            receivedAt: event.ingested_at || event.timestamp || new Date().toISOString(),
            isPlaceholder: false,
            flash: false,
          },
        )

        nextFeed = upsertIntoFeed(nextFeed, incoming)
      }

      return { liveFeed: nextFeed }
    }),

  mergeFetchedEvent: (event) =>
    set((state) => {
      if (!matchesFilters(event, state.filters)) {
        return state
      }

      const incoming = toLiveEventItem(
        {
          ...event,
          id: event.id,
        },
        {
          receivedAt: event.ingested_at || event.timestamp || new Date().toISOString(),
          isPlaceholder: false,
          flash: false,
        },
      )

      return {
        liveFeed: upsertIntoFeed(state.liveFeed, incoming),
      }
    }),

  applyLiveMessage: (message) =>
    set((state) => {
      const asRecord = message as EventRecord
      const incoming = eventFromLiveMessage(message)

      if (!incoming) {
        return state
      }

      if (!matchesFilters(asRecord, state.filters)) {
        return {
          lastMessageAt: incoming.received_at,
        }
      }

      return {
        liveFeed: upsertIntoFeed(state.liveFeed, incoming),
        lastMessageAt: incoming.received_at,
        unseenCount: state.unseenCount + 1,
      }
    }),

  clearFlash: (eventId) =>
    set((state) => ({
      liveFeed: state.liveFeed.map((item) =>
        item.id === eventId
          ? {
              ...item,
              flash: false,
            }
          : item,
      ),
    })),

  clearLiveFeed: () =>
    set({
      liveFeed: [],
      unseenCount: 0,
      lastMessageAt: null,
    }),
}))