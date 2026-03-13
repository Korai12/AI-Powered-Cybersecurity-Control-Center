import { useEffect, useMemo, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { shallow } from 'zustand/shallow'

import {
  getDashboardSummary,
  getEvent,
  getEventStats,
  listEvents,
  type DashboardSummaryResponse,
  type EventRecord,
  type EventStatsResponse,
  type EventsListResponse,
} from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import {
  getEventQueryParamsFromFilters,
  useEventsStore,
} from '@/store/events'
import { useWebSocket } from '@/hooks/useWebSocket'

const DASHBOARD_SUMMARY_QUERY_KEY = ['dashboard', 'summary'] as const
const EVENT_STATS_QUERY_KEY = ['events', 'stats'] as const
const EVENTS_LIST_QUERY_KEY = ['events', 'list'] as const
const GEO_EVENTS_QUERY_KEY = ['events', 'geo'] as const
const EVENT_DETAIL_QUERY_KEY = ['events', 'detail'] as const

const LIVE_INVALIDATION_DEBOUNCE_MS = 1500

type GeoThreatEventsOptions = {
  enabled?: boolean
  severity?: string
  limit?: number
  timeRange?: string
}

function useLiveInvalidationScheduler() {
  const queryClient = useQueryClient()
  const timerRef = useRef<number | null>(null)

  return () => {
    if (timerRef.current !== null) {
      return
    }

    timerRef.current = window.setTimeout(() => {
      timerRef.current = null

      void queryClient.invalidateQueries({
        queryKey: [...DASHBOARD_SUMMARY_QUERY_KEY],
      })
      void queryClient.invalidateQueries({
        queryKey: [...EVENT_STATS_QUERY_KEY],
      })
      void queryClient.invalidateQueries({
        queryKey: [...EVENTS_LIST_QUERY_KEY],
      })
      void queryClient.invalidateQueries({
        queryKey: [...GEO_EVENTS_QUERY_KEY],
      })
    }, LIVE_INVALIDATION_DEBOUNCE_MS)
  }
}

export function useDashboardSummary(hours = 24, enabled = true) {
  return useQuery<DashboardSummaryResponse>({
    queryKey: [...DASHBOARD_SUMMARY_QUERY_KEY, hours],
    queryFn: () => getDashboardSummary({ hours }),
    enabled,
    staleTime: 30_000,
    refetchInterval: 30_000,
  })
}

export function useDashboardEventStats(
  timeRange = '24h',
  enabled = true,
) {
  return useQuery<EventStatsResponse>({
    queryKey: [...EVENT_STATS_QUERY_KEY, timeRange],
    queryFn: () => getEventStats({ time_range: timeRange }),
    enabled,
    staleTime: 20_000,
    refetchInterval: 30_000,
  })
}

export function useGeoThreatEvents(options: GeoThreatEventsOptions = {}) {
  const {
    enabled = true,
    severity = 'HIGH,CRITICAL',
    limit = 200,
    timeRange = '24h',
  } = options

  return useQuery<EventsListResponse>({
    queryKey: [...GEO_EVENTS_QUERY_KEY, severity, limit, timeRange],
    queryFn: () =>
      listEvents({
        geo: true,
        severity,
        limit,
        time_range: timeRange,
      }),
    enabled,
    staleTime: 20_000,
    refetchInterval: 30_000,
  })
}

export function useEventDetails(
  eventId?: string | null,
  enabled = true,
) {
  return useQuery<EventRecord>({
    queryKey: [...EVENT_DETAIL_QUERY_KEY, eventId],
    queryFn: () => getEvent(eventId as string),
    enabled: Boolean(eventId) && enabled,
    staleTime: 15_000,
  })
}

export function useLiveEventsSocket(enabled = true) {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  const {
    applyLiveMessage,
    setConnectionState,
    setSocketError,
  } = useEventsStore(
    (state) => ({
      applyLiveMessage: state.applyLiveMessage,
      setConnectionState: state.setConnectionState,
      setSocketError: state.setSocketError,
    }),
    shallow,
  )

  const scheduleInvalidation = useLiveInvalidationScheduler()

  const socket = useWebSocket<Record<string, unknown>>({
    path: '/ws/events',
    enabled: enabled && isAuthenticated,
    reconnect: true,
    parseJson: true,
    onOpen: () => {
      setConnectionState('open')
      setSocketError(null)
    },
    onMessage: (message) => {
      applyLiveMessage(message)
      scheduleInvalidation()
    },
    onClose: () => {
      setConnectionState('closed')
    },
    onError: () => {
      setConnectionState('error')
      setSocketError('WebSocket connection error')
    },
  })

  useEffect(() => {
    if (socket.connectionState === 'connecting') {
      setConnectionState('connecting')
    } else if (socket.connectionState === 'idle') {
      setConnectionState('idle')
    }
  }, [socket.connectionState, setConnectionState])

  useEffect(() => {
    setSocketError(socket.lastError)
  }, [socket.lastError, setSocketError])

  return socket
}

export function useEvents() {
  const {
    filters,
    liveFeed,
    selectedEventId,
    connectionState,
    socketError,
    unseenCount,
    setFilters,
    resetFilters,
    setSelectedEventId,
    replaceLiveFeed,
    mergeFetchedEvents,
    markAllSeen,
    clearFlash,
  } = useEventsStore(
    (state) => ({
      filters: state.filters,
      liveFeed: state.liveFeed,
      selectedEventId: state.selectedEventId,
      connectionState: state.connectionState,
      socketError: state.socketError,
      unseenCount: state.unseenCount,
      setFilters: state.setFilters,
      resetFilters: state.resetFilters,
      setSelectedEventId: state.setSelectedEventId,
      replaceLiveFeed: state.replaceLiveFeed,
      mergeFetchedEvents: state.mergeFetchedEvents,
      markAllSeen: state.markAllSeen,
      clearFlash: state.clearFlash,
    }),
    shallow,
  )

  const queryParams = useMemo(
    () => getEventQueryParamsFromFilters(filters),
    [filters],
  )

  const eventsQuery = useQuery<EventsListResponse>({
    queryKey: [...EVENTS_LIST_QUERY_KEY, queryParams],
    queryFn: () => listEvents(queryParams),
    staleTime: 15_000,
    refetchInterval: 30_000,
  })

  const summaryQuery = useDashboardSummary(24, true)
  const statsQuery = useDashboardEventStats(filters.time_range, true)
  const geoEventsQuery = useGeoThreatEvents({
    enabled: true,
    severity: 'HIGH,CRITICAL',
    limit: 200,
    timeRange: filters.time_range,
  })
  const selectedEventQuery = useEventDetails(selectedEventId, Boolean(selectedEventId))

  useLiveEventsSocket(true)

  useEffect(() => {
    const events = eventsQuery.data?.events
    if (!events) {
      return
    }

    replaceLiveFeed(events)
  }, [eventsQuery.data?.events, replaceLiveFeed])

  useEffect(() => {
    const latestEvents = summaryQuery.data?.latest_events
    if (!latestEvents || latestEvents.length === 0) {
      return
    }

    mergeFetchedEvents(latestEvents)
  }, [summaryQuery.data?.latest_events, mergeFetchedEvents])

  const chartData = useMemo(
    () => statsQuery.data?.severity_trend ?? summaryQuery.data?.severity_trend ?? [],
    [statsQuery.data?.severity_trend, summaryQuery.data?.severity_trend],
  )

  const distributionData = useMemo(
    () =>
      statsQuery.data?.event_type_distribution ??
      summaryQuery.data?.event_type_distribution ??
      [],
    [
      statsQuery.data?.event_type_distribution,
      summaryQuery.data?.event_type_distribution,
    ],
  )

  const geoEvents = useMemo(
    () => geoEventsQuery.data?.events ?? [],
    [geoEventsQuery.data?.events],
  )

  return {
    filters,
    liveFeed,
    selectedEventId,
    connectionState,
    socketError,
    unseenCount,

    setFilters,
    resetFilters,
    setSelectedEventId,
    markAllSeen,
    clearFlash,

    eventsQuery,
    summaryQuery,
    statsQuery,
    geoEventsQuery,
    selectedEventQuery,

    events: eventsQuery.data?.events ?? [],
    totalEvents: eventsQuery.data?.total ?? 0,
    kpis: summaryQuery.data?.kpis ?? null,
    baseline: summaryQuery.data?.baseline ?? null,
    anomalies: summaryQuery.data?.anomalies ?? [],
    chartData,
    distributionData,
    geoEvents,
  }
}