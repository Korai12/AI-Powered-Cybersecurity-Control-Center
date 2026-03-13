export type HttpMethod = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'

export class ApiError extends Error {
  status: number
  data: unknown

  constructor(message: string, status: number, data: unknown = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

export interface UserProfile {
  id: string
  username: string
  role: string
  display_name?: string | null
  preferences?: Record<string, unknown> | null
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  refresh_token?: string
  expires_in: number
  role: string
}

export interface RefreshResponse {
  access_token: string
  expires_in: number
}

export interface DashboardKpis {
  total_events: number
  critical_events: number
  high_events: number
  active_alerts: number
  open_incidents: number
  mean_time_to_respond_minutes: number
}

export interface SeverityTrendPoint {
  bucket: string | null
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  INFO: number
  total: number
}

export interface DistributionPoint {
  name: string
  value: number
}

export interface TopEventType {
  type: string
  count: number
}

export interface BaselineSummary {
  status?: string
  refreshed_at?: string | null
  window_hours?: number
  recent_minutes?: number
  events_scanned?: number
  entities_processed?: number
  anomalies_detected?: number
  ttl_seconds?: number
  error?: string
}

export interface BaselineAnomaly {
  entity_type: string
  entity_value: string
  recent_events: number
  total_events: number
  baseline_hourly_rate: number
  current_hourly_rate: number
  anomaly_ratio: number
  common_event_types?: Array<{ name: string; count: number }>
  common_severities?: Array<{ name: string; count: number }>
  last_seen?: string | null
}

export interface BaselineSnapshot {
  summary: BaselineSummary
  anomalies_count: number
  sample_anomalies: BaselineAnomaly[]
  sample_entities: Array<Record<string, unknown>>
}

export interface EventRecord {
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

export interface EventsListResponse {
  total: number
  limit: number
  offset: number
  events: EventRecord[]
}

export interface EventStatsResponse {
  time_range_minutes: number
  counts: {
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
    info_count: number
    pending_count: number
    false_positive_count: number
    total_count: number
  }
  top_event_types: TopEventType[]
  event_type_distribution: DistributionPoint[]
  severity_trend: SeverityTrendPoint[]
}

export interface DashboardSummaryResponse {
  window_hours: number
  kpis: DashboardKpis
  severity_trend: SeverityTrendPoint[]
  event_type_distribution: DistributionPoint[]
  latest_events: EventRecord[]
  baseline: BaselineSnapshot
  anomalies: BaselineAnomaly[]
  ws_events_path: string
}

export interface EventQueryParams {
  severity?: string
  event_type?: string
  type?: string
  triage_status?: string
  source?: string
  time_range?: string
  geo?: boolean
  limit?: number
  offset?: number
}

export interface TriageUpdatePayload {
  triage_status?: 'pending' | 'triaged' | 'escalated' | 'closed'
  is_false_positive?: boolean
  ai_triage_notes?: string
}

export interface UploadEventsResponse {
  filename?: string
  ingested: number
  failed: number
  event_ids: string[]
}

export interface LiveEventMessage {
  event_id: string
  severity?: string
  event_type?: string
  published_at?: string
  update_type?: string
}

type AuthBindings = {
  getAccessToken?: () => string | null | undefined
  refreshAccessToken?: () => Promise<string | null | undefined>
  onUnauthorized?: () => void | Promise<void>
}

type RequestOptions = {
  auth?: boolean
  retryOn401?: boolean
  signal?: AbortSignal
}

let authBindings: AuthBindings = {}
let refreshInFlight: Promise<string | null | undefined> | null = null

const RAW_API_BASE = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '')
const RAW_WS_BASE = (import.meta.env.VITE_WS_BASE_URL || '').trim().replace(/\/+$/, '')

export function configureApiAuth(bindings: AuthBindings) {
  authBindings = bindings
}

function getApiBaseUrl(): string {
  return RAW_API_BASE
}

function getWsBaseUrl(): string {
  return RAW_WS_BASE
}

function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  const base = getApiBaseUrl()

  return base ? `${base}${normalizedPath}` : normalizedPath
}

function buildWsBaseUrlFromWindow(): string {
  if (typeof window === 'undefined') {
    return 'ws://localhost'
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}`
}

export function buildWebSocketUrl(path: string, token?: string | null): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  const base = getWsBaseUrl() || buildWsBaseUrlFromWindow()
  const url = new URL(`${base}${normalizedPath}`)

  if (token) {
    url.searchParams.set('token', token)
  }

  return url.toString()
}

function isFormData(value: unknown): value is FormData {
  return typeof FormData !== 'undefined' && value instanceof FormData
}

function makeQueryString(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams()

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') {
      continue
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null && item !== '') {
          searchParams.append(key, String(item))
        }
      }
      continue
    }

    searchParams.set(key, String(value))
  }

  const qs = searchParams.toString()
  return qs ? `?${qs}` : ''
}

async function parseResponseBody(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return null
  }

  const contentType = response.headers.get('content-type') || ''

  if (contentType.includes('application/json')) {
    return response.json()
  }

  const text = await response.text()
  return text || null
}

async function maybeRefreshToken(): Promise<string | null | undefined> {
  if (!authBindings.refreshAccessToken) {
    return null
  }

  if (!refreshInFlight) {
    refreshInFlight = authBindings
      .refreshAccessToken()
      .catch(() => null)
      .finally(() => {
        refreshInFlight = null
      })
  }

  return refreshInFlight
}

function withAuthHeader(headers: Headers, token?: string | null) {
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  options: RequestOptions = {},
): Promise<T> {
  const { auth = false, retryOn401 = true, signal } = options
  const url = buildApiUrl(path)

  const headers = new Headers(init.headers || {})
  headers.set('Accept', 'application/json')

  const body = init.body
  if (body && !isFormData(body) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const token = auth ? authBindings.getAccessToken?.() ?? null : null
  if (auth) {
    withAuthHeader(headers, token)
  }

  const response = await fetch(url, {
    ...init,
    headers,
    credentials: 'include',
    signal,
  })

  if (response.ok) {
    return (await parseResponseBody(response)) as T
  }

  if (response.status === 401 && auth && retryOn401) {
    const refreshedToken = await maybeRefreshToken()

    if (refreshedToken) {
      return request<T>(path, init, { ...options, retryOn401: false })
    }

    await authBindings.onUnauthorized?.()
  }

  const errorData = await parseResponseBody(response)
  const message =
    typeof errorData === 'object' &&
    errorData !== null &&
    'detail' in errorData &&
    typeof (errorData as { detail?: unknown }).detail === 'string'
      ? (errorData as { detail: string }).detail
      : `Request failed with status ${response.status}`

  throw new ApiError(message, response.status, errorData)
}

export async function login(payload: LoginRequest): Promise<LoginResponse> {
  return request<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function refreshAccessToken(): Promise<RefreshResponse> {
  return request<RefreshResponse>('/auth/refresh', {
    method: 'POST',
  })
}

export async function logout(): Promise<void> {
  await request<void>(
    '/auth/logout',
    {
      method: 'POST',
    },
    { auth: true, retryOn401: false },
  )
}

export async function getCurrentUser(): Promise<UserProfile> {
  return request<UserProfile>('/auth/me', {}, { auth: true })
}

export async function getHealth(): Promise<unknown> {
  return request<unknown>('/health')
}

export async function getDashboardSummary(
  params: { hours?: number } = {},
): Promise<DashboardSummaryResponse> {
  const query = makeQueryString(params)
  return request<DashboardSummaryResponse>(`/api/v1/dashboard/summary${query}`, {}, { auth: true })
}

export async function listEvents(
  params: EventQueryParams = {},
): Promise<EventsListResponse> {
  const query = makeQueryString({
    severity: params.severity,
    event_type: params.event_type,
    type: params.type,
    triage_status: params.triage_status,
    source: params.source,
    time_range: params.time_range,
    geo: params.geo,
    limit: params.limit,
    offset: params.offset,
  })

  return request<EventsListResponse>(`/api/v1/events${query}`, {}, { auth: true })
}

export async function getEvent(eventId: string): Promise<EventRecord> {
  return request<EventRecord>(`/api/v1/events/${eventId}`, {}, { auth: true })
}

export async function getEventStats(
  params: { time_range?: string } = {},
): Promise<EventStatsResponse> {
  const query = makeQueryString(params)
  return request<EventStatsResponse>(`/api/v1/events/stats${query}`, {}, { auth: true })
}

export async function ingestEvent(raw_log: string): Promise<{
  event_id: string
  severity: string
  event_type: string
  triage_status: string
}> {
  return request('/api/v1/events/ingest', {
    method: 'POST',
    body: JSON.stringify({ raw_log }),
  }, { auth: true })
}

export async function ingestEventBatch(logs: string[]): Promise<UploadEventsResponse> {
  return request('/api/v1/events/ingest/batch', {
    method: 'POST',
    body: JSON.stringify({ logs }),
  }, { auth: true })
}

export async function uploadEventsFile(file: File): Promise<UploadEventsResponse> {
  const formData = new FormData()
  formData.append('file', file)

  return request<UploadEventsResponse>(
    '/api/v1/events/upload',
    {
      method: 'POST',
      body: formData,
    },
    { auth: true },
  )
}

export async function updateEventTriage(
  eventId: string,
  payload: TriageUpdatePayload,
): Promise<{ status: string; event_id: string; updated_by?: string }> {
  return request(`/api/v1/events/${eventId}/triage`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }, { auth: true })
}

export function getEventsWebSocketUrl(token?: string | null): string {
  return buildWebSocketUrl('/ws/events', token)
}

export function getChatWebSocketUrl(sessionId: string, token?: string | null): string {
  return buildWebSocketUrl(`/ws/chat/${sessionId}`, token)
}

export function getAgentWebSocketUrl(runId: string, token?: string | null): string {
  return buildWebSocketUrl(`/ws/agent/${runId}`, token)
}

export function getHuntWebSocketUrl(huntId: string, token?: string | null): string {
  return buildWebSocketUrl(`/ws/hunt/${huntId}`, token)
}

export const api = {
  login,
  refreshAccessToken,
  logout,
  getCurrentUser,
  getHealth,
  getDashboardSummary,
  listEvents,
  getEvent,
  getEventStats,
  ingestEvent,
  ingestEventBatch,
  uploadEventsFile,
  updateEventTriage,
  getEventsWebSocketUrl,
  getChatWebSocketUrl,
  getAgentWebSocketUrl,
  getHuntWebSocketUrl,
}