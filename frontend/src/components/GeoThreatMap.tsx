import { memo, useEffect, useMemo } from 'react'
import {
  CircleMarker,
  MapContainer,
  Popup,
  TileLayer,
  Tooltip,
  useMap,
} from 'react-leaflet'
import type { LatLngExpression, LatLngTuple } from 'leaflet'
import L from 'leaflet'

import type { EventRecord } from '@/lib/api'

type GeoThreatMapProps = {
  events: EventRecord[]
  isLoading?: boolean
  className?: string
  heightClassName?: string
  emptyMessage?: string
}

type LocationAggregate = {
  key: string
  lat: number
  lon: number
  country: string
  city: string
  count: number
  topSeverity: string
  topEventType: string
  averageAbuseScore: number | null
  maxSeverityScore: number | null
  events: EventRecord[]
}

const DEFAULT_CENTER: LatLngTuple = [20, 0]
const DEFAULT_ZOOM = 2

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function severityRank(severity?: string | null) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 5
    case 'HIGH':
      return 4
    case 'MEDIUM':
      return 3
    case 'LOW':
      return 2
    case 'INFO':
      return 1
    default:
      return 0
  }
}

function severityColor(severity?: string | null) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return '#ef4444'
    case 'HIGH':
      return '#f97316'
    case 'MEDIUM':
      return '#facc15'
    case 'LOW':
      return '#38bdf8'
    default:
      return '#94a3b8'
  }
}

function formatValue(value?: string | number | null) {
  if (value === null || value === undefined || value === '') return '—'
  return String(value)
}

function markerRadius(count: number) {
  return Math.max(8, Math.min(28, 8 + count * 2))
}

function coerceNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null
  const num = Number(value)
  return Number.isFinite(num) ? num : null
}

function topByFrequency(values: Array<string | null | undefined>, fallback = 'unknown') {
  const counts = new Map<string, number>()

  for (const value of values) {
    const key = (value || '').trim() || fallback
    counts.set(key, (counts.get(key) || 0) + 1)
  }

  let winner = fallback
  let winnerCount = -1

  for (const [key, count] of counts.entries()) {
    if (count > winnerCount) {
      winner = key
      winnerCount = count
    }
  }

  return winner
}

function aggregateEvents(events: EventRecord[]): LocationAggregate[] {
  const groups = new Map<string, LocationAggregate>()

  for (const event of events) {
    const lat = coerceNumber(event.geo_lat)
    const lon = coerceNumber(event.geo_lon)

    if (lat === null || lon === null) {
      continue
    }

    const key = `${lat.toFixed(4)},${lon.toFixed(4)}`
    const existing = groups.get(key)

    if (!existing) {
      groups.set(key, {
        key,
        lat,
        lon,
        country: event.geo_country || 'Unknown country',
        city: event.geo_city || 'Unknown city',
        count: 1,
        topSeverity: event.severity || 'INFO',
        topEventType: event.event_type || 'unknown',
        averageAbuseScore:
          typeof event.abuse_score === 'number' ? event.abuse_score : null,
        maxSeverityScore:
          typeof event.severity_score === 'number' ? event.severity_score : null,
        events: [event],
      })
      continue
    }

    existing.count += 1
    existing.events.push(event)

    if (severityRank(event.severity) > severityRank(existing.topSeverity)) {
      existing.topSeverity = event.severity || existing.topSeverity
    }

    existing.country = existing.country || event.geo_country || 'Unknown country'
    existing.city = existing.city || event.geo_city || 'Unknown city'

    if (
      typeof event.severity_score === 'number' &&
      (existing.maxSeverityScore === null || event.severity_score > existing.maxSeverityScore)
    ) {
      existing.maxSeverityScore = event.severity_score
    }

    if (typeof event.abuse_score === 'number') {
      const scoredEvents = existing.events.filter(
        (item) => typeof item.abuse_score === 'number',
      )
      const total = scoredEvents.reduce(
        (sum, item) => sum + Number(item.abuse_score || 0),
        0,
      )
      existing.averageAbuseScore = Number((total / scoredEvents.length).toFixed(1))
    }
  }

  const aggregates = Array.from(groups.values()).map((group) => ({
    ...group,
    topEventType: topByFrequency(group.events.map((event) => event.event_type), 'unknown'),
  }))

  return aggregates.sort((a, b) => {
    const severityDiff = severityRank(b.topSeverity) - severityRank(a.topSeverity)
    if (severityDiff !== 0) return severityDiff
    return b.count - a.count
  })
}

function FitBoundsController({ locations }: { locations: LocationAggregate[] }) {
  const map = useMap()

  useEffect(() => {
    if (locations.length === 0) {
      map.setView(DEFAULT_CENTER, DEFAULT_ZOOM)
      return
    }

    if (locations.length === 1) {
      map.setView([locations[0].lat, locations[0].lon], 4)
      return
    }

    const bounds = L.latLngBounds(
      locations.map((location) => [location.lat, location.lon] as LatLngTuple),
    )

    map.fitBounds(bounds, {
      padding: [40, 40],
      maxZoom: 5,
    })
  }, [locations, map])

  return null
}

function GeoThreatMapComponent({
  events,
  isLoading = false,
  className,
  heightClassName = 'h-[460px]',
  emptyMessage = 'No geo-enriched events are currently available for the selected dashboard window.',
}: GeoThreatMapProps) {
  const locations = useMemo(() => aggregateEvents(events), [events])

  const totals = useMemo(() => {
    const totalEvents = locations.reduce((sum, item) => sum + item.count, 0)
    const criticalOrigins = locations.filter(
      (item) => (item.topSeverity || '').toUpperCase() === 'CRITICAL',
    ).length

    return {
      origins: locations.length,
      totalEvents,
      criticalOrigins,
    }
  }, [locations])

  const center: LatLngExpression = useMemo(() => {
    if (locations.length === 0) return DEFAULT_CENTER
    return [locations[0].lat, locations[0].lon]
  }, [locations])

  return (
    <section
      className={cx(
        'rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg shadow-black/20',
        className,
      )}
    >
      <div className="flex flex-col gap-3 border-b border-slate-800 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
            Geographic threat visibility
          </div>
          <h3 className="mt-1 text-lg font-semibold text-slate-50">
            Geo Threat Map
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            Leaflet map of geo-enriched events using real <span className="font-mono">geo_lat</span> and <span className="font-mono">geo_lon</span> values, grouped by origin and colored by highest observed severity.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-2 text-xs">
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
            <div className="text-slate-500">Origins</div>
            <div className="mt-1 font-semibold text-slate-100">{totals.origins}</div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
            <div className="text-slate-500">Mapped events</div>
            <div className="mt-1 font-semibold text-slate-100">{totals.totalEvents}</div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
            <div className="text-slate-500">Critical origins</div>
            <div className="mt-1 font-semibold text-slate-100">{totals.criticalOrigins}</div>
          </div>
        </div>
      </div>

      <div className="border-b border-slate-800 px-5 py-3">
        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
            <span>CRITICAL</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-orange-500" />
            <span>HIGH</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-yellow-400" />
            <span>MEDIUM</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400" />
            <span>LOW / INFO</span>
          </div>
          <div className="text-slate-500">
            Marker radius increases with event count from the same origin.
          </div>
        </div>
      </div>

      <div className="p-4">
        {isLoading && locations.length === 0 ? (
          <div className={cx(heightClassName, 'animate-pulse rounded-2xl border border-slate-800 bg-slate-950/60')} />
        ) : locations.length === 0 ? (
          <div className={cx(heightClassName, 'flex items-center justify-center rounded-2xl border border-slate-800 bg-slate-950/60 p-6 text-center')}>
            <div>
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900 text-slate-400">
                🌍
              </div>
              <h4 className="mt-4 text-base font-semibold text-slate-100">
                Geo data not available
              </h4>
              <p className="mt-2 max-w-lg text-sm leading-6 text-slate-400">
                {emptyMessage}
              </p>
            </div>
          </div>
        ) : (
          <div className={cx(heightClassName, 'overflow-hidden rounded-2xl border border-slate-800')}>
            <MapContainer
              center={center}
              zoom={DEFAULT_ZOOM}
              scrollWheelZoom
              worldCopyJump
              className="h-full w-full"
            >
              <TileLayer
                attribution='&copy; OpenStreetMap contributors &copy; CARTO'
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              />

              <FitBoundsController locations={locations} />

              {locations.map((location) => {
                const color = severityColor(location.topSeverity)

                return (
                  <CircleMarker
                    key={location.key}
                    center={[location.lat, location.lon]}
                    radius={markerRadius(location.count)}
                    pathOptions={{
                      color,
                      fillColor: color,
                      fillOpacity: 0.45,
                      weight: 2,
                    }}
                  >
                    <Tooltip direction="top" offset={[0, -4]} opacity={0.95}>
                      <div className="text-xs">
                        <div className="font-semibold">
                          {location.city}, {location.country}
                        </div>
                        <div>{location.count} event{location.count === 1 ? '' : 's'}</div>
                        <div>Top type: {location.topEventType}</div>
                      </div>
                    </Tooltip>

                    <Popup>
                      <div className="min-w-[220px] text-sm text-slate-900">
                        <div className="mb-2 text-base font-semibold">
                          {location.city}, {location.country}
                        </div>

                        <div className="space-y-1">
                          <div>
                            <span className="font-medium">Highest severity:</span>{' '}
                            {formatValue(location.topSeverity)}
                          </div>
                          <div>
                            <span className="font-medium">Event count:</span>{' '}
                            {location.count}
                          </div>
                          <div>
                            <span className="font-medium">Top attack type:</span>{' '}
                            {formatValue(location.topEventType)}
                          </div>
                          <div>
                            <span className="font-medium">Avg. abuse score:</span>{' '}
                            {location.averageAbuseScore ?? '—'}
                          </div>
                          <div>
                            <span className="font-medium">Max severity score:</span>{' '}
                            {location.maxSeverityScore ?? '—'}
                          </div>
                          <div>
                            <span className="font-medium">Coordinates:</span>{' '}
                            {location.lat.toFixed(3)}, {location.lon.toFixed(3)}
                          </div>
                        </div>

                        <div className="mt-3 border-t border-slate-300 pt-2">
                          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                            Sample events
                          </div>
                          <div className="space-y-1 text-xs">
                            {location.events.slice(0, 3).map((event) => (
                              <div key={event.id} className="rounded-lg bg-slate-100 px-2 py-1">
                                <div className="font-medium">
                                  {event.event_type || 'unknown'} · {event.severity || '—'}
                                </div>
                                <div className="text-slate-600">
                                  {event.src_ip || '—'} → {event.dst_ip || '—'}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </Popup>
                  </CircleMarker>
                )
              })}
            </MapContainer>
          </div>
        )}
      </div>
    </section>
  )
}

const GeoThreatMap = memo(GeoThreatMapComponent)
export default GeoThreatMap