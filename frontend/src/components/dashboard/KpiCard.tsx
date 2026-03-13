import { memo, type ReactNode } from 'react'

type Tone = 'default' | 'critical' | 'high' | 'warning' | 'success' | 'info'

type TrendDirection = 'up' | 'down' | 'neutral'

export interface KpiCardProps {
  title: string
  value: string | number
  subtitle?: string
  helperText?: string
  badge?: string
  icon?: ReactNode
  tone?: Tone
  trend?: {
    value: string
    direction?: TrendDirection
    label?: string
  }
  loading?: boolean
  compact?: boolean
  className?: string
}

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function formatValue(value: string | number) {
  if (typeof value === 'number') {
    return new Intl.NumberFormat().format(value)
  }

  return value
}

function toneStyles(tone: Tone) {
  switch (tone) {
    case 'critical':
      return {
        accent: 'bg-rose-500',
        glow: 'shadow-[0_0_24px_rgba(244,63,94,0.28)]',
        border: 'border-rose-500/20',
        badge: 'border-rose-500/20 bg-rose-500/10 text-rose-200',
        icon: 'border-rose-500/20 bg-rose-500/10 text-rose-200',
      }
    case 'high':
      return {
        accent: 'bg-orange-500',
        glow: 'shadow-[0_0_24px_rgba(249,115,22,0.24)]',
        border: 'border-orange-500/20',
        badge: 'border-orange-500/20 bg-orange-500/10 text-orange-200',
        icon: 'border-orange-500/20 bg-orange-500/10 text-orange-200',
      }
    case 'warning':
      return {
        accent: 'bg-amber-400',
        glow: 'shadow-[0_0_24px_rgba(250,204,21,0.2)]',
        border: 'border-amber-500/20',
        badge: 'border-amber-500/20 bg-amber-500/10 text-amber-200',
        icon: 'border-amber-500/20 bg-amber-500/10 text-amber-100',
      }
    case 'success':
      return {
        accent: 'bg-emerald-400',
        glow: 'shadow-[0_0_24px_rgba(52,211,153,0.18)]',
        border: 'border-emerald-500/20',
        badge: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200',
        icon: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200',
      }
    case 'info':
      return {
        accent: 'bg-cyan-400',
        glow: 'shadow-[0_0_24px_rgba(34,211,238,0.22)]',
        border: 'border-cyan-500/20',
        badge: 'border-cyan-500/20 bg-cyan-500/10 text-cyan-200',
        icon: 'border-cyan-500/20 bg-cyan-500/10 text-cyan-200',
      }
    default:
      return {
        accent: 'bg-slate-500',
        glow: 'shadow-[0_0_18px_rgba(148,163,184,0.12)]',
        border: 'border-slate-800',
        badge: 'border-slate-700 bg-slate-800/80 text-slate-300',
        icon: 'border-slate-700 bg-slate-800/80 text-slate-200',
      }
  }
}

function trendStyles(direction: TrendDirection = 'neutral') {
  switch (direction) {
    case 'up':
      return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
    case 'down':
      return 'border-rose-500/20 bg-rose-500/10 text-rose-300'
    default:
      return 'border-slate-700 bg-slate-800/80 text-slate-300'
  }
}

function trendArrow(direction: TrendDirection = 'neutral') {
  switch (direction) {
    case 'up':
      return '↑'
    case 'down':
      return '↓'
    default:
      return '•'
  }
}

function Skeleton({ compact = false }: { compact?: boolean }) {
  return (
    <div
      className={cx(
        'animate-pulse rounded-2xl border border-slate-800 bg-slate-900/70 p-5',
        compact && 'p-4',
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="h-3 w-24 rounded bg-slate-800" />
          <div className="mt-4 h-10 w-32 rounded bg-slate-800" />
          <div className="mt-3 h-3 w-40 rounded bg-slate-800" />
        </div>
        <div className="h-11 w-11 rounded-2xl bg-slate-800" />
      </div>
      <div className="mt-5 flex items-center gap-2">
        <div className="h-6 w-20 rounded-full bg-slate-800" />
        <div className="h-3 w-24 rounded bg-slate-800" />
      </div>
    </div>
  )
}

function KpiCardComponent({
  title,
  value,
  subtitle,
  helperText,
  badge,
  icon,
  tone = 'default',
  trend,
  loading = false,
  compact = false,
  className,
}: KpiCardProps) {
  if (loading) {
    return <Skeleton compact={compact} />
  }

  const styles = toneStyles(tone)

  return (
    <article
      className={cx(
        'group relative overflow-hidden rounded-2xl border bg-slate-900/70 p-5 transition',
        'shadow-lg shadow-black/20 hover:border-slate-700 hover:bg-slate-900/85',
        styles.border,
        styles.glow,
        compact && 'p-4',
        className,
      )}
    >
      <div
        className={cx(
          'absolute inset-x-0 top-0 h-[2px] opacity-90',
          styles.accent,
        )}
      />

      <div className="absolute right-0 top-0 h-28 w-28 translate-x-8 -translate-y-8 rounded-full bg-slate-800/20 blur-2xl transition group-hover:scale-110" />

      <div className="relative flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
              {title}
            </p>

            {badge && (
              <span
                className={cx(
                  'rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.16em]',
                  styles.badge,
                )}
              >
                {badge}
              </span>
            )}
          </div>

          <div className={cx('mt-4', compact && 'mt-3')}>
            <div className="text-3xl font-semibold tracking-tight text-slate-50 sm:text-4xl">
              {formatValue(value)}
            </div>

            {subtitle && (
              <p className="mt-2 text-sm leading-6 text-slate-400">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <div
          className={cx(
            'inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border text-sm font-semibold',
            styles.icon,
          )}
          aria-hidden="true"
        >
          {icon ?? title.slice(0, 1)}
        </div>
      </div>

      {(trend || helperText) && (
        <div className={cx('relative mt-5 flex flex-wrap items-center gap-2', compact && 'mt-4')}>
          {trend && (
            <span
              className={cx(
                'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-semibold tracking-wide',
                trendStyles(trend.direction),
              )}
            >
              <span>{trendArrow(trend.direction)}</span>
              <span>{trend.value}</span>
            </span>
          )}

          {trend?.label && (
            <span className="text-xs text-slate-500">{trend.label}</span>
          )}

          {!trend?.label && helperText && (
            <span className="text-xs text-slate-500">{helperText}</span>
          )}
        </div>
      )}

      {trend?.label && helperText && (
        <p className="relative mt-3 text-xs leading-5 text-slate-500">
          {helperText}
        </p>
      )}
    </article>
  )
}

const KpiCard = memo(KpiCardComponent)
export default KpiCard