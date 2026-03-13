import { useEffect, type ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { shallow } from 'zustand/shallow'

import { useAuth } from '@/hooks/useAuth'
import { useEventsStore } from '@/store/events'
import { getPageFromPathname, useUiStore } from '@/store/ui'

type LayoutProps = {
  children: ReactNode
}

type NavItem = {
  label: string
  to: string
  page: ReturnType<typeof getPageFromPathname>
  badge?: string
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', to: '/', page: 'dashboard' },
  { label: 'Events', to: '/events', page: 'events' },
  { label: 'Incidents', to: '/incidents', page: 'incidents' },
  { label: 'Copilot Chat', to: '/chat', page: 'chat' },
  { label: 'Threat Hunt', to: '/hunt', page: 'hunt' },
  { label: 'MITRE Heatmap', to: '/mitre', page: 'mitre' },
  { label: 'Actions Queue', to: '/actions', page: 'actions' },
  { label: 'Reports', to: '/reports', page: 'reports' },
  { label: 'Executive View', to: '/ciso', page: 'ciso', badge: 'Mgr' },
  { label: 'Settings', to: '/settings', page: 'settings' },
]

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function statusTone(state: 'idle' | 'connecting' | 'open' | 'closed' | 'error') {
  switch (state) {
    case 'open':
      return 'bg-emerald-500'
    case 'connecting':
      return 'bg-amber-400'
    case 'error':
      return 'bg-rose-500'
    case 'closed':
      return 'bg-slate-500'
    default:
      return 'bg-slate-500'
  }
}

function statusLabel(state: 'idle' | 'connecting' | 'open' | 'closed' | 'error') {
  switch (state) {
    case 'open':
      return 'Live'
    case 'connecting':
      return 'Connecting'
    case 'error':
      return 'WS Error'
    case 'closed':
      return 'Closed'
    default:
      return 'Idle'
  }
}

function pageTitle(pathname: string) {
  const page = getPageFromPathname(pathname)

  switch (page) {
    case 'dashboard':
      return 'Unified Security Dashboard'
    case 'events':
      return 'Event Feed'
    case 'incidents':
      return 'Incident Management'
    case 'chat':
      return 'Analyst Copilot'
    case 'hunt':
      return 'Threat Hunting Workspace'
    case 'mitre':
      return 'MITRE ATT&CK Heatmap'
    case 'actions':
      return 'Response Actions Queue'
    case 'reports':
      return 'Reporting'
    case 'incident-graph':
      return 'Entity Relationship Graph'
    case 'ciso':
      return 'Executive Summary View'
    case 'settings':
      return 'Settings'
    default:
      return 'AI-Powered Cybersecurity Control Center'
  }
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const auth = useAuth()

  const {
    activePage,
    sidebarCollapsed,
    audioEnabled,
    syncActivePageFromPathname,
    toggleSidebar,
    toggleAudio,
    applyUserPreferences,
  } = useUiStore(
    (state) => ({
      activePage: state.activePage,
      sidebarCollapsed: state.sidebarCollapsed,
      audioEnabled: state.audioEnabled,
      syncActivePageFromPathname: state.syncActivePageFromPathname,
      toggleSidebar: state.toggleSidebar,
      toggleAudio: state.toggleAudio,
      applyUserPreferences: state.applyUserPreferences,
    }),
    shallow,
  )

  const { connectionState, unseenCount } = useEventsStore(
    (state) => ({
      connectionState: state.connectionState,
      unseenCount: state.unseenCount,
    }),
    shallow,
  )

  useEffect(() => {
    syncActivePageFromPathname(location.pathname)
  }, [location.pathname, syncActivePageFromPathname])

  useEffect(() => {
    applyUserPreferences(auth.user?.preferences as Record<string, unknown> | null | undefined)
  }, [auth.user?.preferences, applyUserPreferences])

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="flex min-h-screen">
        <aside
          className={cx(
            'border-r border-slate-800/80 bg-slate-950/95 transition-all duration-300',
            sidebarCollapsed ? 'w-[92px]' : 'w-[280px]',
          )}
        >
          <div className="flex h-full flex-col">
            <div className="border-b border-slate-800/80 px-4 py-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <div className="h-3 w-3 rounded-full bg-cyan-400 shadow-[0_0_18px_rgba(34,211,238,0.8)]" />
                    {!sidebarCollapsed && (
                      <span className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-300">
                        ACCC
                      </span>
                    )}
                  </div>

                  {!sidebarCollapsed && (
                    <>
                      <h1 className="mt-3 text-sm font-semibold text-slate-100">
                        Cybersecurity Control Center
                      </h1>
                      <p className="mt-1 text-xs leading-5 text-slate-400">
                        Real-time SOC dashboard, AI triage, live event streaming, and analyst workflows.
                      </p>
                    </>
                  )}
                </div>

                <button
                  type="button"
                  onClick={toggleSidebar}
                  className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-slate-800 bg-slate-900 text-slate-300 transition hover:border-slate-700 hover:text-white"
                  aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                  title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                >
                  {sidebarCollapsed ? '»' : '«'}
                </button>
              </div>
            </div>

            <nav className="flex-1 px-3 py-4">
              <div className="mb-3 px-2 text-[10px] font-semibold uppercase tracking-[0.24em] text-slate-500">
                {!sidebarCollapsed ? 'Operations' : 'Nav'}
              </div>

              <div className="space-y-1">
                {NAV_ITEMS.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      cx(
                        'group flex items-center gap-3 rounded-2xl border px-3 py-3 text-sm transition',
                        isActive || activePage === item.page
                          ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200 shadow-[0_0_0_1px_rgba(34,211,238,0.08)]'
                          : 'border-transparent text-slate-400 hover:border-slate-800 hover:bg-slate-900 hover:text-slate-100',
                      )
                    }
                    title={sidebarCollapsed ? item.label : undefined}
                  >
                    <span
                      className={cx(
                        'inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border text-xs font-semibold',
                        activePage === item.page
                          ? 'border-cyan-400/20 bg-cyan-400/10 text-cyan-200'
                          : 'border-slate-800 bg-slate-900 text-slate-400 group-hover:text-slate-200',
                      )}
                    >
                      {item.label.slice(0, 1)}
                    </span>

                    {!sidebarCollapsed && (
                      <div className="flex min-w-0 flex-1 items-center justify-between gap-2">
                        <span className="truncate">{item.label}</span>
                        {item.badge && (
                          <span className="rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-300">
                            {item.badge}
                          </span>
                        )}
                      </div>
                    )}
                  </NavLink>
                ))}
              </div>
            </nav>

            <div className="border-t border-slate-800/80 p-3">
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-3">
                <div className="flex items-center gap-2">
                  <span className={cx('h-2.5 w-2.5 rounded-full', statusTone(connectionState))} />
                  {!sidebarCollapsed && (
                    <span className="text-xs font-medium text-slate-300">
                      Event stream: {statusLabel(connectionState)}
                    </span>
                  )}
                </div>

                {!sidebarCollapsed && (
                  <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
                      <div className="text-slate-500">Audio</div>
                      <div className="mt-1 font-semibold text-slate-100">
                        {audioEnabled ? 'Enabled' : 'Muted'}
                      </div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
                      <div className="text-slate-500">Unseen</div>
                      <div className="mt-1 font-semibold text-slate-100">{unseenCount}</div>
                    </div>
                  </div>
                )}

                {!sidebarCollapsed && (
                  <button
                    type="button"
                    onClick={toggleAudio}
                    className="mt-3 inline-flex w-full items-center justify-center rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-700 hover:text-white"
                  >
                    {audioEnabled ? 'Mute critical audio' : 'Enable critical audio'}
                  </button>
                )}
              </div>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 border-b border-slate-800/80 bg-slate-950/85 backdrop-blur">
            <div className="flex flex-col gap-4 px-6 py-5 lg:flex-row lg:items-center lg:justify-between">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] text-cyan-300">
                    SOC Console
                  </span>
                  <span className="rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] text-slate-400">
                    {statusLabel(connectionState)}
                  </span>
                </div>

                <h2 className="mt-3 text-2xl font-semibold text-slate-50">
                  {pageTitle(location.pathname)}
                </h2>

                <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                  Authenticated analyst workspace with live events, protected routes, dashboard telemetry, and
                  real-time streaming from the ACCC backend.
                </p>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                    Analyst
                  </div>
                  <div className="mt-1 text-sm font-semibold text-slate-100">
                    {auth.displayName || 'Authenticated User'}
                  </div>
                  <div className="mt-1 text-xs text-slate-400">
                    {auth.role ? auth.role.replace(/_/g, ' ') : 'role unavailable'}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => void auth.logout()}
                  className="inline-flex items-center justify-center rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 text-sm font-medium text-slate-300 transition hover:border-rose-500/30 hover:bg-rose-500/10 hover:text-rose-200"
                >
                  Sign out
                </button>
              </div>
            </div>
          </header>

          <main className="flex-1 px-6 py-6">
            <div className="mx-auto w-full max-w-[1600px]">{children}</div>
          </main>
        </div>
      </div>
    </div>
  )
}