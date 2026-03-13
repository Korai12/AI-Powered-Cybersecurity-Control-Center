import { useEffect, useMemo, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '@/hooks/useAuth'

type LoginFormState = {
  username: string
  password: string
}

type DemoAccount = {
  username: string
  password: string
  role: string
  description: string
}

const DEMO_ACCOUNTS: DemoAccount[] = [
  {
    username: 'analyst',
    password: 'analyst123',
    role: 'analyst',
    description: 'Tier 1 analyst — core dashboard and triage demo account',
  },
  {
    username: 'senior',
    password: 'senior123',
    role: 'senior_analyst',
    description: 'Senior analyst — deeper investigation workflow account',
  },
  {
    username: 'manager',
    password: 'manager123',
    role: 'soc_manager',
    description: 'SOC manager — executive and approval-oriented account',
  },
]

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function resolveRedirectTarget(locationState: unknown): string {
  if (
    locationState &&
    typeof locationState === 'object' &&
    'from' in locationState
  ) {
    const from = (locationState as { from?: { pathname?: string } }).from
    if (from?.pathname && from.pathname !== '/login') {
      return from.pathname
    }
  }

  return '/'
}

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()

  const {
    login,
    isAuthenticated,
    isBootstrapping,
    isRefreshing,
    error,
    clearError,
  } = useAuth()

  const [form, setForm] = useState<LoginFormState>({
    username: 'analyst',
    password: 'analyst123',
  })
  const [showPassword, setShowPassword] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const redirectTo = useMemo(
    () => resolveRedirectTarget(location.state),
    [location.state],
  )

  useEffect(() => {
    return () => {
      clearError()
    }
  }, [clearError])

  useEffect(() => {
    if (isAuthenticated) {
      navigate(redirectTo, { replace: true })
    }
  }, [isAuthenticated, navigate, redirectTo])

  const updateField =
    (field: keyof LoginFormState) =>
    (event: React.ChangeEvent<HTMLInputElement>) => {
      if (error) {
        clearError()
      }

      setForm((current) => ({
        ...current,
        [field]: event.target.value,
      }))
    }

  const applyDemoAccount = (account: DemoAccount) => {
    if (error) {
      clearError()
    }

    setForm({
      username: account.username,
      password: account.password,
    })
  }

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    const username = form.username.trim()
    const password = form.password

    if (!username || !password || isSubmitting) {
      return
    }

    setIsSubmitting(true)

    try {
      await login({
        username,
        password,
      })

      navigate(redirectTo, { replace: true })
    } catch {
      // Error state is already managed by the auth store.
    } finally {
      setIsSubmitting(false)
    }
  }

  if (isBootstrapping) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center px-6">
        <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl shadow-black/30">
          <div className="mb-4 flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-400">
              ACCC
            </span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-50">
            Restoring analyst session
          </h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Checking for an active refresh session and preparing the dashboard.
          </p>
        </div>
      </div>
    )
  }

  if (isAuthenticated) {
    return <Navigate to={redirectTo} replace />
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="grid min-h-screen lg:grid-cols-[1.05fr_0.95fr]">
        <section className="relative hidden overflow-hidden border-r border-slate-800/80 bg-slate-950 lg:flex">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.15),transparent_35%),radial-gradient(circle_at_bottom_right,rgba(244,63,94,0.10),transparent_35%)]" />
          <div className="relative z-10 flex w-full flex-col justify-between p-10">
            <div>
              <div className="inline-flex items-center gap-3 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">
                <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 shadow-[0_0_14px_rgba(34,211,238,0.7)]" />
                ACCC · SOC Console
              </div>

              <h1 className="mt-8 max-w-xl text-4xl font-semibold leading-tight text-slate-50">
                AI-Powered Cybersecurity Control Center
              </h1>

              <p className="mt-5 max-w-2xl text-base leading-8 text-slate-400">
                Authenticated analyst workspace for live alert streaming, AI-assisted triage,
                geo-enriched event monitoring, and dashboard-driven incident visibility.
              </p>
            </div>

            <div className="grid gap-4">
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                  Real-time stack
                </div>
                <p className="mt-3 text-sm leading-7 text-slate-300">
                  Live event feed from <span className="font-mono text-cyan-300">/ws/events</span>,
                  dashboard charts from protected REST APIs, and enrichment-aware alert context.
                </p>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                  Phase 4 focus
                </div>
                <p className="mt-3 text-sm leading-7 text-slate-300">
                  Unified dashboard, geo threat map, live alerts, behavioral baseline output,
                  and frontend authentication wired to the real backend.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="flex items-center justify-center px-6 py-10 sm:px-8 lg:px-10">
          <div className="w-full max-w-xl">
            <div className="rounded-3xl border border-slate-800 bg-slate-900/75 p-6 shadow-2xl shadow-black/30 backdrop-blur sm:p-8">
              <div className="mb-6">
                <div className="inline-flex items-center gap-2 rounded-full border border-slate-800 bg-slate-950/80 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-slate-400 lg:hidden">
                  ACCC
                </div>

                <h2 className="mt-4 text-3xl font-semibold text-slate-50">
                  Analyst sign in
                </h2>

                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Sign in with a seeded demo account or your configured analyst credentials.
                  Access tokens stay in frontend memory and refresh happens silently through the backend session cookie.
                </p>
              </div>

              <div className="mb-6 grid gap-3">
                {DEMO_ACCOUNTS.map((account) => {
                  const isActive =
                    form.username === account.username &&
                    form.password === account.password

                  return (
                    <button
                      key={account.username}
                      type="button"
                      onClick={() => applyDemoAccount(account)}
                      className={cx(
                        'rounded-2xl border p-4 text-left transition',
                        isActive
                          ? 'border-cyan-500/30 bg-cyan-500/10'
                          : 'border-slate-800 bg-slate-950/55 hover:border-slate-700 hover:bg-slate-950/85',
                      )}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="text-sm font-semibold text-slate-100">
                            {account.username}
                          </div>
                          <div className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-500">
                            {account.role}
                          </div>
                        </div>

                        <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-300">
                          Demo
                        </span>
                      </div>

                      <p className="mt-3 text-sm leading-6 text-slate-400">
                        {account.description}
                      </p>
                    </button>
                  )
                })}
              </div>

              <form className="space-y-5" onSubmit={handleSubmit}>
                <div>
                  <label
                    htmlFor="username"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Username
                  </label>
                  <input
                    id="username"
                    name="username"
                    autoComplete="username"
                    value={form.username}
                    onChange={updateField('username')}
                    className="w-full rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/15"
                    placeholder="analyst"
                    disabled={isSubmitting || isRefreshing}
                  />
                </div>

                <div>
                  <label
                    htmlFor="password"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Password
                  </label>

                  <div className="relative">
                    <input
                      id="password"
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      value={form.password}
                      onChange={updateField('password')}
                      className="w-full rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 pr-24 text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/15"
                      placeholder="••••••••"
                      disabled={isSubmitting || isRefreshing}
                    />

                    <button
                      type="button"
                      onClick={() => setShowPassword((current) => !current)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-700 hover:text-slate-100"
                    >
                      {showPassword ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={
                    isSubmitting ||
                    isRefreshing ||
                    !form.username.trim() ||
                    !form.password
                  }
                  className={cx(
                    'inline-flex w-full items-center justify-center rounded-2xl px-4 py-3 text-sm font-semibold transition',
                    isSubmitting || isRefreshing
                      ? 'cursor-not-allowed border border-slate-800 bg-slate-800 text-slate-500'
                      : 'border border-cyan-500/20 bg-cyan-500/15 text-cyan-100 hover:border-cyan-400/30 hover:bg-cyan-500/20',
                  )}
                >
                  {isSubmitting
                    ? 'Signing in...'
                    : isRefreshing
                    ? 'Refreshing session...'
                    : 'Sign in to ACCC'}
                </button>
              </form>

              <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-950/60 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                  Quick credentials
                </div>
                <div className="mt-3 grid gap-2 text-sm text-slate-300">
                  {DEMO_ACCOUNTS.map((account) => (
                    <div
                      key={`${account.username}-summary`}
                      className="flex flex-wrap items-center gap-x-2 gap-y-1"
                    >
                      <span className="font-semibold text-slate-100">
                        {account.username}
                      </span>
                      <span className="text-slate-500">/</span>
                      <span className="font-mono text-cyan-300">
                        {account.password}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <p className="mt-6 text-xs leading-6 text-slate-500">
                After successful login, protected API calls use the Bearer access token while silent refresh uses the backend refresh cookie. Signing out clears the active session and returns you to this page.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}