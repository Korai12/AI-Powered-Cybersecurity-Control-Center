import { create } from 'zustand'

import {
  ApiError,
  configureApiAuth,
  getCurrentUser,
  login as loginRequest,
  logout as logoutRequest,
  refreshAccessToken as refreshAccessTokenRequest,
  type LoginRequest,
  type UserProfile,
} from '@/lib/api'

type AuthStatus = 'idle' | 'authenticated' | 'anonymous'

type AuthState = {
  status: AuthStatus
  accessToken: string | null
  expiresAt: number | null
  user: UserProfile | null
  isAuthenticated: boolean
  isBootstrapping: boolean
  isRefreshing: boolean
  error: string | null

  setSession: (payload: {
    accessToken: string
    expiresIn: number
    user?: UserProfile | null
  }) => void

  login: (payload: LoginRequest) => Promise<void>
  bootstrap: () => Promise<void>
  refreshSession: () => Promise<string | null>
  logout: () => Promise<void>
  handleUnauthorized: () => Promise<void>

  startTokenMonitor: () => void
  stopTokenMonitor: () => void
  clearError: () => void
  reset: () => void
}

const REFRESH_THRESHOLD_MS = 2 * 60 * 1000
const TOKEN_MONITOR_INTERVAL_MS = 60 * 1000

let tokenMonitorId: number | null = null
let bootstrapPromise: Promise<void> | null = null
let refreshPromise: Promise<string | null> | null = null

function computeExpiresAt(expiresInSeconds: number): number {
  const safeSeconds = Math.max(0, Number(expiresInSeconds) || 0)
  return Date.now() + safeSeconds * 1000
}

function getFriendlyErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (typeof error.data === 'object' && error.data && 'detail' in error.data) {
      const detail = (error.data as { detail?: unknown }).detail
      if (typeof detail === 'string' && detail.trim()) {
        return detail
      }
    }
    if (error.message?.trim()) {
      return error.message
    }
  }

  if (error instanceof Error && error.message.trim()) {
    return error.message
  }

  return 'Authentication request failed'
}

async function fetchAndStoreCurrentUser(): Promise<UserProfile> {
  const user = await getCurrentUser()

  useAuthStore.setState((state) => ({
    ...state,
    user,
    isAuthenticated: Boolean(state.accessToken),
    status: state.accessToken ? 'authenticated' : state.status,
    error: null,
  }))

  return user
}

function ensureTokenMonitorRunning() {
  const store = useAuthStore.getState()

  if (!store.isAuthenticated) {
    store.stopTokenMonitor()
    return
  }

  store.startTokenMonitor()
}

export const useAuthStore = create<AuthState>((set, get) => ({
  status: 'idle',
  accessToken: null,
  expiresAt: null,
  user: null,
  isAuthenticated: false,
  isBootstrapping: true,
  isRefreshing: false,
  error: null,

  setSession: ({ accessToken, expiresIn, user }) => {
    set((state) => ({
      ...state,
      accessToken,
      expiresAt: computeExpiresAt(expiresIn),
      user: user ?? state.user,
      isAuthenticated: true,
      status: 'authenticated',
      error: null,
    }))

    ensureTokenMonitorRunning()
  },

  login: async (payload) => {
    set((state) => ({
      ...state,
      error: null,
    }))

    try {
      const response = await loginRequest(payload)

      get().setSession({
        accessToken: response.access_token,
        expiresIn: response.expires_in,
      })

      await fetchAndStoreCurrentUser()
      get().startTokenMonitor()
    } catch (error) {
      get().reset()
      set((state) => ({
        ...state,
        status: 'anonymous',
        isBootstrapping: false,
        error: getFriendlyErrorMessage(error),
      }))
      throw error
    }
  },

  bootstrap: async () => {
    if (bootstrapPromise) {
      return bootstrapPromise
    }

    bootstrapPromise = (async () => {
      const state = get()

      if (state.isAuthenticated && state.user && state.accessToken) {
        set((current) => ({
          ...current,
          isBootstrapping: false,
          status: 'authenticated',
        }))
        ensureTokenMonitorRunning()
        return
      }

      set((current) => ({
        ...current,
        isBootstrapping: true,
        error: null,
      }))

      try {
        const refreshedToken = await get().refreshSession()

        if (!refreshedToken) {
          set((current) => ({
            ...current,
            status: 'anonymous',
            isBootstrapping: false,
            isAuthenticated: false,
            user: null,
          }))
          return
        }

        await fetchAndStoreCurrentUser()

        set((current) => ({
          ...current,
          isBootstrapping: false,
          isAuthenticated: true,
          status: 'authenticated',
          error: null,
        }))

        get().startTokenMonitor()
      } catch (error) {
        get().reset()
        set((current) => ({
          ...current,
          status: 'anonymous',
          isBootstrapping: false,
          error: null,
        }))
      }
    })().finally(() => {
      bootstrapPromise = null
    })

    return bootstrapPromise
  },

  refreshSession: async () => {
    if (refreshPromise) {
      return refreshPromise
    }

    refreshPromise = (async () => {
      const state = get()

      if (state.isRefreshing) {
        return state.accessToken
      }

      set((current) => ({
        ...current,
        isRefreshing: true,
        error: null,
      }))

      try {
        const response = await refreshAccessTokenRequest()

        set((current) => ({
          ...current,
          accessToken: response.access_token,
          expiresAt: computeExpiresAt(response.expires_in),
          isAuthenticated: true,
          status: 'authenticated',
          isRefreshing: false,
          error: null,
        }))

        ensureTokenMonitorRunning()
        return response.access_token
      } catch (error) {
        get().stopTokenMonitor()

        set((current) => ({
          ...current,
          accessToken: null,
          expiresAt: null,
          user: null,
          isAuthenticated: false,
          status: 'anonymous',
          isRefreshing: false,
          error: null,
        }))

        return null
      }
    })().finally(() => {
      refreshPromise = null
    })

    return refreshPromise
  },

  logout: async () => {
    try {
      if (get().accessToken) {
        await logoutRequest()
      }
    } catch {
      // Always clear local auth state even if logout API fails.
    } finally {
      get().reset()
    }
  },

  handleUnauthorized: async () => {
    get().stopTokenMonitor()

    set((state) => ({
      ...state,
      accessToken: null,
      expiresAt: null,
      user: null,
      isAuthenticated: false,
      status: 'anonymous',
      isBootstrapping: false,
      isRefreshing: false,
      error: null,
    }))
  },

  startTokenMonitor: () => {
    if (typeof window === 'undefined') {
      return
    }

    if (tokenMonitorId !== null) {
      return
    }

    const runCheck = async () => {
      const state = get()

      if (!state.isAuthenticated || !state.expiresAt) {
        get().stopTokenMonitor()
        return
      }

      const msRemaining = state.expiresAt - Date.now()

      if (msRemaining <= REFRESH_THRESHOLD_MS && !state.isRefreshing) {
        const refreshed = await get().refreshSession()

        if (!refreshed) {
          await get().handleUnauthorized()
        }
      }
    }

    tokenMonitorId = window.setInterval(() => {
      void runCheck()
    }, TOKEN_MONITOR_INTERVAL_MS)

    void runCheck()
  },

  stopTokenMonitor: () => {
    if (typeof window === 'undefined') {
      return
    }

    if (tokenMonitorId !== null) {
      window.clearInterval(tokenMonitorId)
      tokenMonitorId = null
    }
  },

  clearError: () => {
    set((state) => ({
      ...state,
      error: null,
    }))
  },

  reset: () => {
    get().stopTokenMonitor()

    set((state) => ({
      ...state,
      status: 'anonymous',
      accessToken: null,
      expiresAt: null,
      user: null,
      isAuthenticated: false,
      isBootstrapping: false,
      isRefreshing: false,
      error: null,
    }))
  },
}))

configureApiAuth({
  getAccessToken: () => useAuthStore.getState().accessToken,
  refreshAccessToken: async () => useAuthStore.getState().refreshSession(),
  onUnauthorized: async () => {
    await useAuthStore.getState().handleUnauthorized()
  },
})