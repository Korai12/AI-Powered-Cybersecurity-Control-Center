import { useEffect } from 'react'
import { shallow } from 'zustand/shallow'

import { useAuthStore } from '@/store/auth'

export function useAuth() {
  const auth = useAuthStore(
    (state) => ({
      status: state.status,
      accessToken: state.accessToken,
      expiresAt: state.expiresAt,
      user: state.user,
      isAuthenticated: state.isAuthenticated,
      isBootstrapping: state.isBootstrapping,
      isRefreshing: state.isRefreshing,
      error: state.error,
      login: state.login,
      logout: state.logout,
      bootstrap: state.bootstrap,
      refreshSession: state.refreshSession,
      clearError: state.clearError,
      handleUnauthorized: state.handleUnauthorized,
    }),
    shallow,
  )

  useEffect(() => {
    void auth.bootstrap()
  }, [auth.bootstrap])

  return {
    ...auth,
    role: auth.user?.role ?? null,
    username: auth.user?.username ?? null,
    displayName: auth.user?.display_name ?? auth.user?.username ?? null,
    hasRole: (...roles: string[]) =>
      Boolean(auth.user?.role && roles.includes(auth.user.role)),
  }
}