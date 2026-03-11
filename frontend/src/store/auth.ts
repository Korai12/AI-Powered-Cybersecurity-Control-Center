// Zustand auth store — implemented in Phase 2
import { create } from 'zustand'
interface AuthState { token: string | null; user: unknown | null; isAuthenticated: boolean }
export const useAuthStore = create<AuthState>(() => ({ token: null, user: null, isAuthenticated: false }))
