import { create } from 'zustand'

export type AppPage =
  | 'dashboard'
  | 'events'
  | 'incidents'
  | 'chat'
  | 'hunt'
  | 'mitre'
  | 'actions'
  | 'reports'
  | 'incident-graph'
  | 'ciso'
  | 'settings'
  | 'unknown'

export type ModalType =
  | null
  | 'event-details'
  | 'incident-details'
  | 'upload-events'
  | 'command-palette'
  | 'settings'
  | 'confirm-action'

export type ThemeMode = 'soc-dark'

export interface ModalState {
  type: ModalType
  isOpen: boolean
  payload: Record<string, unknown> | null
}

export interface TourState {
  isOpen: boolean
  currentStep: number
  completed: boolean
  hasStarted: boolean
}

type UiPreferences = {
  theme?: string | null
  audio_alerts?: boolean | null
  tour_completed?: boolean | null
}

type UiState = {
  activePage: AppPage
  sidebarCollapsed: boolean
  theme: ThemeMode
  audioEnabled: boolean
  modal: ModalState
  tour: TourState

  setActivePage: (page: AppPage) => void
  syncActivePageFromPathname: (pathname: string) => void

  setSidebarCollapsed: (collapsed: boolean) => void
  toggleSidebar: () => void

  openModal: (type: Exclude<ModalType, null>, payload?: Record<string, unknown> | null) => void
  closeModal: () => void

  setAudioEnabled: (enabled: boolean) => void
  toggleAudio: () => void

  startTour: (startStep?: number) => void
  stopTour: () => void
  completeTour: () => void
  resetTour: () => void
  setTourStep: (step: number) => void

  applyUserPreferences: (preferences?: UiPreferences | null) => void
  resetUiState: () => void
}

const DEFAULT_MODAL: ModalState = {
  type: null,
  isOpen: false,
  payload: null,
}

const DEFAULT_TOUR: TourState = {
  isOpen: false,
  currentStep: 0,
  completed: false,
  hasStarted: false,
}

const DEFAULT_ACTIVE_PAGE: AppPage = 'dashboard'

function resolvePageFromPathname(pathname: string): AppPage {
  const path = pathname.trim().toLowerCase()

  if (path === '/' || path === '') return 'dashboard'
  if (path === '/events') return 'events'
  if (path === '/incidents') return 'incidents'
  if (path.startsWith('/incidents/') && path.endsWith('/graph')) return 'incident-graph'
  if (path === '/chat') return 'chat'
  if (path === '/hunt') return 'hunt'
  if (path === '/mitre') return 'mitre'
  if (path === '/actions') return 'actions'
  if (path === '/reports') return 'reports'
  if (path === '/ciso') return 'ciso'
  if (path === '/settings') return 'settings'

  return 'unknown'
}

export const useUiStore = create<UiState>((set) => ({
  activePage: DEFAULT_ACTIVE_PAGE,
  sidebarCollapsed: false,
  theme: 'soc-dark',
  audioEnabled: true,
  modal: DEFAULT_MODAL,
  tour: DEFAULT_TOUR,

  setActivePage: (page) => {
    set({ activePage: page })
  },

  syncActivePageFromPathname: (pathname) => {
    set({ activePage: resolvePageFromPathname(pathname) })
  },

  setSidebarCollapsed: (collapsed) => {
    set({ sidebarCollapsed: collapsed })
  },

  toggleSidebar: () => {
    set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }))
  },

  openModal: (type, payload = null) => {
    set({
      modal: {
        type,
        isOpen: true,
        payload,
      },
    })
  },

  closeModal: () => {
    set({ modal: DEFAULT_MODAL })
  },

  setAudioEnabled: (enabled) => {
    set({ audioEnabled: enabled })
  },

  toggleAudio: () => {
    set((state) => ({ audioEnabled: !state.audioEnabled }))
  },

  startTour: (startStep = 0) => {
    set((state) => ({
      tour: {
        ...state.tour,
        isOpen: true,
        hasStarted: true,
        currentStep: Math.max(0, startStep),
      },
    }))
  },

  stopTour: () => {
    set((state) => ({
      tour: {
        ...state.tour,
        isOpen: false,
      },
    }))
  },

  completeTour: () => {
    set((state) => ({
      tour: {
        ...state.tour,
        isOpen: false,
        completed: true,
        hasStarted: true,
      },
    }))
  },

  resetTour: () => {
    set({
      tour: DEFAULT_TOUR,
    })
  },

  setTourStep: (step) => {
    set((state) => ({
      tour: {
        ...state.tour,
        currentStep: Math.max(0, step),
      },
    }))
  },

  applyUserPreferences: (preferences) => {
    if (!preferences) return

    set((state) => ({
      theme: 'soc-dark',
      audioEnabled:
        typeof preferences.audio_alerts === 'boolean'
          ? preferences.audio_alerts
          : state.audioEnabled,
      tour: {
        ...state.tour,
        completed:
          typeof preferences.tour_completed === 'boolean'
            ? preferences.tour_completed
            : state.tour.completed,
      },
    }))
  },

  resetUiState: () => {
    set({
      activePage: DEFAULT_ACTIVE_PAGE,
      sidebarCollapsed: false,
      theme: 'soc-dark',
      audioEnabled: true,
      modal: DEFAULT_MODAL,
      tour: DEFAULT_TOUR,
    })
  },
}))

export function getPageFromPathname(pathname: string): AppPage {
  return resolvePageFromPathname(pathname)
}