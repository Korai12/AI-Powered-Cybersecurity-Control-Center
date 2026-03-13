import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { shallow } from 'zustand/shallow'

import { ApiError, buildWebSocketUrl } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export type WebSocketConnectionState =
  | 'idle'
  | 'connecting'
  | 'open'
  | 'closed'
  | 'error'

export interface UseWebSocketOptions<TMessage = unknown> {
  path: string | null
  enabled?: boolean
  protocols?: string | string[]
  parseJson?: boolean
  reconnect?: boolean
  reconnectBaseDelayMs?: number
  reconnectMaxDelayMs?: number
  maxReconnectAttempts?: number
  refreshThresholdMs?: number
  shouldReconnect?: (event: CloseEvent) => boolean
  onOpen?: (event: Event) => void
  onMessage?: (message: TMessage, rawEvent: MessageEvent) => void
  onClose?: (event: CloseEvent) => void
  onError?: (event: Event) => void
}

export interface UseWebSocketResult<TMessage = unknown> {
  connectionState: WebSocketConnectionState
  isConnected: boolean
  reconnectAttempt: number
  lastMessage: TMessage | null
  lastError: string | null
  connect: () => Promise<void>
  disconnect: (code?: number, reason?: string) => void
  reconnectNow: () => Promise<void>
  sendMessage: (payload: string | ArrayBufferLike | Blob | ArrayBufferView) => boolean
  sendJsonMessage: (payload: unknown) => boolean
}

const DEFAULT_REFRESH_THRESHOLD_MS = 2 * 60 * 1000
const DEFAULT_RECONNECT_BASE_DELAY_MS = 1500
const DEFAULT_RECONNECT_MAX_DELAY_MS = 15000

function toErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message || 'WebSocket authentication failed'
  }

  if (error instanceof Error) {
    return error.message || 'WebSocket connection failed'
  }

  return 'WebSocket connection failed'
}

function useLatestRef<T>(value: T) {
  const ref = useRef(value)

  useEffect(() => {
    ref.current = value
  }, [value])

  return ref
}

export function useWebSocket<TMessage = unknown>(
  options: UseWebSocketOptions<TMessage>,
): UseWebSocketResult<TMessage> {
  const {
    accessToken,
    expiresAt,
    isAuthenticated,
    isBootstrapping,
    refreshSession,
    handleUnauthorized,
  } = useAuthStore(
    (state) => ({
      accessToken: state.accessToken,
      expiresAt: state.expiresAt,
      isAuthenticated: state.isAuthenticated,
      isBootstrapping: state.isBootstrapping,
      refreshSession: state.refreshSession,
      handleUnauthorized: state.handleUnauthorized,
    }),
    shallow,
  )

  const [connectionState, setConnectionState] =
    useState<WebSocketConnectionState>('idle')
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const [lastMessage, setLastMessage] = useState<TMessage | null>(null)
  const [lastError, setLastError] = useState<string | null>(null)

  const socketRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<number | null>(null)
  const reconnectAttemptRef = useRef(0)
  const manualCloseRef = useRef(false)
  const connectingRef = useRef(false)

  const optionsRef = useLatestRef(options)

  const {
    path,
    enabled = true,
    protocols,
    parseJson = true,
    reconnect = true,
    reconnectBaseDelayMs = DEFAULT_RECONNECT_BASE_DELAY_MS,
    reconnectMaxDelayMs = DEFAULT_RECONNECT_MAX_DELAY_MS,
    maxReconnectAttempts = Infinity,
    refreshThresholdMs = DEFAULT_REFRESH_THRESHOLD_MS,
  } = options

  const effectiveEnabled = enabled && Boolean(path) && isAuthenticated && !isBootstrapping

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
  }, [])

  const cleanupSocket = useCallback(() => {
    const socket = socketRef.current
    socketRef.current = null

    if (socket) {
      socket.onopen = null
      socket.onmessage = null
      socket.onerror = null
      socket.onclose = null

      if (
        socket.readyState === WebSocket.OPEN ||
        socket.readyState === WebSocket.CONNECTING
      ) {
        try {
          socket.close(1000, 'client disconnect')
        } catch {
          // Ignore close failures on cleanup.
        }
      }
    }
  }, [])

  const resolveToken = useCallback(async (): Promise<string | null> => {
    const msRemaining =
      typeof expiresAt === 'number' ? expiresAt - Date.now() : null

    if (
      accessToken &&
      msRemaining !== null &&
      msRemaining > refreshThresholdMs
    ) {
      return accessToken
    }

    const refreshed = await refreshSession()
    return refreshed || null
  }, [accessToken, expiresAt, refreshSession, refreshThresholdMs])

  const resetConnectionMeta = useCallback(() => {
    reconnectAttemptRef.current = 0
    setReconnectAttempt(0)
    setLastError(null)
  }, [])

  const scheduleReconnect = useCallback(
    (event: CloseEvent) => {
      const currentOptions = optionsRef.current

      if (
        manualCloseRef.current ||
        !reconnect ||
        !effectiveEnabled ||
        reconnectAttemptRef.current >= maxReconnectAttempts
      ) {
        return
      }

      const shouldReconnect =
        currentOptions.shouldReconnect?.(event) ?? (event.code !== 1000)

      if (!shouldReconnect) {
        return
      }

      reconnectAttemptRef.current += 1
      setReconnectAttempt(reconnectAttemptRef.current)

      const delay = Math.min(
        reconnectMaxDelayMs,
        reconnectBaseDelayMs * 2 ** (reconnectAttemptRef.current - 1),
      )

      clearReconnectTimer()

      reconnectTimerRef.current = window.setTimeout(() => {
        void connect()
      }, delay)
    },
    [
      clearReconnectTimer,
      effectiveEnabled,
      maxReconnectAttempts,
      reconnect,
      reconnectBaseDelayMs,
      reconnectMaxDelayMs,
      optionsRef,
    ],
  )

  const connect = useCallback(async () => {
    if (!effectiveEnabled || !path) {
      setConnectionState('idle')
      return
    }

    if (connectingRef.current) {
      return
    }

    const existing = socketRef.current
    if (
      existing &&
      (existing.readyState === WebSocket.OPEN ||
        existing.readyState === WebSocket.CONNECTING)
    ) {
      return
    }

    connectingRef.current = true
    clearReconnectTimer()
    setConnectionState('connecting')
    setLastError(null)

    try {
      const token = await resolveToken()

      if (!token) {
        setConnectionState('closed')
        await handleUnauthorized()
        return
      }

      const url = buildWebSocketUrl(path, token)
      const socket = protocols
        ? new WebSocket(url, protocols)
        : new WebSocket(url)

      socketRef.current = socket

      socket.onopen = (event) => {
        connectingRef.current = false
        resetConnectionMeta()
        setConnectionState('open')
        optionsRef.current.onOpen?.(event)
      }

      socket.onmessage = (event) => {
        let message: TMessage

        try {
          if (parseJson) {
            message = JSON.parse(event.data as string) as TMessage
          } else {
            message = event.data as TMessage
          }
        } catch {
          message = event.data as TMessage
        }

        setLastMessage(message)
        optionsRef.current.onMessage?.(message, event)
      }

      socket.onerror = (event) => {
        setConnectionState('error')
        setLastError('WebSocket transport error')
        optionsRef.current.onError?.(event)
      }

      socket.onclose = (event) => {
        connectingRef.current = false

        if (socketRef.current === socket) {
          socketRef.current = null
        }

        setConnectionState('closed')
        optionsRef.current.onClose?.(event)

        if (!manualCloseRef.current) {
          scheduleReconnect(event)
        }
      }
    } catch (error) {
      connectingRef.current = false
      setConnectionState('error')
      setLastError(toErrorMessage(error))

      if (error instanceof ApiError && error.status === 401) {
        await handleUnauthorized()
      }
    }
  }, [
    clearReconnectTimer,
    effectiveEnabled,
    handleUnauthorized,
    optionsRef,
    parseJson,
    path,
    protocols,
    resolveToken,
    resetConnectionMeta,
    scheduleReconnect,
  ])

  const disconnect = useCallback(
    (code = 1000, reason = 'client disconnect') => {
      manualCloseRef.current = true
      clearReconnectTimer()

      const socket = socketRef.current
      socketRef.current = null

      if (socket) {
        socket.onopen = null
        socket.onmessage = null
        socket.onerror = null
        socket.onclose = null

        if (
          socket.readyState === WebSocket.OPEN ||
          socket.readyState === WebSocket.CONNECTING
        ) {
          try {
            socket.close(code, reason)
          } catch {
            // Ignore close errors on manual disconnect.
          }
        }
      }

      connectingRef.current = false
      setConnectionState('closed')
    },
    [clearReconnectTimer],
  )

  const reconnectNow = useCallback(async () => {
    manualCloseRef.current = false
    clearReconnectTimer()
    cleanupSocket()
    await connect()
  }, [cleanupSocket, clearReconnectTimer, connect])

  const sendMessage = useCallback(
    (payload: string | ArrayBufferLike | Blob | ArrayBufferView) => {
      const socket = socketRef.current

      if (!socket || socket.readyState !== WebSocket.OPEN) {
        return false
      }

      socket.send(payload)
      return true
    },
    [],
  )

  const sendJsonMessage = useCallback(
    (payload: unknown) => {
      try {
        return sendMessage(JSON.stringify(payload))
      } catch {
        return false
      }
    },
    [sendMessage],
  )

  useEffect(() => {
    if (!effectiveEnabled || !path) {
      disconnect(1000, 'disabled')
      setConnectionState('idle')
      return
    }

    manualCloseRef.current = false
    void connect()

    return () => {
      disconnect(1000, 'effect cleanup')
    }
  }, [connect, disconnect, effectiveEnabled, path])

  useEffect(() => {
    if (!effectiveEnabled) {
      return
    }

    const msRemaining =
      typeof expiresAt === 'number' ? expiresAt - Date.now() : null

    if (
      connectionState === 'open' &&
      msRemaining !== null &&
      msRemaining <= refreshThresholdMs
    ) {
      void reconnectNow()
    }
  }, [
    connectionState,
    effectiveEnabled,
    expiresAt,
    reconnectNow,
    refreshThresholdMs,
  ])

  useEffect(() => {
    return () => {
      clearReconnectTimer()
      cleanupSocket()
    }
  }, [clearReconnectTimer, cleanupSocket])

  return useMemo(
    () => ({
      connectionState,
      isConnected: connectionState === 'open',
      reconnectAttempt,
      lastMessage,
      lastError,
      connect,
      disconnect,
      reconnectNow,
      sendMessage,
      sendJsonMessage,
    }),
    [
      connectionState,
      reconnectAttempt,
      lastMessage,
      lastError,
      connect,
      disconnect,
      reconnectNow,
      sendMessage,
      sendJsonMessage,
    ],
  )
}