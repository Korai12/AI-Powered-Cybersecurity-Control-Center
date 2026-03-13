import { useEffect, useRef } from 'react'

import { buildWebSocketUrl } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

interface UseWebSocketOptions {
  path: string
  enabled?: boolean
  onMessage?: (payload: any) => void
  onOpen?: () => void
  onClose?: () => void
  onError?: () => void
}

export function useWebSocket({ path, enabled = true, onMessage, onOpen, onClose, onError }: UseWebSocketOptions) {
  const socketRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<number | null>(null)

  useEffect(() => {
    let active = true

    const cleanup = () => {
      if (reconnectTimer.current) {
        window.clearTimeout(reconnectTimer.current)
      }
      if (socketRef.current) {
        socketRef.current.close()
        socketRef.current = null
      }
    }

    const connect = async () => {
      const authStore = useAuthStore.getState()
      let token = authStore.accessToken
      if (!enabled) return
      if (!token) token = await authStore.refreshToken()
      if (!token || !active) return

      const socket = new WebSocket(buildWebSocketUrl(path, token))
      socketRef.current = socket

      socket.onopen = () => {
        if (!active) return
        onOpen?.()
      }

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data)
          if (payload.type === 'ping') {
            socket.send(JSON.stringify({ type: 'ping' }))
            return
          }
          onMessage?.(payload)
        } catch {
          onMessage?.(event.data)
        }
      }

      socket.onerror = () => {
        onError?.()
      }

      socket.onclose = () => {
        if (!active) return
        onClose?.()
        reconnectTimer.current = window.setTimeout(async () => {
          const state = useAuthStore.getState()
          if (state.expiresAt && state.expiresAt - Date.now() < 120_000) {
            await state.refreshToken()
          }
          await connect()
        }, 2500)
      }
    }

    void connect()
    return () => {
      active = false
      cleanup()
    }
  }, [enabled, onClose, onError, onMessage, onOpen, path])

  return socketRef
}

