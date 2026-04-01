import { useState, useEffect, useRef, useCallback } from 'react'

interface WebSocketMessage {
  type: string
  data: unknown
  timestamp: string
}

export function useWebSocket(url: string) {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}${url}`

    try {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        setIsConnected(true)
        setError(null)
        // Send heartbeat
        const heartbeat = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping')
          }
        }, 30000)
        ws.onclose = () => clearInterval(heartbeat)
      }

      ws.onmessage = (event) => {
        if (event.data === 'pong') return
        try {
          const message = JSON.parse(event.data)
          setLastMessage({
            type: message.type || 'unknown',
            data: message,
            timestamp: new Date().toISOString()
          })
        } catch {
          // Not JSON, ignore
        }
      }

      ws.onerror = () => {
        setError('WebSocket connection error')
      }

      ws.onclose = () => {
        setIsConnected(false)
        wsRef.current = null
        // Reconnect after 5 seconds
        reconnectTimeoutRef.current = window.setTimeout(connect, 5000)
      }

      wsRef.current = ws
    } catch (err) {
      setError('Failed to create WebSocket connection')
    }
  }, [url])

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [connect])

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { isConnected, lastMessage, error, send }
}
