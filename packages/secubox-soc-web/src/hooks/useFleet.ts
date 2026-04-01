import { useState, useCallback } from 'react'

interface FleetSummary {
  total_nodes: number
  nodes_online: number
  nodes_offline: number
  health_breakdown: Record<string, number>
  resources: {
    avg_cpu: number
    avg_memory: number
    avg_disk: number
  }
  services_down: number
  total_alerts: number
  critical_nodes: Array<{
    node_id: string
    hostname: string
    cpu: number
    memory: number
  }>
  timestamp: string
}

interface FleetNode {
  node_id: string
  hostname: string
  status: string
  health: string
  ip_address: string
  region: string
  last_seen: string
  enrolled_at: string
  cpu?: number
  memory?: number
  disk?: number
}

const API_BASE = '/api/v1/soc-gateway'

async function fetchApi<T>(endpoint: string): Promise<T | null> {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`)
    if (!response.ok) return null
    return await response.json()
  } catch {
    return null
  }
}

export function useFleet() {
  const [summary, setSummary] = useState<FleetSummary | null>(null)
  const [nodes, setNodes] = useState<FleetNode[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refreshFleet = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const [summaryData, nodesData] = await Promise.all([
        fetchApi<FleetSummary>('/fleet/summary'),
        fetchApi<{ nodes: FleetNode[] }>('/fleet/nodes')
      ])

      if (summaryData) {
        setSummary(summaryData)
      }

      if (nodesData?.nodes) {
        setNodes(nodesData.nodes)
      }
    } catch (err) {
      setError('Failed to fetch fleet data')
    } finally {
      setLoading(false)
    }
  }, [])

  const getNode = useCallback(async (nodeId: string) => {
    return fetchApi<{
      node: FleetNode
      metrics: Record<string, number>
      alerts: Array<Record<string, unknown>>
    }>(`/fleet/nodes/${nodeId}`)
  }, [])

  const sendCommand = useCallback(async (nodeId: string, action: string, args: string[] = []) => {
    try {
      const response = await fetch(`${API_BASE}/nodes/${nodeId}/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, args })
      })
      return await response.json()
    } catch {
      return null
    }
  }, [])

  const sendServiceAction = useCallback(async (
    nodeId: string,
    service: string,
    action: string
  ) => {
    try {
      const response = await fetch(
        `${API_BASE}/nodes/${nodeId}/services/${service}/action?action=${action}`,
        { method: 'POST' }
      )
      return await response.json()
    } catch {
      return null
    }
  }, [])

  return {
    summary,
    nodes,
    loading,
    error,
    refreshFleet,
    getNode,
    sendCommand,
    sendServiceAction
  }
}

export function useAlerts() {
  const [alerts, setAlerts] = useState<Array<Record<string, unknown>>>([])
  const [threats, setThreats] = useState<Array<Record<string, unknown>>>([])
  const [loading, setLoading] = useState(false)

  const refreshAlerts = useCallback(async (
    limit = 50,
    severity?: string,
    source?: string
  ) => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ limit: String(limit) })
      if (severity) params.set('severity', severity)
      if (source) params.set('source', source)

      const data = await fetchApi<{ alerts: Array<Record<string, unknown>> }>(
        `/alerts/stream?${params}`
      )
      if (data?.alerts) {
        setAlerts(data.alerts)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  const refreshThreats = useCallback(async (minNodes = 2, severity?: string) => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ min_nodes: String(minNodes) })
      if (severity) params.set('severity', severity)

      const data = await fetchApi<{ threats: Array<Record<string, unknown>> }>(
        `/alerts/correlated?${params}`
      )
      if (data?.threats) {
        setThreats(data.threats)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  return { alerts, threats, loading, refreshAlerts, refreshThreats }
}
