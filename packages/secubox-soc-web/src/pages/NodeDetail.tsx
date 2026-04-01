import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Server, Play, Square, RotateCw, AlertTriangle } from 'lucide-react'
import { useFleet } from '../hooks/useFleet'
import AlertItem from '../components/AlertItem'

interface NodeData {
  node: {
    node_id: string
    hostname: string
    status: string
    health: string
    ip_address: string
    region: string
    tags: string[]
    capabilities: string[]
    enrolled_at: string
    last_seen: string
  }
  metrics: {
    cpu: number
    memory: number
    disk: number
  }
  alerts: Array<Record<string, unknown>>
}

const SERVICES = [
  { name: 'nginx', label: 'Nginx' },
  { name: 'haproxy', label: 'HAProxy' },
  { name: 'crowdsec', label: 'CrowdSec' },
  { name: 'suricata', label: 'Suricata' },
  { name: 'netdata', label: 'Netdata' },
]

export default function NodeDetail() {
  const { nodeId } = useParams()
  const navigate = useNavigate()
  const { getNode, sendServiceAction } = useFleet()
  const [nodeData, setNodeData] = useState<NodeData | null>(null)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  useEffect(() => {
    if (nodeId) {
      loadNode()
      const interval = setInterval(loadNode, 15000)
      return () => clearInterval(interval)
    }
  }, [nodeId])

  async function loadNode() {
    if (!nodeId) return
    setLoading(true)
    const data = await getNode(nodeId)
    if (data) {
      setNodeData(data as NodeData)
    }
    setLoading(false)
  }

  async function handleServiceAction(service: string, action: string) {
    if (!nodeId) return
    setActionLoading(`${service}-${action}`)
    const result = await sendServiceAction(nodeId, service, action)
    setActionLoading(null)
    if (result?.status === 'queued') {
      // Show success notification
      console.log('Command queued:', result)
    }
  }

  if (loading && !nodeData) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    )
  }

  if (!nodeData) {
    return (
      <div className="empty-state">
        <Server size={48} />
        <p>Node not found</p>
        <button className="btn btn-primary" onClick={() => navigate('/')}>
          Back to Fleet
        </button>
      </div>
    )
  }

  const { node, metrics, alerts } = nodeData

  return (
    <div>
      <button
        className="btn btn-secondary"
        onClick={() => navigate('/')}
        style={{ marginBottom: '1rem' }}
      >
        <ArrowLeft size={16} />
        Back to Fleet
      </button>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Server size={18} />
            {node.hostname}
          </div>
          <span className={`health-badge ${node.health}`}>
            {node.health}
          </span>
        </div>
        <div className="card-body">
          <div className="grid-2" style={{ marginBottom: '1.5rem' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Node ID</div>
              <div style={{ fontFamily: 'monospace' }}>{node.node_id}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>IP Address</div>
              <div>{node.ip_address}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Region</div>
              <div>{node.region || 'default'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Capabilities</div>
              <div>{node.capabilities?.join(', ') || 'none'}</div>
            </div>
          </div>

          {/* Resource metrics */}
          <h3 style={{ fontSize: '1rem', marginBottom: '1rem' }}>Resources</h3>
          <div className="grid-3">
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>CPU</span>
                <span style={{ fontSize: '0.875rem' }}>{(metrics?.cpu || 0).toFixed(1)}%</span>
              </div>
              <div className="progress-bar" style={{ height: '8px' }}>
                <div
                  className={`progress-fill ${(metrics?.cpu || 0) < 50 ? 'low' : (metrics?.cpu || 0) < 80 ? 'medium' : 'high'}`}
                  style={{ width: `${metrics?.cpu || 0}%` }}
                />
              </div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Memory</span>
                <span style={{ fontSize: '0.875rem' }}>{(metrics?.memory || 0).toFixed(1)}%</span>
              </div>
              <div className="progress-bar" style={{ height: '8px' }}>
                <div
                  className={`progress-fill ${(metrics?.memory || 0) < 50 ? 'low' : (metrics?.memory || 0) < 80 ? 'medium' : 'high'}`}
                  style={{ width: `${metrics?.memory || 0}%` }}
                />
              </div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Disk</span>
                <span style={{ fontSize: '0.875rem' }}>{(metrics?.disk || 0).toFixed(1)}%</span>
              </div>
              <div className="progress-bar" style={{ height: '8px' }}>
                <div
                  className={`progress-fill ${(metrics?.disk || 0) < 70 ? 'low' : (metrics?.disk || 0) < 85 ? 'medium' : 'high'}`}
                  style={{ width: `${metrics?.disk || 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Service Management */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">Service Management</div>
        </div>
        <div className="card-body">
          <table className="data-table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {SERVICES.map(service => (
                <tr key={service.name}>
                  <td>{service.label}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        className="btn btn-secondary"
                        onClick={() => handleServiceAction(service.name, 'start')}
                        disabled={actionLoading === `${service.name}-start`}
                        title="Start"
                      >
                        <Play size={14} />
                      </button>
                      <button
                        className="btn btn-secondary"
                        onClick={() => handleServiceAction(service.name, 'stop')}
                        disabled={actionLoading === `${service.name}-stop`}
                        title="Stop"
                      >
                        <Square size={14} />
                      </button>
                      <button
                        className="btn btn-secondary"
                        onClick={() => handleServiceAction(service.name, 'restart')}
                        disabled={actionLoading === `${service.name}-restart`}
                        title="Restart"
                      >
                        <RotateCw size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <AlertTriangle size={18} />
            Recent Alerts
          </div>
        </div>
        <div className="card-body">
          {alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: '2rem' }}>
              <AlertTriangle size={32} />
              <p>No recent alerts</p>
            </div>
          ) : (
            <div className="alert-list">
              {alerts.slice(0, 10).map((alert, idx) => (
                <AlertItem key={idx} alert={alert} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
