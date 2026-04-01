import { useNavigate } from 'react-router-dom'
import { Server, Cpu, HardDrive, MemoryStick } from 'lucide-react'

interface NodeCardProps {
  node: {
    node_id: string
    hostname: string
    status: string
    health: string
    ip_address: string
    region: string
    last_seen: string
    cpu?: number
    memory?: number
    disk?: number
  }
}

function getProgressClass(value: number): string {
  if (value < 50) return 'low'
  if (value < 80) return 'medium'
  return 'high'
}

function formatLastSeen(timestamp: string): string {
  if (!timestamp) return 'never'
  try {
    const dt = new Date(timestamp)
    const now = new Date()
    const diffMs = now.getTime() - dt.getTime()
    const diffMins = Math.floor(diffMs / 60000)

    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m ago`
    const diffHours = Math.floor(diffMins / 60)
    if (diffHours < 24) return `${diffHours}h ago`
    return `${Math.floor(diffHours / 24)}d ago`
  } catch {
    return timestamp
  }
}

export default function NodeCard({ node }: NodeCardProps) {
  const navigate = useNavigate()

  const cpu = node.cpu || 0
  const memory = node.memory || 0
  const disk = node.disk || 0

  return (
    <div
      className="node-card"
      onClick={() => navigate(`/node/${node.node_id}`)}
    >
      <div className="node-card-header">
        <div className="node-hostname">
          <Server size={16} />
          <span>{node.hostname}</span>
        </div>
        <span className={`health-badge ${node.health}`}>
          {node.health}
        </span>
      </div>

      <div className="node-id">{node.node_id}</div>

      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
        {node.ip_address} &bull; {node.region || 'default'} &bull; {formatLastSeen(node.last_seen)}
      </div>

      <div className="node-metrics">
        <div className="metric-item">
          <div className="metric-value" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
            <Cpu size={14} />
            {cpu.toFixed(0)}%
          </div>
          <div className="progress-bar">
            <div
              className={`progress-fill ${getProgressClass(cpu)}`}
              style={{ width: `${cpu}%` }}
            />
          </div>
          <div className="metric-label">CPU</div>
        </div>

        <div className="metric-item">
          <div className="metric-value" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
            <MemoryStick size={14} />
            {memory.toFixed(0)}%
          </div>
          <div className="progress-bar">
            <div
              className={`progress-fill ${getProgressClass(memory)}`}
              style={{ width: `${memory}%` }}
            />
          </div>
          <div className="metric-label">Memory</div>
        </div>

        <div className="metric-item">
          <div className="metric-value" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
            <HardDrive size={14} />
            {disk.toFixed(0)}%
          </div>
          <div className="progress-bar">
            <div
              className={`progress-fill ${getProgressClass(disk)}`}
              style={{ width: `${disk}%` }}
            />
          </div>
          <div className="metric-label">Disk</div>
        </div>
      </div>
    </div>
  )
}
