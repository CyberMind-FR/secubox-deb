import { Server, AlertTriangle, Activity, Cpu } from 'lucide-react'
import NodeCard from '../components/NodeCard'
import StatCard from '../components/StatCard'

interface FleetOverviewProps {
  nodes: Array<{
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
  }>
  summary: {
    total_nodes?: number
    nodes_online?: number
    nodes_offline?: number
    health_breakdown?: Record<string, number>
    resources?: {
      avg_cpu?: number
      avg_memory?: number
      avg_disk?: number
    }
    services_down?: number
    total_alerts?: number
    critical_nodes?: Array<{
      node_id: string
      hostname: string
    }>
  } | null
}

export default function FleetOverview({ nodes, summary }: FleetOverviewProps) {
  const critical = summary?.health_breakdown?.critical || 0
  const degraded = summary?.health_breakdown?.degraded || 0
  const healthy = summary?.health_breakdown?.healthy || 0

  return (
    <div>
      <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: 600 }}>
        Fleet Overview
      </h2>

      {/* Stats Row */}
      <div className="grid-4" style={{ marginBottom: '1.5rem' }}>
        <StatCard
          title="Total Nodes"
          value={summary?.total_nodes || 0}
          icon={<Server size={24} />}
          color="var(--cyber-cyan)"
        />
        <StatCard
          title="Online"
          value={`${summary?.nodes_online || 0} / ${summary?.total_nodes || 0}`}
          icon={<Activity size={24} />}
          color="var(--status-healthy)"
        />
        <StatCard
          title="Critical"
          value={critical}
          icon={<AlertTriangle size={24} />}
          color={critical > 0 ? 'var(--status-critical)' : 'var(--text-muted)'}
        />
        <StatCard
          title="Avg CPU"
          value={`${(summary?.resources?.avg_cpu || 0).toFixed(1)}%`}
          icon={<Cpu size={24} />}
        />
      </div>

      {/* Health Summary */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">Fleet Health</div>
        </div>
        <div className="card-body">
          <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                width: 12,
                height: 12,
                borderRadius: '50%',
                background: 'var(--status-healthy)'
              }} />
              <span>Healthy: <strong>{healthy}</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                width: 12,
                height: 12,
                borderRadius: '50%',
                background: 'var(--status-degraded)'
              }} />
              <span>Degraded: <strong>{degraded}</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                width: 12,
                height: 12,
                borderRadius: '50%',
                background: 'var(--status-critical)'
              }} />
              <span>Critical: <strong>{critical}</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                width: 12,
                height: 12,
                borderRadius: '50%',
                background: 'var(--status-offline)'
              }} />
              <span>Offline: <strong>{summary?.nodes_offline || 0}</strong></span>
            </div>
          </div>

          {/* Resource averages */}
          <div style={{ marginTop: '1.5rem' }}>
            <div style={{ marginBottom: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Average CPU</span>
                <span style={{ fontSize: '0.875rem' }}>{(summary?.resources?.avg_cpu || 0).toFixed(1)}%</span>
              </div>
              <div className="progress-bar" style={{ height: '8px' }}>
                <div
                  className={`progress-fill ${(summary?.resources?.avg_cpu || 0) < 50 ? 'low' : (summary?.resources?.avg_cpu || 0) < 80 ? 'medium' : 'high'}`}
                  style={{ width: `${summary?.resources?.avg_cpu || 0}%` }}
                />
              </div>
            </div>

            <div style={{ marginBottom: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Average Memory</span>
                <span style={{ fontSize: '0.875rem' }}>{(summary?.resources?.avg_memory || 0).toFixed(1)}%</span>
              </div>
              <div className="progress-bar" style={{ height: '8px' }}>
                <div
                  className={`progress-fill ${(summary?.resources?.avg_memory || 0) < 50 ? 'low' : (summary?.resources?.avg_memory || 0) < 80 ? 'medium' : 'high'}`}
                  style={{ width: `${summary?.resources?.avg_memory || 0}%` }}
                />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Average Disk</span>
                <span style={{ fontSize: '0.875rem' }}>{(summary?.resources?.avg_disk || 0).toFixed(1)}%</span>
              </div>
              <div className="progress-bar" style={{ height: '8px' }}>
                <div
                  className={`progress-fill ${(summary?.resources?.avg_disk || 0) < 70 ? 'low' : (summary?.resources?.avg_disk || 0) < 85 ? 'medium' : 'high'}`}
                  style={{ width: `${summary?.resources?.avg_disk || 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Nodes Grid */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Server size={18} />
            Edge Nodes
          </div>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            {nodes.length} nodes
          </span>
        </div>
        <div className="card-body">
          {nodes.length === 0 ? (
            <div className="empty-state">
              <Server size={48} />
              <p>No nodes registered</p>
              <p style={{ fontSize: '0.875rem' }}>Generate an enrollment token to add edge nodes</p>
            </div>
          ) : (
            <div className="node-grid">
              {nodes.map(node => (
                <NodeCard key={node.node_id} node={node} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
