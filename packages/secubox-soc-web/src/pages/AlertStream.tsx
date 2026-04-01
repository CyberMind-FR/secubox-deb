import { useState, useEffect } from 'react'
import { AlertTriangle, Shield, RefreshCw } from 'lucide-react'
import AlertItem from '../components/AlertItem'
import { useAlerts } from '../hooks/useFleet'

interface AlertStreamProps {
  lastMessage: {
    type: string
    data: unknown
    timestamp: string
  } | null
}

type FilterType = 'all' | 'critical' | 'high' | 'medium' | 'crowdsec' | 'suricata' | 'waf'

export default function AlertStream({ lastMessage }: AlertStreamProps) {
  const { alerts, threats, loading, refreshAlerts, refreshThreats } = useAlerts()
  const [filter, setFilter] = useState<FilterType>('all')
  const [showThreats, setShowThreats] = useState(false)

  useEffect(() => {
    refreshAlerts()
    refreshThreats()
    const interval = setInterval(() => {
      refreshAlerts()
      refreshThreats()
    }, 15000)
    return () => clearInterval(interval)
  }, [refreshAlerts, refreshThreats])

  // Handle real-time updates
  useEffect(() => {
    if (lastMessage?.type === 'alert') {
      refreshAlerts()
    }
  }, [lastMessage, refreshAlerts])

  const filteredAlerts = alerts.filter(alert => {
    if (filter === 'all') return true
    if (filter === 'critical') return alert.severity === 'critical' || alert.severity === 1
    if (filter === 'high') return alert.severity === 'high' || alert.severity === 2
    if (filter === 'medium') return alert.severity === 'medium' || alert.severity === 3
    if (filter === 'crowdsec') return alert.source === 'crowdsec'
    if (filter === 'suricata') return alert.source === 'suricata'
    if (filter === 'waf') return alert.source === 'waf'
    return true
  })

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 600 }}>
          {showThreats ? 'Correlated Threats' : 'Alert Stream'}
        </h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className={`btn ${showThreats ? 'btn-secondary' : 'btn-primary'}`}
            onClick={() => setShowThreats(false)}
          >
            <AlertTriangle size={16} />
            Alerts
          </button>
          <button
            className={`btn ${showThreats ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setShowThreats(true)}
          >
            <Shield size={16} />
            Threats ({threats.length})
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => { refreshAlerts(); refreshThreats(); }}
            disabled={loading}
          >
            <RefreshCw size={16} className={loading ? 'spinner' : ''} />
          </button>
        </div>
      </div>

      {!showThreats && (
        <div className="filter-bar">
          {(['all', 'critical', 'high', 'medium'] as FilterType[]).map(f => (
            <button
              key={f}
              className={`filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
          <span style={{ margin: '0 0.5rem', color: 'var(--text-muted)' }}>|</span>
          {(['crowdsec', 'suricata', 'waf'] as FilterType[]).map(f => (
            <button
              key={f}
              className={`filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      )}

      <div className="card">
        <div className="card-body">
          {showThreats ? (
            threats.length === 0 ? (
              <div className="empty-state">
                <Shield size={48} />
                <p>No correlated threats detected</p>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                  Threats are detected when the same IP attacks multiple nodes
                </p>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Nodes Affected</th>
                    <th>Total Hits</th>
                    <th>Severity</th>
                    <th>Recommended Action</th>
                    <th>Scenarios</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((threat, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace' }}>{threat.source_ip as string}</td>
                      <td>
                        <span className={`health-badge ${
                          (threat.nodes_affected as string[])?.length >= 5 ? 'critical' :
                          (threat.nodes_affected as string[])?.length >= 3 ? 'degraded' : 'healthy'
                        }`}>
                          {(threat.nodes_affected as string[])?.length || 0} nodes
                        </span>
                      </td>
                      <td>{threat.total_hits as number}</td>
                      <td>
                        <span className={`health-badge ${threat.severity as string}`}>
                          {threat.severity as string}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          color: threat.recommended_action === 'block_globally'
                            ? 'var(--status-critical)'
                            : threat.recommended_action === 'rate_limit'
                            ? 'var(--status-degraded)'
                            : 'var(--text-muted)'
                        }}>
                          {threat.recommended_action as string}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {(threat.scenarios as string[])?.join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          ) : (
            filteredAlerts.length === 0 ? (
              <div className="empty-state">
                <AlertTriangle size={48} />
                <p>No alerts matching filter</p>
              </div>
            ) : (
              <div className="alert-list">
                {filteredAlerts.map((alert, idx) => (
                  <AlertItem key={idx} alert={alert} />
                ))}
              </div>
            )
          )}
        </div>
      </div>
    </div>
  )
}
