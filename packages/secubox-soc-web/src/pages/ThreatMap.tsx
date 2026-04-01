import { useState, useEffect } from 'react'
import { Globe, RefreshCw, AlertTriangle } from 'lucide-react'
import { useAlerts } from '../hooks/useFleet'

export default function ThreatMap() {
  const { threats, loading, refreshThreats } = useAlerts()
  const [selectedThreat, setSelectedThreat] = useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    refreshThreats()
    const interval = setInterval(refreshThreats, 30000)
    return () => clearInterval(interval)
  }, [refreshThreats])

  // Count threats by severity
  const critical = threats.filter(t => t.severity === 'critical').length
  const high = threats.filter(t => t.severity === 'high').length
  const medium = threats.filter(t => t.severity === 'medium').length

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 600 }}>
          <Globe size={24} style={{ verticalAlign: 'middle', marginRight: '0.5rem' }} />
          Threat Intelligence Map
        </h2>
        <button
          className="btn btn-secondary"
          onClick={() => refreshThreats()}
          disabled={loading}
        >
          <RefreshCw size={16} className={loading ? 'spinner' : ''} />
          Refresh
        </button>
      </div>

      {/* Threat Summary */}
      <div className="grid-3" style={{ marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div className="stat-card-value" style={{ color: 'var(--status-critical)' }}>{critical}</div>
          <div className="stat-card-label">Critical Threats</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-value" style={{ color: 'var(--cinnabar)' }}>{high}</div>
          <div className="stat-card-label">High Threats</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-value" style={{ color: 'var(--status-degraded)' }}>{medium}</div>
          <div className="stat-card-label">Medium Threats</div>
        </div>
      </div>

      <div className="grid-2">
        {/* Threat List */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <AlertTriangle size={18} />
              Active Threats
            </div>
          </div>
          <div className="card-body" style={{ maxHeight: '500px', overflow: 'auto' }}>
            {threats.length === 0 ? (
              <div className="empty-state">
                <Globe size={48} />
                <p>No correlated threats detected</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {threats.map((threat, idx) => (
                  <div
                    key={idx}
                    className={`alert-item ${selectedThreat === threat ? 'selected' : ''}`}
                    onClick={() => setSelectedThreat(threat)}
                    style={{
                      cursor: 'pointer',
                      background: selectedThreat === threat ? 'var(--panel-hover)' : undefined,
                      borderColor: selectedThreat === threat ? 'var(--cyber-cyan)' : undefined
                    }}
                  >
                    <div className={`alert-severity ${threat.severity as string}`} />
                    <div className="alert-content">
                      <div className="alert-title" style={{ fontFamily: 'monospace' }}>
                        {threat.source_ip as string}
                      </div>
                      <div className="alert-meta">
                        <span>{(threat.nodes_affected as string[])?.length} nodes</span>
                        <span>{threat.total_hits as number} hits</span>
                      </div>
                    </div>
                    <span className={`health-badge ${threat.severity as string}`}>
                      {threat.severity as string}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Threat Details */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Threat Details</div>
          </div>
          <div className="card-body">
            {selectedThreat ? (
              <div>
                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Source IP</div>
                  <div style={{ fontSize: '1.5rem', fontFamily: 'monospace', color: 'var(--cyber-cyan)' }}>
                    {selectedThreat.source_ip as string}
                  </div>
                </div>

                <div className="grid-2" style={{ marginBottom: '1.5rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Severity</div>
                    <span className={`health-badge ${selectedThreat.severity as string}`}>
                      {selectedThreat.severity as string}
                    </span>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Recommended Action</div>
                    <span style={{
                      color: selectedThreat.recommended_action === 'block_globally'
                        ? 'var(--status-critical)'
                        : selectedThreat.recommended_action === 'rate_limit'
                        ? 'var(--status-degraded)'
                        : 'var(--text-muted)'
                    }}>
                      {selectedThreat.recommended_action as string}
                    </span>
                  </div>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Affected Nodes</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {(selectedThreat.nodes_affected as string[])?.map((nodeId, idx) => (
                      <span key={idx} style={{
                        padding: '0.25rem 0.5rem',
                        background: 'var(--panel-border)',
                        borderRadius: '0.25rem',
                        fontSize: '0.75rem',
                        fontFamily: 'monospace'
                      }}>
                        {nodeId}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Attack Scenarios</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {(selectedThreat.scenarios as string[])?.map((scenario, idx) => (
                      <span key={idx} style={{
                        padding: '0.25rem 0.5rem',
                        background: 'rgba(230, 57, 70, 0.15)',
                        color: 'var(--cinnabar)',
                        borderRadius: '0.25rem',
                        fontSize: '0.75rem'
                      }}>
                        {scenario}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="grid-2">
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>First Seen</div>
                    <div style={{ fontSize: '0.875rem' }}>
                      {new Date(selectedThreat.first_seen as string).toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Last Seen</div>
                    <div style={{ fontSize: '0.875rem' }}>
                      {new Date(selectedThreat.last_seen as string).toLocaleString()}
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.5rem' }}>
                  <button className="btn btn-danger">
                    Block Globally
                  </button>
                  <button className="btn btn-secondary">
                    View in WHOIS
                  </button>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <AlertTriangle size={48} />
                <p>Select a threat to view details</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
