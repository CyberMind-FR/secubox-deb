/**
 * SecuBox SOC - Global View (Central Mode)
 * Cross-region overview for central SOC
 */

import { useState, useEffect } from 'react';
import { Globe, AlertTriangle, MapPin, Activity, Shield } from 'lucide-react';

interface RegionalSummary {
  region_id: string;
  region_name: string;
  status: string;
  nodes_online: number;
  nodes_total: number;
  alerts_count: number;
  critical_alerts: number;
  last_update: string;
}

interface CrossRegionThreat {
  threat_id: string;
  source_ip: string;
  severity: string;
  regions_affected: string[];
  nodes_affected: string[];
  first_seen: string;
  last_seen: string;
  total_hits: number;
  attack_types: string[];
}

interface GlobalSummary {
  total_regions: number;
  regions_online: number;
  total_nodes: number;
  total_nodes_online: number;
  total_alerts: number;
  total_critical: number;
  cross_region_threats: number;
  active_attackers: number;
}

export default function GlobalView() {
  const [globalSummary, setGlobalSummary] = useState<GlobalSummary | null>(null);
  const [regions, setRegions] = useState<RegionalSummary[]>([]);
  const [threats, setThreats] = useState<CrossRegionThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('jwt_token');
      const headers = { 'Authorization': `Bearer ${token}` };

      const [summaryRes, regionsRes, threatsRes] = await Promise.all([
        fetch('/api/v1/soc-gateway/global/summary', { headers }),
        fetch('/api/v1/soc-gateway/global/regions', { headers }),
        fetch('/api/v1/soc-gateway/global/threats', { headers })
      ]);

      if (!summaryRes.ok || !regionsRes.ok || !threatsRes.ok) {
        throw new Error('Not in central mode or unauthorized');
      }

      setGlobalSummary(await summaryRes.json());
      const regionsData = await regionsRes.json();
      setRegions(regionsData.regions || []);
      const threatsData = await threatsRes.json();
      setThreats(threatsData.threats || []);
      setError(null);
    } catch (err) {
      setError('Global view requires central SOC mode');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'var(--alert-critical)';
      case 'high': return 'var(--alert-high)';
      case 'medium': return 'var(--alert-medium)';
      default: return 'var(--alert-low)';
    }
  };

  const formatTime = (iso: string) => {
    if (!iso) return '--';
    const date = new Date(iso);
    return date.toLocaleTimeString();
  };

  if (loading) {
    return (
      <div className="page-loading">
        <Globe className="spin" size={48} />
        <p>Loading global view...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-error">
        <AlertTriangle size={48} />
        <h2>Central Mode Required</h2>
        <p>{error}</p>
        <p className="hint">Configure this gateway as central SOC to enable global view.</p>
      </div>
    );
  }

  return (
    <div className="page global-view">
      <header className="page-header">
        <h1><Globe size={28} /> Global SOC Overview</h1>
        <span className="badge badge-central">CENTRAL</span>
      </header>

      {/* Global Stats */}
      <div className="stats-grid global-stats">
        <div className="stat-card">
          <MapPin size={24} />
          <div className="stat-value">{globalSummary?.regions_online || 0}/{globalSummary?.total_regions || 0}</div>
          <div className="stat-label">Regions Online</div>
        </div>
        <div className="stat-card">
          <Activity size={24} />
          <div className="stat-value">{globalSummary?.total_nodes_online || 0}/{globalSummary?.total_nodes || 0}</div>
          <div className="stat-label">Total Nodes</div>
        </div>
        <div className="stat-card warning">
          <AlertTriangle size={24} />
          <div className="stat-value">{globalSummary?.total_critical || 0}</div>
          <div className="stat-label">Critical Alerts</div>
        </div>
        <div className="stat-card danger">
          <Shield size={24} />
          <div className="stat-value">{globalSummary?.cross_region_threats || 0}</div>
          <div className="stat-label">Cross-Region Threats</div>
        </div>
      </div>

      {/* Regional Grid */}
      <section className="section">
        <h2><MapPin size={20} /> Regional SOCs</h2>
        <div className="region-grid">
          {regions.length === 0 ? (
            <div className="empty-state">
              <p>No regional SOCs connected</p>
              <p className="hint">Generate enrollment tokens to connect regional SOCs</p>
            </div>
          ) : (
            regions.map(region => (
              <div key={region.region_id} className={`region-card status-${region.status}`}>
                <div className="region-header">
                  <span className="region-name">{region.region_name || region.region_id}</span>
                  <span className={`status-dot ${region.status}`}></span>
                </div>
                <div className="region-stats">
                  <div className="region-stat">
                    <span className="label">Nodes</span>
                    <span className="value">{region.nodes_online}/{region.nodes_total}</span>
                  </div>
                  <div className="region-stat">
                    <span className="label">Alerts</span>
                    <span className="value">{region.alerts_count}</span>
                  </div>
                  <div className="region-stat critical">
                    <span className="label">Critical</span>
                    <span className="value">{region.critical_alerts}</span>
                  </div>
                </div>
                <div className="region-footer">
                  Last update: {formatTime(region.last_update)}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {/* Cross-Region Threats */}
      <section className="section">
        <h2><Shield size={20} /> Cross-Region Threats</h2>
        {threats.length === 0 ? (
          <div className="empty-state">
            <p>No cross-region threats detected</p>
            <p className="hint">Threats appear when the same attacker targets multiple regions</p>
          </div>
        ) : (
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Severity</th>
                  <th>Regions</th>
                  <th>Nodes</th>
                  <th>Hits</th>
                  <th>Attack Types</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {threats.map(threat => (
                  <tr key={threat.threat_id} className={`severity-${threat.severity}`}>
                    <td className="ip-cell">{threat.source_ip}</td>
                    <td>
                      <span
                        className="severity-badge"
                        style={{ backgroundColor: getSeverityColor(threat.severity) }}
                      >
                        {threat.severity.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span className="count-badge">{threat.regions_affected.length}</span>
                      <span className="regions-list">
                        {threat.regions_affected.join(', ')}
                      </span>
                    </td>
                    <td>{threat.nodes_affected.length}</td>
                    <td>{threat.total_hits}</td>
                    <td className="attack-types">
                      {threat.attack_types.slice(0, 3).join(', ')}
                      {threat.attack_types.length > 3 && '...'}
                    </td>
                    <td>{formatTime(threat.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <style>{`
        .global-view {
          padding: 1.5rem;
        }

        .page-header {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-bottom: 1.5rem;
        }

        .page-header h1 {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin: 0;
        }

        .badge-central {
          background: linear-gradient(135deg, var(--cyber-cyan), var(--void-purple));
          color: white;
          padding: 0.25rem 0.75rem;
          border-radius: 4px;
          font-size: 0.75rem;
          font-weight: bold;
        }

        .global-stats {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 1rem;
          margin-bottom: 2rem;
        }

        .stat-card {
          background: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 1.25rem;
          text-align: center;
        }

        .stat-card.warning {
          border-color: var(--alert-medium);
        }

        .stat-card.danger {
          border-color: var(--alert-critical);
        }

        .stat-value {
          font-size: 2rem;
          font-weight: bold;
          color: var(--cyber-cyan);
          margin: 0.5rem 0;
        }

        .stat-card.warning .stat-value {
          color: var(--alert-medium);
        }

        .stat-card.danger .stat-value {
          color: var(--alert-critical);
        }

        .stat-label {
          color: var(--text-muted);
          font-size: 0.85rem;
        }

        .section {
          margin-bottom: 2rem;
        }

        .section h2 {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1rem;
          color: var(--text-primary);
        }

        .region-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
          gap: 1rem;
        }

        .region-card {
          background: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 1rem;
        }

        .region-card.status-online {
          border-left: 3px solid var(--status-online);
        }

        .region-card.status-degraded {
          border-left: 3px solid var(--status-warning);
        }

        .region-card.status-offline {
          border-left: 3px solid var(--status-offline);
        }

        .region-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1rem;
        }

        .region-name {
          font-weight: bold;
          font-size: 1.1rem;
        }

        .status-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }

        .status-dot.online {
          background: var(--status-online);
          box-shadow: 0 0 8px var(--status-online);
        }

        .status-dot.degraded {
          background: var(--status-warning);
        }

        .status-dot.offline {
          background: var(--status-offline);
        }

        .region-stats {
          display: flex;
          gap: 1rem;
          margin-bottom: 0.75rem;
        }

        .region-stat {
          flex: 1;
          text-align: center;
        }

        .region-stat .label {
          display: block;
          font-size: 0.75rem;
          color: var(--text-muted);
        }

        .region-stat .value {
          font-size: 1.25rem;
          font-weight: bold;
        }

        .region-stat.critical .value {
          color: var(--alert-critical);
        }

        .region-footer {
          font-size: 0.75rem;
          color: var(--text-muted);
          border-top: 1px solid var(--border-color);
          padding-top: 0.5rem;
        }

        .threats-table {
          overflow-x: auto;
        }

        .threats-table table {
          width: 100%;
          border-collapse: collapse;
        }

        .threats-table th,
        .threats-table td {
          padding: 0.75rem;
          text-align: left;
          border-bottom: 1px solid var(--border-color);
        }

        .threats-table th {
          background: var(--bg-secondary);
          color: var(--text-muted);
          font-weight: 500;
        }

        .threats-table tr.severity-critical {
          background: rgba(231, 76, 60, 0.1);
        }

        .ip-cell {
          font-family: monospace;
        }

        .severity-badge {
          padding: 0.2rem 0.5rem;
          border-radius: 3px;
          color: white;
          font-size: 0.7rem;
          font-weight: bold;
        }

        .count-badge {
          background: var(--cyber-cyan);
          color: var(--cosmos-black);
          padding: 0.2rem 0.5rem;
          border-radius: 3px;
          font-size: 0.75rem;
          margin-right: 0.5rem;
        }

        .regions-list {
          font-size: 0.85rem;
          color: var(--text-muted);
        }

        .attack-types {
          font-size: 0.85rem;
          color: var(--text-muted);
        }

        .empty-state {
          text-align: center;
          padding: 3rem;
          color: var(--text-muted);
        }

        .empty-state .hint {
          font-size: 0.85rem;
          margin-top: 0.5rem;
        }

        .page-loading,
        .page-error {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: 400px;
          color: var(--text-muted);
        }

        .page-error h2 {
          color: var(--alert-critical);
          margin: 1rem 0 0.5rem;
        }

        .spin {
          animation: spin 2s linear infinite;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
