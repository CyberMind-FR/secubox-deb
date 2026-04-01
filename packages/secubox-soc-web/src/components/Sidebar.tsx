import { NavLink } from 'react-router-dom'
import { Shield, LayoutDashboard, AlertTriangle, Settings, Map, Layers } from 'lucide-react'

interface SidebarProps {
  isOpen: boolean
  summary: {
    total_nodes?: number
    nodes_online?: number
    nodes_offline?: number
    health_breakdown?: Record<string, number>
    total_alerts?: number
  } | null
  mode?: string
}

export default function Sidebar({ isOpen, summary, mode = 'central' }: SidebarProps) {
  const critical = summary?.health_breakdown?.critical || 0
  const degraded = summary?.health_breakdown?.degraded || 0
  const isCentral = mode === 'central'

  return (
    <aside className={`sidebar ${isOpen ? '' : 'closed'}`}>
      <div className="sidebar-header">
        <Shield className="sidebar-logo" />
        <span className="sidebar-title">SecuBox SOC</span>
        <span className={`mode-badge mode-${mode}`}>{mode.toUpperCase()}</span>
      </div>

      <nav className="sidebar-nav">
        {isCentral && (
          <NavLink to="/global" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Layers />
            <span>Global View</span>
          </NavLink>
        )}

        <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <LayoutDashboard />
          <span>Fleet Overview</span>
        </NavLink>

        <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <AlertTriangle />
          <span>Alerts</span>
          {(summary?.total_alerts || 0) > 0 && (
            <span style={{
              marginLeft: 'auto',
              background: 'var(--status-critical)',
              color: 'white',
              padding: '0.125rem 0.5rem',
              borderRadius: '9999px',
              fontSize: '0.75rem'
            }}>
              {summary?.total_alerts}
            </span>
          )}
        </NavLink>

        <NavLink to="/threats" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Map />
          <span>Threat Map</span>
        </NavLink>

        <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Settings />
          <span>Settings</span>
        </NavLink>
      </nav>

      <div className="sidebar-stats">
        <div className="stat-row">
          <span className="stat-label">Nodes Online</span>
          <span className="stat-value healthy">
            {summary?.nodes_online || 0} / {summary?.total_nodes || 0}
          </span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Critical</span>
          <span className={`stat-value ${critical > 0 ? 'critical' : ''}`}>
            {critical}
          </span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Degraded</span>
          <span className={`stat-value ${degraded > 0 ? 'degraded' : ''}`}>
            {degraded}
          </span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Offline</span>
          <span className="stat-value">
            {summary?.nodes_offline || 0}
          </span>
        </div>
      </div>
    </aside>
  )
}
