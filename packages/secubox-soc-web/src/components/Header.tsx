import { Menu, RefreshCw, Bell, Globe, MapPin, Server } from 'lucide-react'

interface HeaderProps {
  isConnected: boolean
  mode?: string
  regionName?: string
  onToggleSidebar: () => void
}

export default function Header({ isConnected, mode = 'central', regionName, onToggleSidebar }: HeaderProps) {
  const getModeIcon = () => {
    switch (mode) {
      case 'central': return <Globe size={16} />
      case 'regional': return <MapPin size={16} />
      default: return <Server size={16} />
    }
  }

  const getModeLabel = () => {
    if (mode === 'regional' && regionName) {
      return regionName
    }
    return mode.charAt(0).toUpperCase() + mode.slice(1) + ' SOC'
  }

  return (
    <header className="header">
      <div className="header-left">
        <button className="menu-btn" onClick={onToggleSidebar}>
          <Menu size={20} />
        </button>
        <h1 className="header-title">Security Operations Center</h1>
        <div className={`mode-indicator mode-${mode}`}>
          {getModeIcon()}
          <span>{getModeLabel()}</span>
        </div>
      </div>

      <div className="header-right">
        <div className="connection-status">
          <span className={`status-dot ${isConnected ? 'connected' : ''}`} />
          <span>{isConnected ? 'Live' : 'Offline'}</span>
        </div>

        <button className="menu-btn" title="Notifications">
          <Bell size={20} />
        </button>

        <button className="menu-btn" title="Refresh" onClick={() => window.location.reload()}>
          <RefreshCw size={20} />
        </button>
      </div>

      <style>{`
        .mode-indicator {
          display: flex;
          align-items: center;
          gap: 0.4rem;
          padding: 0.35rem 0.75rem;
          border-radius: 4px;
          font-size: 0.8rem;
          font-weight: 500;
          margin-left: 1rem;
        }

        .mode-indicator.mode-central {
          background: linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(110, 64, 201, 0.2));
          color: var(--cyber-cyan);
          border: 1px solid var(--cyber-cyan);
        }

        .mode-indicator.mode-regional {
          background: rgba(46, 204, 113, 0.15);
          color: var(--status-online);
          border: 1px solid var(--status-online);
        }

        .mode-indicator.mode-edge {
          background: rgba(241, 196, 15, 0.15);
          color: var(--status-warning);
          border: 1px solid var(--status-warning);
        }
      `}</style>
    </header>
  )
}
