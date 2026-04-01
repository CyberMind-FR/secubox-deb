import { Routes, Route } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import FleetOverview from './pages/FleetOverview'
import AlertStream from './pages/AlertStream'
import NodeDetail from './pages/NodeDetail'
import ThreatMap from './pages/ThreatMap'
import GlobalView from './pages/GlobalView'
import Settings from './pages/Settings'
import { useWebSocket } from './hooks/useWebSocket'
import { useFleet } from './hooks/useFleet'

interface HierarchyStatus {
  mode: string;
  region_id?: string;
  region_name?: string;
  has_upstream?: boolean;
}

function App() {
  const { isConnected, lastMessage } = useWebSocket('/api/v1/soc-gateway/ws/alerts')
  const { summary, nodes, refreshFleet } = useFleet()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [hierarchy, setHierarchy] = useState<HierarchyStatus>({ mode: 'central' })

  // Fetch hierarchy status
  const fetchHierarchy = async () => {
    try {
      const token = localStorage.getItem('jwt_token')
      const res = await fetch('/api/v1/soc-gateway/hierarchy/status', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (res.ok) {
        setHierarchy(await res.json())
      }
    } catch (err) {
      console.error('Failed to fetch hierarchy status:', err)
    }
  }

  // Refresh fleet data periodically
  useEffect(() => {
    refreshFleet()
    fetchHierarchy()
    const interval = setInterval(() => {
      refreshFleet()
      fetchHierarchy()
    }, 30000)
    return () => clearInterval(interval)
  }, [refreshFleet])

  return (
    <div className="app">
      <Sidebar isOpen={sidebarOpen} summary={summary} mode={hierarchy.mode} />
      <div className={`main-content ${sidebarOpen ? '' : 'sidebar-closed'}`}>
        <Header
          isConnected={isConnected}
          mode={hierarchy.mode}
          regionName={hierarchy.region_name}
          onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
        />
        <div className="content">
          <Routes>
            <Route path="/" element={<FleetOverview nodes={nodes} summary={summary} />} />
            <Route path="/alerts" element={<AlertStream lastMessage={lastMessage} />} />
            <Route path="/threats" element={<ThreatMap />} />
            <Route path="/global" element={<GlobalView />} />
            <Route path="/settings" element={<Settings hierarchy={hierarchy} onUpdate={fetchHierarchy} />} />
            <Route path="/node/:nodeId" element={<NodeDetail />} />
          </Routes>
        </div>
      </div>
    </div>
  )
}

export default App
