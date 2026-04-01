interface AlertItemProps {
  alert: {
    source?: string
    ip?: string
    scenario?: string
    signature?: string
    reason?: string
    severity?: string | number
    timestamp?: string
    created_at?: string
    node_id?: string
    node_hostname?: string
  }
}

function getSeverityClass(severity: string | number | undefined): string {
  if (typeof severity === 'number') {
    if (severity <= 1) return 'critical'
    if (severity === 2) return 'high'
    if (severity === 3) return 'medium'
    return 'low'
  }
  return severity || 'medium'
}

function formatTime(timestamp: string | undefined): string {
  if (!timestamp) return ''
  try {
    const dt = new Date(timestamp)
    return dt.toLocaleTimeString('en-US', { hour12: false })
  } catch {
    return timestamp.slice(0, 8)
  }
}

export default function AlertItem({ alert }: AlertItemProps) {
  const severityClass = getSeverityClass(alert.severity)
  const reason = alert.scenario || alert.signature || alert.reason || 'Unknown alert'
  const time = formatTime(alert.timestamp || alert.created_at)

  return (
    <div className="alert-item">
      <div className={`alert-severity ${severityClass}`} />

      <div className="alert-content">
        <div className="alert-title">{reason}</div>
        <div className="alert-meta">
          <span>{alert.source || 'unknown'}</span>
          <span>{alert.ip}</span>
          <span>{alert.node_hostname || alert.node_id}</span>
        </div>
      </div>

      <div className="alert-time">{time}</div>
    </div>
  )
}
