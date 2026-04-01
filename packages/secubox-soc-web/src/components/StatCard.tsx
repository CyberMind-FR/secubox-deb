import { ReactNode } from 'react'

interface StatCardProps {
  title: string
  value: string | number
  icon?: ReactNode
  trend?: {
    value: number
    direction: 'up' | 'down'
  }
  color?: string
}

export default function StatCard({ title, value, icon, trend, color }: StatCardProps) {
  return (
    <div className="stat-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div
          className="stat-card-value"
          style={{ color: color || 'var(--text-primary)' }}
        >
          {value}
        </div>
        {icon && (
          <div style={{ color: color || 'var(--text-muted)', opacity: 0.7 }}>
            {icon}
          </div>
        )}
      </div>
      <div className="stat-card-label">{title}</div>
      {trend && (
        <div className={`stat-card-trend ${trend.direction}`}>
          {trend.direction === 'up' ? '+' : '-'}{Math.abs(trend.value)}%
        </div>
      )}
    </div>
  )
}
