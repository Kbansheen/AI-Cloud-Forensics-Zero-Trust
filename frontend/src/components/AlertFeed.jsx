import React from 'react'

const ZONE_STYLE = {
  quarantine: { color: '#ef4444', label: 'QUARANTINE', icon: '⛔' },
  read_only:  { color: '#f97316', label: 'READ-ONLY',  icon: '🔒' },
  step_up_mfa:{ color: '#f59e0b', label: 'MFA',        icon: '🔐' },
}

function AlertCard({ alert }) {
  const zs = ZONE_STYLE[alert.zone] || { color: '#3b82f6', label: alert.zone, icon: '⚠' }
  const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'

  return (
    <div style={{
      padding: '10px 12px',
      borderLeft: `2px solid ${zs.color}`,
      background: 'var(--bg-card)',
      borderRadius: '0 6px 6px 0',
      marginBottom: 6,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11 }}>{zs.icon}</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: zs.color, letterSpacing: '0.05em' }}>
            {zs.label}
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-pri)' }}>
            {alert.user_id}
          </span>
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{ts}</span>
      </div>

      <div style={{ fontSize: 10, color: 'var(--text-sec)', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>
        {alert.role} · T={alert.trust?.toFixed(3)} · score={alert.anomaly_score?.toFixed(3)}
      </div>

      <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginBottom: alert.reasons?.length ? 4 : 0,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {alert.action}
      </div>

      {alert.reasons?.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {alert.reasons.slice(0, 2).map((r, i) => (
            <div key={i} style={{ fontSize: 9, color: zs.color, background: zs.color + '11', padding: '2px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)' }}>
              {r}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AlertFeed({ alerts }) {
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-sec)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Enforcement Alerts
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
          {alerts.length}
        </span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {alerts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            No alerts yet
          </div>
        ) : (
          alerts.map(a => <AlertCard key={a.alert_id} alert={a} />)
        )}
      </div>
    </div>
  )
}
