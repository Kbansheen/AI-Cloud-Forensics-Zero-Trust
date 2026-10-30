import React from 'react'

const ZONE_SHORT = {
  normal_access: 'NORMAL', step_up_mfa: 'MFA', read_only: 'READ-ONLY', quarantine: 'QUARANTINE',
}

const ZONE_STYLE = {
  quarantine: { color: '#ef4444', label: 'QUARANTINE', icon: '⛔' },
  read_only:  { color: '#f97316', label: 'READ-ONLY',  icon: '🔒' },
  step_up_mfa:{ color: '#f59e0b', label: 'MFA',        icon: '🔐' },
}

export function AlertCard({ alert, onExplain }) {
  const zs = ZONE_STYLE[alert.zone] || { color: '#3b82f6', label: alert.zone, icon: '⚠' }
  const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'

  return (
    <div style={{
      padding: '14px 16px',
      borderLeft: `3px solid ${zs.color}`,
      background: 'var(--bg-card)',
      borderRadius: '0 8px 8px 0',
      marginBottom: 10,
    }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 4, marginBottom: 7 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12 }}>{zs.icon}</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: zs.color, letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>
            {zs.label}
          </span>
          {alert.zone_from && alert.zone_from !== alert.zone_to && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
              {ZONE_SHORT[alert.zone_from] || alert.zone_from} → {ZONE_SHORT[alert.zone_to] || alert.zone_to}
            </span>
          )}
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, color: 'var(--text-pri)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {alert.user_id}
          </span>
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-sec)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>{ts}</span>
      </div>

      <div style={{ fontSize: 11, color: 'var(--text-sec)', fontFamily: 'var(--font-mono)', marginBottom: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {alert.role} · T={alert.trust?.toFixed(3)} · score={alert.anomaly_score?.toFixed(3)}
        {/* Why this alert fired: either the event itself scored high, or the
            identity stayed below the boundary for N of its own events. */}
        {alert.anomaly_score >= 0.80
          ? ' · high-score event'
          : (alert.persisted > 1 ? ` · held ${alert.persisted} events` : '')}
      </div>

      <div style={{ fontSize: 12, color: 'var(--text-pri)', fontFamily: 'var(--font-mono)', marginBottom: alert.reasons?.length ? 6 : 0,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {alert.action}
      </div>

      {alert.reasons?.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginBottom: onExplain ? 8 : 0 }}>
          {alert.reasons.slice(0, 2).map((r, i) => (
            <div key={i} style={{ fontSize: 11, color: zs.color, background: zs.color + '18', padding: '3px 7px', borderRadius: 4, fontFamily: 'var(--font-mono)', lineHeight: 1.4 }}>
              {r}
            </div>
          ))}
        </div>
      )}

      {onExplain && (
        <button
          onClick={() => onExplain(alert)}
          style={{
            background:'rgba(124,58,237,0.18)', border:'1px solid rgba(167,139,250,0.55)',
            borderRadius:5, padding:'5px 12px', cursor:'pointer', fontFamily:'var(--font-mono)',
            fontSize:11, fontWeight:600, color:'#c4b5fd', letterSpacing:'.03em',
          }}
        >
          ✦ Explain
        </button>
      )}
    </div>
  )
}

export default function AlertFeed({ alerts, totalAlerts, onViewAll, onExplain }) {
  const total = totalAlerts ?? alerts.length
  const SIDEBAR_CAP = 30
  const shown = alerts.slice(0, SIDEBAR_CAP)

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-pri)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Enforcement Alerts
        </span>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--text-pri)' }}>
            {total}
          </span>
          {total > 0 && onViewAll && (
            <button
              onClick={onViewAll}
              style={{
                background:'rgba(124,58,237,0.18)', border:'1px solid rgba(167,139,250,0.55)',
                borderRadius:5, padding:'4px 10px', cursor:'pointer', fontFamily:'var(--font-mono)',
                fontSize:11, fontWeight:600, color:'#c4b5fd', textTransform:'uppercase', letterSpacing:'.03em',
              }}
            >
              View all →
            </button>
          )}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {alerts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--text-sec)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
            No alerts yet
          </div>
        ) : (
          <>
            {shown.map(a => <AlertCard key={a.alert_id} alert={a} onExplain={onExplain} />)}
            {total > SIDEBAR_CAP && (
              <div
                onClick={onViewAll}
                style={{
                  textAlign: 'center', padding: '12px 0', color: '#c4b5fd', fontWeight: 600,
                  fontFamily: 'var(--font-mono)', fontSize: 12, cursor: onViewAll ? 'pointer' : 'default',
                }}
              >
                + {total - SIDEBAR_CAP} more — view all →
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}