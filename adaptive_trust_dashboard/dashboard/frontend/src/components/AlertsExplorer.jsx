import React, { useEffect, useMemo, useRef, useState } from 'react'
import { AlertCard } from './AlertFeed'

const ZONE_FILTERS = [
  { key: 'all',         label: 'All',        color: 'var(--text-sec)' },
  { key: 'quarantine',  label: 'QUARANTINE', color: '#ef4444' },
  { key: 'read_only',   label: 'READ-ONLY',  color: '#f97316' },
  { key: 'step_up_mfa', label: 'MFA',        color: '#f59e0b' },
]

async function fetchExplain(alertId) {
  const res = await fetch(`/api/alerts/${alertId}/explain`)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

function ExplainPanel({ alertId }) {
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    let cancelled = false
    setState({ loading: true, data: null, error: null })
    fetchExplain(alertId)
      .then(data => { if (!cancelled) setState({ loading: false, data, error: null }) })
      .catch(e => { if (!cancelled) setState({ loading: false, data: null, error: e.message }) })
    return () => { cancelled = true }
  }, [alertId])

  if (state.loading) {
    return (
      <div style={{
        margin: '0 0 10px', padding: '12px 14px', background: '#05070d',
        border: '1px solid var(--border)', borderRadius: 6,
        fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-sec)',
      }}>
        computing SHAP attribution…
      </div>
    )
  }

  if (state.error) {
    return (
      <div style={{
        margin: '0 0 10px', padding: '12px 14px', background: '#05070d',
        border: '1px solid var(--border)', borderRadius: 6,
        fontFamily: 'var(--font-mono)', fontSize: 12, color: '#ef4444',
      }}>
        couldn't explain this alert: {state.error}
      </div>
    )
  }

  const { explanation, method, note } = state.data

  if (!explanation || explanation.length === 0) {
    return (
      <div style={{
        margin: '0 0 10px', padding: '14px 16px', background: '#05070d',
        border: '1px solid var(--border)', borderRadius: 6,
      }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: '#fbbf24',
          marginBottom: 8, textTransform: 'uppercase', letterSpacing: '.04em',
        }}>
          {method}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-pri)', lineHeight: 1.7 }}>
          {note}
        </div>
      </div>
    )
  }

  const maxAbs = Math.max(...explanation.map(e => Math.abs(e.contribution)), 0.0001)

  return (
    <div style={{
      margin: '0 0 10px', padding: '14px 16px', background: '#05070d',
      border: '1px solid var(--border)', borderRadius: 6,
    }}>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: '#c4b5fd',
        marginBottom: 12, textTransform: 'uppercase', letterSpacing: '.04em',
      }}>
        {method}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {explanation.map((f, i) => {
          const pct = (Math.abs(f.contribution) / maxAbs) * 100
          const up = f.contribution > 0
          const color = up ? '#f87171' : '#34d399'
          return (
            <div key={i}>
              <div style={{
                display: 'flex', justifyContent: 'space-between',
                fontFamily: 'var(--font-mono)', fontSize: 13, marginBottom: 4,
              }}>
                <span style={{ color: 'var(--text-pri)', fontWeight: 600 }}>{f.feature}</span>
                <span style={{ color, fontWeight: 700 }}>
                  {up ? '+' : ''}{f.contribution.toFixed(3)}
                </span>
              </div>
              <div style={{ height: 6, borderRadius: 3, background: 'var(--bg-card)', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3 }} />
              </div>
            </div>
          )
        })}
      </div>
      <div style={{
        marginTop: 14, fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, color: 'var(--text-sec)',
        display: 'flex', gap: 18,
      }}>
        <span><span style={{ color: '#f87171' }}>■</span> increases anomaly</span>
        <span><span style={{ color: '#34d399' }}>■</span> decreases anomaly</span>
      </div>
    </div>
  )
}

export default function AlertsExplorer({ alerts, onClose, focusAlertId }) {
  const [zoneFilter, setZoneFilter] = useState('all')
  const [query,      setQuery]      = useState('')
  const [expandedId, setExpandedId] = useState(focusAlertId || null)
  const focusRef = useRef(null)

  useEffect(() => {
    if (focusAlertId && focusRef.current) {
      focusRef.current.scrollIntoView({ block: 'center' })
    }
  }, [focusAlertId])

  const zoneCounts = useMemo(() => {
    const c = { quarantine: 0, read_only: 0, step_up_mfa: 0 }
    for (const a of alerts) if (c[a.zone] !== undefined) c[a.zone]++
    return c
  }, [alerts])

  const roleCounts = useMemo(() => {
    const c = {}
    for (const a of alerts) c[a.role] = (c[a.role] || 0) + 1
    return Object.entries(c).sort((a, b) => b[1] - a[1])
  }, [alerts])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return alerts.filter(a => {
      if (zoneFilter !== 'all' && a.zone !== zoneFilter) return false
      if (!q) return true
      return (
        a.user_id?.toLowerCase().includes(q) ||
        a.role?.toLowerCase().includes(q) ||
        a.action?.toLowerCase().includes(q) ||
        a.reasons?.some(r => r.toLowerCase().includes(q))
      )
    })
  }, [alerts, zoneFilter, query])

  const toggleExplain = (alert) => {
    setExpandedId(id => id === alert.alert_id ? null : alert.alert_id)
  }

  return (
    <div
      onClick={onClose}
      style={{
        position:'fixed', inset:0, zIndex:10000,
        background:'rgba(3,5,10,.75)', backdropFilter:'blur(2px)',
        display:'flex', alignItems:'center', justifyContent:'center',
        padding:'40px 20px',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width:'100%', maxWidth:820, maxHeight:'85vh',
          background:'var(--bg-surface)', border:'1px solid var(--border)',
          borderRadius:10, display:'flex', flexDirection:'column',
          boxShadow:'0 20px 60px rgba(0,0,0,.6)',
        }}
      >
        {/* Header */}
        <div style={{
          padding:'16px 18px', borderBottom:'1px solid var(--border)',
          display:'flex', alignItems:'center', justifyContent:'space-between',
        }}>
          <div>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:13, fontWeight:700, color:'var(--text-pri)' }}>
              Enforcement Alerts
            </div>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-sec)', marginTop:3 }}>
              {alerts.length} total this session · click ✦ Explain on any alert for a SHAP breakdown
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background:'none', border:'1px solid var(--border)', borderRadius:6,
              width:28, height:28, cursor:'pointer', color:'var(--text-sec)', fontSize:14,
            }}
          >
            ✕
          </button>
        </div>

        {/* Zone filter chips + per-role breakdown */}
        <div style={{ padding:'12px 18px', borderBottom:'1px solid var(--border)' }}>
          <div style={{ display:'flex', gap:6, marginBottom:10, flexWrap:'wrap' }}>
            {ZONE_FILTERS.map(zf => {
              const count = zf.key === 'all' ? alerts.length : zoneCounts[zf.key]
              const active = zoneFilter === zf.key
              return (
                <button
                  key={zf.key}
                  onClick={() => setZoneFilter(zf.key)}
                  style={{
                    fontFamily:'var(--font-mono)', fontSize:11, fontWeight:600, padding:'5px 12px', borderRadius:12,
                    cursor:'pointer', letterSpacing:'.03em',
                    border:`1px solid ${active ? zf.color : 'var(--border)'}`,
                    background: active ? `${zf.color}18` : 'transparent',
                    color: active ? zf.color : 'var(--text-sec)',
                  }}
                >
                  {zf.label} · {count}
                </button>
              )
            })}
          </div>

          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search by user, role, action, or reason…"
            style={{
              width:'100%', boxSizing:'border-box', background:'var(--bg-card)',
              border:'1px solid var(--border)', borderRadius:6, padding:'9px 12px',
              color:'var(--text-pri)', fontFamily:'var(--font-mono)', fontSize:13,
              outline:'none',
            }}
          />

          {roleCounts.length > 0 && (
            <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop:10 }}>
              {roleCounts.map(([role, count]) => (
                <span
                  key={role}
                  style={{
                    fontFamily:'var(--font-mono)', fontSize:11, fontWeight:600, color:'var(--text-sec)',
                    border:'1px solid var(--border)', borderRadius:4, padding:'3px 9px',
                  }}
                >
                  {role}: {count}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* List */}
        <div style={{ flex:1, overflowY:'auto', padding:'14px 18px' }}>
          {filtered.length === 0 ? (
            <div style={{ textAlign:'center', padding:'40px 0', color:'var(--text-sec)', fontFamily:'var(--font-mono)', fontSize:13 }}>
              No alerts match this filter
            </div>
          ) : (
            <>
              <div style={{ fontFamily:'var(--font-mono)', fontSize:12, fontWeight:600, color:'var(--text-sec)', marginBottom:10 }}>
                showing {filtered.length} of {alerts.length}
              </div>
              {filtered.map(a => (
                <div key={a.alert_id} ref={a.alert_id === focusAlertId ? focusRef : null}>
                  <AlertCard alert={a} onExplain={toggleExplain} />
                  {expandedId === a.alert_id && <ExplainPanel alertId={a.alert_id} />}
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  )
}