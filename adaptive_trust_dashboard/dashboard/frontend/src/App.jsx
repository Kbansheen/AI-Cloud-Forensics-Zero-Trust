import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import MetricsBar from './components/MetricsBar'
import TrustGrid from './components/TrustGrid'
import UserDetailPanel from './components/UserDetailPanel'
import AlertFeed from './components/AlertFeed'
import AlertsExplorer from './components/AlertsExplorer'
import ControlPanel from './components/ControlPanel'
import ComparisonPanel from './components/ComparisonPanel'
import BaselineScorecard from './components/BaselineScorecard'

const API = ''
const api = async (path, opts = {}) => {
  const res = await fetch(API + path, opts)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

// Merge incoming alerts into the existing list instead of replacing it —
// the websocket only ever sends the 5 most-recent alerts per tick, so a
// plain setAlerts(incoming) was silently discarding everything earlier
// in the session. Dedupe by alert_id, newest first, capped so the list
// can't grow unbounded across a very long session.
function mergeAlerts(prev, incoming, cap = 500) {
  if (!incoming?.length) return prev
  const seen = new Set(prev.map(a => a.alert_id))
  const fresh = incoming.filter(a => !seen.has(a.alert_id))
  if (fresh.length === 0) return prev
  return [...fresh, ...prev].slice(0, cap)
}

export default function App() {
  const [users,        setUsers]        = useState([])
  const [alerts,       setAlerts]       = useState([])
  const [showAllAlerts, setShowAllAlerts] = useState(false)
  const [focusAlertId,  setFocusAlertId]  = useState(null)
  const [metrics,      setMetrics]      = useState({})
  const [status,       setStatus]       = useState({})
  const [selectedUser, setSelectedUser] = useState(null)
  const [userHistory,  setUserHistory]  = useState([])
  const [userUcb,      setUserUcb]      = useState(null)
  const [wsConnected,  setWsConnected]  = useState(false)
  const [toast,        setToast]        = useState(null)
  const [comparison,   setComparison]   = useState(null)
  const [comparisonLog, setComparisonLog] = useState([])
  const [centreView,   setCentreView]   = useState('grid')
  const [shapChips,    setShapChips]    = useState({})   // { [user_id]: { alertId, loading, feature, direction, novelty, note, error } }
  const wsRef = useRef(null)

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4500)
  }

  const connectWs = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws    = new WebSocket(`${proto}://${location.host}/ws`)
    wsRef.current = ws
    ws.onopen    = () => setWsConnected(true)
    ws.onclose   = () => { setWsConnected(false); setTimeout(connectWs, 3000) }
    ws.onmessage = ({ data }) => {
      const msg = JSON.parse(data)
      if (msg.users_snapshot) setUsers(msg.users_snapshot)
      if (msg.alerts)         setAlerts(prev => mergeAlerts(prev, msg.alerts))
      if (msg.metrics)        setMetrics(msg.metrics)
      if (msg.type === 'comparison_progress' && msg.entry) {
        setComparisonLog(prev => [...prev, msg.entry])
      }
      if (msg.type === 'comparison_done') {
        api('/api/comparison/results').then(r => { setComparison(r); setCentreView('comparison') }).catch(() => {})
        showToast('Analysis complete — results ready', 'ok')
      }
      if (msg.type === 'attack') {
        const z = msg.result?.zone
        showToast(`Attack detected → T=${msg.result?.trust?.toFixed(3)} (${z})`,
          z === 'quarantine' ? 'danger' : 'warn')
      }
    }
  }, [])

  useEffect(() => { connectWs(); return () => wsRef.current?.close() }, [connectWs])

  useEffect(() => {
    const poll = async () => {
      try {
        const s = await api('/api/status')
        setStatus(s)
        if (s.comparison_ready && !comparison) {
          api('/api/comparison/results').then(setComparison).catch(() => {})
        }
        if (s.comparison_running && comparisonLog.length === 0) {
          api('/api/comparison/log').then(r => setComparisonLog(r.log || [])).catch(() => {})
        }
        if (s.processed_events > 0 && alerts.length === 0) {
          api('/api/alerts?limit=500').then(a => setAlerts(prev => mergeAlerts(prev, a))).catch(() => {})
        }
      } catch {}
    }
    poll()
    const t = setInterval(poll, 2500)
    return () => clearInterval(t)
  }, [comparison, comparisonLog.length, alerts.length])

  useEffect(() => {
    if (!selectedUser) return
    api(`/api/users/${selectedUser.user_id}`)
      .then(u => {
        setSelectedUser(prev => ({ ...prev, ...u }))
        setUserHistory(u.history || [])
        setUserUcb(u.ucb || null)
      }).catch(() => {})
  }, [selectedUser?.user_id, status.processed_events])

  useEffect(() => {
    if (!selectedUser) return
    const fresh = users.find(u => u.user_id === selectedUser.user_id)
    if (fresh) setSelectedUser(prev => ({ ...prev, ...fresh }))
  }, [users])

  const handleInit = async () => {
    showToast('Initialising — training Isolation Forests…', 'info')
    try {
      const r = await api('/api/simulation/init', { method:'POST' })
      const [s, u] = await Promise.all([api('/api/status'), api('/api/users')])
      setStatus(s); setUsers(u); setAlerts([])
      showToast(`Ready: ${r.users} identities · ${r.events?.toLocaleString()} events`, 'ok')
    } catch (e) { showToast('Init failed: ' + e.message, 'danger') }
  }

  const handleStep = async (n) => {
    try {
      await api('/api/simulation/step', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ n_events:n })
      })
      const [s, u, a, m] = await Promise.all([
        api('/api/status'), api('/api/users'), api('/api/alerts?limit=500'), api('/api/metrics')
      ])
      setStatus(s); setUsers(u); setAlerts(prev => mergeAlerts(prev, a)); setMetrics(m)
    } catch (e) { showToast('Step failed: ' + e.message, 'danger') }
  }

  const handleRun = async () => {
    showToast('Running full simulation…', 'info')
    await api('/api/simulation/run', { method:'POST' })
  }

  const handleAttack = async (uid, scenario) => {
    try {
      await api(`/api/attack/${uid}`, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ scenario })
      })
      const [u, a] = await Promise.all([api('/api/users'), api('/api/alerts?limit=500')])
      setUsers(u); setAlerts(prev => mergeAlerts(prev, a))
    } catch (e) { showToast('Attack failed: ' + e.message, 'danger') }
  }

  const handleModeChange = async (mode) => {
    try {
      await api('/api/mode', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify(mode)
      })
    } catch {}
  }

  const handleRunComparison = async () => {
    try {
      setComparisonLog([])
      await api('/api/comparison/run', { method:'POST' })
      setCentreView('comparison')
      showToast('Running analysis — this takes a few minutes…', 'info')
    } catch (e) { showToast('Analysis failed: ' + e.message, 'danger') }
  }

  const handleSelectUser = useCallback((user) => {
    setSelectedUser(user)
    setCentreView('grid')
    api(`/api/users/${user.user_id}`)
      .then(u => {
        setSelectedUser({ ...user, ...u })
        setUserHistory(u.history || [])
        setUserUcb(u.ucb || null)
      }).catch(() => {})
  }, [])

  const handleExplainAlert = (alert) => {
    setFocusAlertId(alert.alert_id)
    setShowAllAlerts(true)
  }

  // Most recent alert per user — `alerts` is already newest-first (see
  // mergeAlerts / backend get_alerts), so the first match per user_id wins.
  const latestAlertByUser = useMemo(() => {
    const m = {}
    for (const a of alerts) {
      if (!m[a.user_id]) m[a.user_id] = a
    }
    return m
  }, [alerts])

  // SHAP top-reason chip for Live Monitor cards. Deliberately NOT computed
  // for every user/every poll tick — matches the backend's own on-demand
  // design (/api/alerts/{id}/explain is explicitly kept out of the live
  // scoring path). We fetch once per alert, only for users currently in a
  // non-normal zone, cache by user_id+alertId, and never refetch the same
  // alert twice.
  useEffect(() => {
    users.forEach(u => {
      if (u.zone === 'normal_access') return
      const alert = latestAlertByUser[u.user_id]
      if (!alert) return
      const existing = shapChips[u.user_id]
      if (existing && existing.alertId === alert.alert_id) return

      setShapChips(prev => ({ ...prev, [u.user_id]: { alertId: alert.alert_id, loading: true } }))
      api(`/api/alerts/${alert.alert_id}/explain?top_k=1`)
        .then(res => {
          if (res.explanation && res.explanation.length > 0) {
            const top = res.explanation[0]
            setShapChips(prev => ({ ...prev, [u.user_id]: {
              alertId: alert.alert_id, loading: false, feature: top.feature, direction: top.direction,
            } }))
          } else {
            setShapChips(prev => ({ ...prev, [u.user_id]: {
              alertId: alert.alert_id, loading: false, novelty: true, note: res.note,
            } }))
          }
        })
        .catch(() => {
          setShapChips(prev => ({ ...prev, [u.user_id]: { alertId: alert.alert_id, loading: false, error: true } }))
        })
    })
  }, [users, latestAlertByUser])

  const TOAST_C = { info:'#3b82f6', ok:'#10b981', warn:'#f59e0b', danger:'#ef4444' }

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', overflow:'hidden' }}>

      {/* Header */}
      <header style={{
        display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 20px', height:46,
        borderBottom:'1px solid var(--border)', background:'var(--bg-surface)', flexShrink:0
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <div style={{
            width:8, height:8, borderRadius:'50%',
            background: wsConnected ? 'var(--z-green)' : 'var(--z-red)',
            boxShadow: wsConnected ? '0 0 6px var(--z-green)' : 'none'
          }}/>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:13, fontWeight:700, color:'var(--text-pri)' }}>
            ZT Trust Engine
          </span>
          <span style={{ fontSize:10, color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>
            Zero Trust Cloud Security · Behavioral Drift Detection · Adaptive Enforcement
          </span>
        </div>

        {/* View toggle */}
        <div style={{ display:'flex', gap:4 }}>
          {[
            { id:'grid',       label:'Live Monitor' },
            { id:'comparison', label:'Analysis Report' },
            { id:'scorecard',  label:'Baseline vs Adaptive' },
          ].map(v => (
            <button key={v.id} onClick={() => setCentreView(v.id)} style={{
              padding:'4px 12px', fontSize:10, fontFamily:'var(--font-mono)',
              background: centreView===v.id ? 'rgba(124,58,237,.15)' : 'transparent',
              border:`1px solid ${centreView===v.id ? 'var(--z-purple)' : 'var(--border)'}`,
              borderRadius:4,
              color: centreView===v.id ? '#c4b5fd' : 'var(--text-sec)',
              cursor:'pointer',
            }}>{v.label}</button>
          ))}
        </div>

        <div style={{ display:'flex', gap:10, alignItems:'center' }}>
          <span style={{ fontSize:10, color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>
            {(status.processed_events||0).toLocaleString()} / {(status.total_events||0).toLocaleString()}
          </span>
          <div style={{
            padding:'2px 8px', borderRadius:3,
            background: status.is_running ? 'rgba(245,158,11,.1)' : (status.is_initialised ? 'rgba(16,185,129,.1)' : 'var(--bg-card)'),
            border:`1px solid ${status.is_running ? 'var(--z-yellow)' : (status.is_initialised ? 'var(--z-green)' : 'var(--border)')}`,
            fontSize:9, fontFamily:'var(--font-mono)',
            color: status.is_running ? 'var(--z-yellow)' : (status.is_initialised ? 'var(--z-green)' : 'var(--text-dim)'),
          }}>
            {status.is_running ? '⚡ RUNNING' : (status.is_initialised ? '✓ READY' : '○ IDLE')}
          </div>
        </div>
      </header>

      {/* Metrics bar */}
      <MetricsBar metrics={metrics}/>

      {/* Main 3-column layout */}
      <div style={{ flex:1, display:'flex', overflow:'hidden', minHeight:0 }}>

        {/* Left: controls */}
        <aside style={{ width:210, flexShrink:0, borderRight:'1px solid var(--border)', padding:'14px', overflowY:'auto', background:'var(--bg-surface)' }}>
          <ControlPanel
            status={status}
            onInit={handleInit}
            onStep={handleStep}
            onRun={handleRun}
            onAttack={handleAttack}
            onModeChange={handleModeChange}
            onRunComparison={handleRunComparison}
            selectedUser={selectedUser}
          />
        </aside>

        {/* Centre */}
        <main style={{ flex:1, minWidth:0, display:'flex', flexDirection:'column', overflow:'hidden' }}>
          <div style={{ flex:1, overflowY:'auto', minHeight:0 }}>
            {centreView === 'grid' ? (
              <div style={{ padding:'14px' }}>
                <TrustGrid users={users} onSelectUser={handleSelectUser} selectedUser={selectedUser} realEventsPerRole={status.real_events_per_role} shapChips={shapChips}/>
              </div>
            ) : centreView === 'scorecard' ? (
              <div style={{ overflowY:'auto', height:'100%' }}>
                <BaselineScorecard results={comparison}/>
                {!comparison && !status.comparison_running && (
                  <div style={{ padding:'30px', textAlign:'center', color:'var(--text-dim)', fontFamily:'var(--font-mono)', fontSize:11 }}>
                    Click "Run Analysis" in the left panel to generate the baseline vs adaptive scorecard
                  </div>
                )}
                {status.comparison_running && (
                  <div style={{ padding:'30px', textAlign:'center', color:'var(--text-dim)', fontFamily:'var(--font-mono)', fontSize:11 }}>
                    Analysis running — see Analysis Report tab for live progress
                  </div>
                )}
              </div>
            ) : (
              <div style={{ overflowY:'auto', height:'100%' }}>
                <ComparisonPanel results={comparison} running={status.comparison_running} log={comparisonLog}/>
                {!comparison && !status.comparison_running && (
                  <div style={{ padding:'30px', textAlign:'center', color:'var(--text-dim)', fontFamily:'var(--font-mono)', fontSize:11 }}>
                    Click "Run Analysis" in the left panel to generate the comparison report
                  </div>
                )}
              </div>
            )}
          </div>
          <div style={{
            height:240, minHeight:150, maxHeight:'60vh', flexShrink:0,
            resize:'vertical', overflow:'auto',
            borderTop:'1px solid var(--border)', padding:'14px', background:'var(--bg-surface)',
          }}>
            <UserDetailPanel user={selectedUser} history={userHistory} ucb={userUcb} onClose={() => setSelectedUser(null)}/>
          </div>
        </main>

        {/* Right: alerts */}
        <aside style={{
          width:280, minWidth:200, maxWidth:520, flexShrink:0,
          resize:'horizontal', overflow:'auto',
          borderLeft:'1px solid var(--border)', padding:'14px', background:'var(--bg-surface)',
        }}>
          <AlertFeed
            alerts={alerts}
            totalAlerts={status.total_alerts}
            onViewAll={() => { setFocusAlertId(null); setShowAllAlerts(true) }}
            onExplain={handleExplainAlert}
          />
        </aside>
      </div>

      {showAllAlerts && (
        <AlertsExplorer
          alerts={alerts}
          focusAlertId={focusAlertId}
          onClose={() => { setShowAllAlerts(false); setFocusAlertId(null) }}
        />
      )}

      {/* Toast */}
      {toast && (
        <div style={{
          position:'fixed', bottom:20, right:20, zIndex:9999,
          padding:'9px 14px', borderRadius:6,
          background:'var(--bg-card)',
          border:`1px solid ${TOAST_C[toast.type]||'var(--border)'}`,
          color:'var(--text-pri)', fontSize:11, fontFamily:'var(--font-mono)',
          maxWidth:380, boxShadow:'0 4px 20px rgba(0,0,0,.6)',
        }}>
          <style>{`@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}`}</style>
          <span style={{ color:TOAST_C[toast.type], marginRight:8 }}>●</span>{toast.msg}
        </div>
      )}
    </div>
  )
}