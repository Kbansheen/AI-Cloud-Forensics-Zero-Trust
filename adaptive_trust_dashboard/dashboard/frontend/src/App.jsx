import React, { useState, useEffect, useRef, useCallback } from 'react'
import MetricsBar from './components/MetricsBar'
import TrustGrid from './components/TrustGrid'
import UserDetailPanel from './components/UserDetailPanel'
import AlertFeed from './components/AlertFeed'
import ControlPanel from './components/ControlPanel'
import ComparisonPanel from './components/ComparisonPanel'

const API = ''
const api = async (path, opts = {}) => {
  const res = await fetch(API + path, opts)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export default function App() {
  const [users,        setUsers]        = useState([])
  const [alerts,       setAlerts]       = useState([])
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
      if (msg.alerts)         setAlerts(msg.alerts)
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
      } catch {}
    }
    poll()
    const t = setInterval(poll, 2500)
    return () => clearInterval(t)
  }, [comparison, comparisonLog.length])

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
      setStatus(s); setUsers(u)
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
        api('/api/status'), api('/api/users'), api('/api/alerts'), api('/api/metrics')
      ])
      setStatus(s); setUsers(u); setAlerts(a); setMetrics(m)
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
      const [u, a] = await Promise.all([api('/api/users'), api('/api/alerts')])
      setUsers(u); setAlerts(a)
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
      <div style={{ flex:1, display:'grid', gridTemplateColumns:'210px 1fr 280px', overflow:'hidden', minHeight:0 }}>

        {/* Left: controls */}
        <aside style={{ borderRight:'1px solid var(--border)', padding:'14px', overflowY:'auto', background:'var(--bg-surface)' }}>
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
        <main style={{ display:'grid', gridTemplateRows:'1fr 240px', overflow:'hidden' }}>
          <div style={{ overflowY:'auto' }}>
            {centreView === 'grid' ? (
              <div style={{ padding:'14px' }}>
                <TrustGrid users={users} onSelectUser={handleSelectUser} selectedUser={selectedUser}/>
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
          <div style={{ borderTop:'1px solid var(--border)', padding:'14px', background:'var(--bg-surface)', overflow:'hidden' }}>
            <UserDetailPanel user={selectedUser} history={userHistory} ucb={userUcb}/>
          </div>
        </main>

        {/* Right: alerts */}
        <aside style={{ borderLeft:'1px solid var(--border)', padding:'14px', overflowY:'auto', background:'var(--bg-surface)' }}>
          <AlertFeed alerts={alerts}/>
        </aside>
      </div>

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