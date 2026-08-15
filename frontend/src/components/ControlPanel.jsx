import React, { useState } from 'react'

const SCENARIOS = [
  { key: 'privilege_escalation', label: 'Privilege Escalation', tactic: 'T1068' },
  { key: 'data_exfiltration',    label: 'Data Exfiltration',    tactic: 'T1048' },
  { key: 'defense_evasion',      label: 'Defense Evasion',      tactic: 'T1036' },
  { key: 'persistence',          label: 'Persistence',          tactic: 'T1098' },
  { key: 'discovery',            label: 'Discovery',            tactic: 'T1087' },
  { key: 'collection',           label: 'Collection',           tactic: 'T1119' },
  { key: 'credential_access',    label: 'Credential Access',    tactic: 'T1606' },
  { key: 'lateral_movement',     label: 'Lateral Movement',     tactic: 'T1530' },
]

const Btn = ({ onClick, disabled, children, variant = 'default', full = false }) => {
  const s = {
    default: { bg:'var(--bg-hover)', border:'var(--border-hi)', color:'var(--text-pri)' },
    primary: { bg:'#1d4ed8', border:'#3b82f6', color:'#fff' },
    success: { bg:'#064e3b', border:'var(--z-green)', color:'#6ee7b7' },
    danger:  { bg:'#7f1d1d', border:'var(--z-red)', color:'#fca5a5' },
    purple:  { bg:'#3b0764', border:'var(--z-purple)', color:'#c4b5fd' },
  }[variant]
  return (
    <button onClick={onClick} disabled={disabled} style={{
      width: full ? '100%' : undefined,
      padding:'6px 12px',
      background: disabled ? 'var(--bg-surface)' : s.bg,
      border:`1px solid ${disabled ? 'var(--border)' : s.border}`,
      borderRadius:5, color: disabled ? 'var(--text-dim)' : s.color,
      fontSize:10, fontFamily:'var(--font-mono)',
      cursor: disabled ? 'not-allowed' : 'pointer',
      fontWeight:600, whiteSpace:'nowrap',
    }}>
      {children}
    </button>
  )
}

const Section = ({ title, children }) => (
  <div style={{ marginBottom:16 }}>
    <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.1em', fontFamily:'var(--font-mono)', marginBottom:8 }}>
      {title}
    </div>
    {children}
  </div>
)

const Toggle = ({ label, value, onChange }) => (
  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
    <span style={{ fontSize:10, color:'var(--text-sec)', fontFamily:'var(--font-mono)' }}>{label}</span>
    <div onClick={() => onChange(!value)} style={{
      width:32, height:18, borderRadius:9, cursor:'pointer', position:'relative',
      background: value ? 'var(--z-purple)' : 'var(--border-hi)', transition:'background .2s',
    }}>
      <div style={{
        position:'absolute', top:2, left: value ? 16 : 2,
        width:14, height:14, borderRadius:'50%',
        background:'#fff', transition:'left .2s',
      }}/>
    </div>
  </div>
)

export default function ControlPanel({
  status, onInit, onStep, onRun, onAttack,
  onModeChange, onRunComparison, selectedUser,
}) {
  const [stepSize, setStepSize]   = useState(250)
  const [scenario, setScenario]   = useState(SCENARIOS[0].key)
  const [adaptiveUcb, setAdaptiveUcb] = useState(true)
  const [adversaryMode, setAdversaryMode] = useState(false)
  const [loading, setLoading]     = useState(false)

  const wrap = fn => async () => { setLoading(true); try { await fn() } finally { setLoading(false) } }

  const handleToggle = (field, value) => {
    const next = field === 'ucb'
      ? { adaptive_ucb: value, adversary: adversaryMode }
      : { adaptive_ucb: adaptiveUcb, adversary: value }
    if (field === 'ucb') setAdaptiveUcb(value)
    else setAdversaryMode(value)
    onModeChange(next)
  }

  const progress = status?.total_events
    ? Math.round(100 * (status.processed_events || 0) / status.total_events) : 0

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%' }}>

      {/* Simulation */}
      <Section title="Simulation">
        <div style={{ display:'flex', gap:5, marginBottom:8, flexWrap:'wrap' }}>
          <Btn variant="primary" onClick={wrap(onInit)} disabled={loading || status?.is_running} full>
            {status?.is_initialised ? '↺ Re-init' : '▶ Initialise'}
          </Btn>
          <Btn variant="success" onClick={wrap(onRun)} disabled={loading || !status?.is_initialised || status?.is_running} full>
            ⚡ Run all
          </Btn>
        </div>
        {status?.is_initialised && (
          <div style={{ display:'flex', gap:5, alignItems:'center' }}>
            <select value={stepSize} onChange={e => setStepSize(+e.target.value)} style={{
              flex:1, background:'var(--bg-card)', border:'1px solid var(--border)',
              color:'var(--text-pri)', padding:'4px 6px', borderRadius:4,
              fontSize:10, fontFamily:'var(--font-mono)',
            }}>
              {[50,100,250,500,1000].map(n => <option key={n} value={n}>{n} events</option>)}
            </select>
            <Btn onClick={wrap(() => onStep(stepSize))} disabled={loading || status?.is_running}>Step →</Btn>
          </div>
        )}
        {status?.is_initialised && (
          <div style={{ marginTop:8 }}>
            <div style={{ display:'flex', justifyContent:'space-between', fontSize:9, color:'var(--text-dim)', fontFamily:'var(--font-mono)', marginBottom:3 }}>
              <span>{(status.processed_events||0).toLocaleString()} events</span>
              <span>{progress}%</span>
            </div>
            <div style={{ height:3, background:'var(--border)', borderRadius:2, overflow:'hidden' }}>
              <div style={{
                height:'100%', width:`${progress}%`,
                background: status?.is_running ? 'var(--z-yellow)' : 'var(--z-purple)',
                borderRadius:2, transition:'width .3s',
              }}/>
            </div>
          </div>
        )}
      </Section>

      {/* Engine mode */}
      <Section title="Engine mode">
        <Toggle label="Adaptive parameters (UCB)" value={adaptiveUcb}
          onChange={v => handleToggle('ucb', v)} />
        <Toggle label="Evasion simulation" value={adversaryMode}
          onChange={v => handleToggle('adv', v)} />
        <div style={{ fontSize:9, color:'var(--text-dim)', fontFamily:'var(--font-mono)', marginTop:4, lineHeight:1.6 }}>
          {adaptiveUcb ? 'UCB on: λ/ρ adapts per identity' : 'Fixed: λ=0.15 ρ=0.05'}
          {adversaryMode && ' · Pacing adversary active'}
        </div>
      </Section>

      {/* Attack injection */}
      {status?.is_initialised && selectedUser && (
        <Section title={`Inject attack → ${selectedUser.user_id}`}>
          <select value={scenario} onChange={e => setScenario(e.target.value)} style={{
            width:'100%', background:'var(--bg-card)', border:'1px solid var(--border)',
            color:'var(--text-pri)', padding:'4px 6px', borderRadius:4,
            fontSize:10, fontFamily:'var(--font-mono)', marginBottom:6,
          }}>
            {SCENARIOS.map(s => (
              <option key={s.key} value={s.key}>[{s.tactic}] {s.label}</option>
            ))}
          </select>
          <Btn variant="danger" full onClick={wrap(() => onAttack(selectedUser.user_id, scenario))} disabled={loading}>
            ⚠ Inject attack
          </Btn>
        </Section>
      )}

      {/* Analysis */}
      <Section title="Comparison analysis">
        <div style={{ fontSize:9, color:'var(--text-dim)', fontFamily:'var(--font-mono)', marginBottom:6, lineHeight:1.6 }}>
          Runs 3 conditions: baseline, evasion attack, and adaptive defence. Produces detection comparison report.
        </div>
        <Btn variant="purple" full onClick={wrap(onRunComparison)} disabled={loading || status?.comparison_running}>
          {status?.comparison_running ? '⟳ Running…' : '≡ Run Analysis'}
        </Btn>
        {status?.comparison_ready && (
          <div style={{ marginTop:5, fontSize:9, color:'var(--z-green)', fontFamily:'var(--font-mono)' }}>
            ✓ Results ready — see Analysis Report
          </div>
        )}
      </Section>

      {/* System info */}
      <div style={{ marginTop:'auto', padding:'10px', background:'var(--bg-surface)', borderRadius:5, border:'1px solid var(--border)' }}>
        <div style={{ fontSize:9, color:'var(--text-dim)', fontFamily:'var(--font-mono)', lineHeight:1.8 }}>
          <div>Model: Isolation Forest + k-medoids</div>
          <div>Features: 538-dim sparse vectors</div>
          <div>Scenarios: 8 MITRE ATT&CK</div>
          <div>Novelty override + percentile calib.</div>
          <div>UCB arms: 14 stable (λ,ρ) pairs</div>
        </div>
      </div>
    </div>
  )
}
