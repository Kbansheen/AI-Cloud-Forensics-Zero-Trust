import React from 'react'

// Labels state WHAT is measured, because several different definitions of
// "FPR" and "precision" exist in this project and they are not interchangeable:
//   - these are EVENT-level, at the fixed operational threshold score >= 0.60
//   - the published A/B/C table is per 10,000 benign events, at T < 0.60
//   - Paper 1's tables are session-level (user-day), post-hoc ROC threshold
// Mixing them on one screen without saying which is which reads as a contradiction.
const METRICS = [
  { key:'auc',               label:'AUC (event)',        fmt:v=>v?.toFixed(3)??'—',       note:'Paper 1 baseline: 0.65' },
  { key:'fpr',               label:'FPR (score ≥ 0.60)', fmt:v=>v?.toFixed(4)??'—',       note:'event-level rate' },
  { key:'precision',         label:'Precision (≥ 0.60)', fmt:v=>v?.toFixed(3)??'—',       note:'event-level' },
  { key:'scenarios_detected',label:'Scenarios',          fmt:v=>`${v??'—'} / 8`,          note:'attack event in restricted zone' },
  { key:'total_alerts',      label:'Alerts',
    fmt:(v,m)=>v?.toLocaleString()??'—',
    note:(v,m)=> m?.alerts_attack!=null ? `${m.alerts_attack} real / ${m.alerts_benign} benign` : '' },
  { key:'total_events',      label:'Events',             fmt:v=>v?.toLocaleString()??'—', note:'' },
]

const Flag = ({ label, active, colour }) => (
  <div style={{
    padding:'2px 8px', borderRadius:3, fontSize:9, fontFamily:'var(--font-mono)',
    background: active ? colour+'22' : 'transparent',
    border:`1px solid ${active ? colour : 'var(--border)'}`,
    color: active ? colour : 'var(--text-dim)',
    whiteSpace:'nowrap',
  }}>
    {label}
  </div>
)

export default function MetricsBar({ metrics }) {
  return (
    <div style={{
      display:'flex', alignItems:'stretch',
      borderBottom:'1px solid var(--border)',
      background:'var(--bg-surface)', flexShrink:0,
    }}>
      {METRICS.map(def => (
        <div key={def.key} style={{ flex:1, padding:'8px 14px', borderRight:'1px solid var(--border)' }}>
          <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'.08em', fontFamily:'var(--font-mono)', marginBottom:2 }}>
            {def.label}
          </div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:19, fontWeight:700, color:'var(--text-pri)', lineHeight:1 }}>
            {def.fmt(metrics?.[def.key])}
          </div>
          {(() => {
            const note = typeof def.note === 'function' ? def.note(metrics?.[def.key], metrics) : def.note
            return note ? (
              <div style={{ fontSize:8, color:'var(--text-dim)', marginTop:1, fontFamily:'var(--font-mono)' }}>
                {note}
              </div>
            ) : null
          })()}
        </div>
      ))}
      <div style={{ padding:'8px 14px', display:'flex', flexDirection:'column', gap:4, justifyContent:'center' }}>
        <Flag label="UCB adaptive" active={metrics?.adaptive_ucb}    colour="var(--z-purple)"/>
        <Flag label="Evasion sim"  active={metrics?.adversary_enabled} colour="var(--z-red)"/>
      </div>
    </div>
  )
}
