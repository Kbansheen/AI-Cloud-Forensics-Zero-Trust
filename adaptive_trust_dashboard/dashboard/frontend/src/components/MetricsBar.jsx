import React from 'react'

const METRICS = [
  { key:'auc',               label:'Session AUC',  fmt:v=>v?.toFixed(3)??'—',           note:'Baseline: 0.65' },
  { key:'fpr',               label:'FPR',           fmt:v=>v?.toFixed(3)??'—',           note:'Baseline: 0.48' },
  { key:'precision',         label:'Precision',     fmt:v=>v?.toFixed(3)??'—',           note:'Baseline: 0.06' },
  { key:'scenarios_detected',label:'Scenarios',     fmt:v=>`${v??'—'} / 8`,              note:'' },
  { key:'total_alerts',      label:'Alerts',        fmt:v=>v?.toLocaleString()??'—',     note:'' },
  { key:'total_events',      label:'Events',        fmt:v=>v?.toLocaleString()??'—',     note:'' },
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
          {def.note && (
            <div style={{ fontSize:8, color:'var(--text-dim)', marginTop:1, fontFamily:'var(--font-mono)' }}>
              {def.note}
            </div>
          )}
        </div>
      ))}
      <div style={{ padding:'8px 14px', display:'flex', flexDirection:'column', gap:4, justifyContent:'center' }}>
        <Flag label="UCB adaptive" active={metrics?.adaptive_ucb}    colour="var(--z-purple)"/>
        <Flag label="Evasion sim"  active={metrics?.adversary_enabled} colour="var(--z-red)"/>
      </div>
    </div>
  )
}
