import React from 'react'

const D = ({ v }) => {
  if (v === null || v === undefined) return <span style={{ color:'var(--text-dim)', fontSize:9 }}>—</span>
  return v === 1
    ? <span style={{ color:'#10b981', fontWeight:700, fontSize:12 }}>✓</span>
    : <span style={{ color:'#ef4444', fontWeight:700, fontSize:12 }}>✗</span>
}

const M = ({ v }) => {
  if (v === null || v === undefined) return <span style={{ color:'#ef4444', fontSize:9 }}>not detected</span>
  return <span style={{ fontFamily:'var(--font-mono)', fontSize:10 }}>{v}h</span>
}

const COND_COLOUR = ['#10b981', '#f97316', '#7c3aed']

const COND_LABELS = [
  'A — Static parameters, no adversary',
  'B — Static parameters + evasion attack',
  'C — Adaptive UCB + evasion attack',
]

export default function ComparisonPanel({ results, running }) {
  if (running) return (
    <div style={{ padding:'30px', textAlign:'center', color:'var(--text-dim)', fontFamily:'var(--font-mono)', fontSize:11 }}>
      ⟳ Running 3-condition analysis…
    </div>
  )
  if (!results) return null

  const { summary, table_detection, table_mttd } = results

  return (
    <div style={{ padding:'16px', display:'flex', flexDirection:'column', gap:20 }}>

      {/* Summary */}
      <div>
        <div style={{ fontSize:9, textTransform:'uppercase', letterSpacing:'.1em', color:'var(--text-dim)', fontFamily:'var(--font-mono)', marginBottom:8 }}>
          Detection rate + FPR per 10K events — 3 conditions
        </div>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:10 }}>
          <thead>
            <tr style={{ borderBottom:'1px solid var(--border)' }}>
              {['Condition','Detection rate','FPR / 10K','Precision'].map(h => (
                <th key={h} style={{ padding:'4px 8px', textAlign:'left', color:'var(--text-sec)', fontSize:9, fontFamily:'var(--font-mono)', fontWeight:600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {summary.map((row, i) => (
              <tr key={i} style={{ borderBottom:'1px solid var(--border)' }}>
                <td style={{ padding:'7px 8px', color:COND_COLOUR[i], fontSize:9, fontFamily:'var(--font-mono)' }}>{COND_LABELS[i]}</td>
                <td style={{ padding:'7px 8px', fontFamily:'var(--font-mono)', fontWeight:700, color:COND_COLOUR[i] }}>{(row.detection_rate*100).toFixed(1)}%</td>
                <td style={{ padding:'7px 8px', fontFamily:'var(--font-mono)', color:'var(--text-sec)' }}>{row.fpr_per_10k}</td>
                <td style={{ padding:'7px 8px', fontFamily:'var(--font-mono)', color:'var(--text-sec)' }}>{(row.precision*100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Per-scenario detection */}
      <div>
        <div style={{ fontSize:9, textTransform:'uppercase', letterSpacing:'.1em', color:'var(--text-dim)', fontFamily:'var(--font-mono)', marginBottom:8 }}>
          Per-scenario detection · A = static / B = evasion / C = adaptive
        </div>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:10 }}>
          <thead>
            <tr style={{ borderBottom:'1px solid var(--border)' }}>
              {['Scenario','Tactic','A','B','C','MTTD-A','MTTD-B','MTTD-C'].map(h => (
                <th key={h} style={{ padding:'4px 6px', textAlign:'left', color:'var(--text-sec)', fontSize:9, fontFamily:'var(--font-mono)', fontWeight:600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {table_detection.map((row, i) => {
              const m = table_mttd?.[i] || {}
              return (
                <tr key={i} style={{ borderBottom:'1px solid var(--border)' }}>
                  <td style={{ padding:'6px 6px', fontSize:9, fontFamily:'var(--font-mono)', color:'var(--text-pri)' }}>{row.scenario}</td>
                  <td style={{ padding:'6px 6px', fontSize:9, color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{row.tactic}</td>
                  <td style={{ padding:'6px 6px' }}><D v={row.A}/></td>
                  <td style={{ padding:'6px 6px' }}><D v={row.B}/></td>
                  <td style={{ padding:'6px 6px' }}><D v={row.C}/></td>
                  <td style={{ padding:'6px 6px' }}><M v={m.A}/></td>
                  <td style={{ padding:'6px 6px' }}><M v={m.B}/></td>
                  <td style={{ padding:'6px 6px' }}><M v={m.C}/></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
