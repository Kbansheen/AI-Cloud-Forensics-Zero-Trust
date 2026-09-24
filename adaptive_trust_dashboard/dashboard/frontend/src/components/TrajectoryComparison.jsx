import React, { useMemo, useState } from 'react'

const STATIC_COLOR   = '#f97316'  // matches Condition B elsewhere in the dashboard
const ADAPTIVE_COLOR = '#7c3aed'  // matches Condition C elsewhere in the dashboard

const THRESH_MFA  = 0.80
const THRESH_RO   = 0.60
const THRESH_QUAR = 0.40

const CHART_W = 900
const CHART_H = 300
const PAD_L = 42
const PAD_R = 14
const PAD_T = 14
const PAD_B = 30

function buildPath(points, xScale, yScale) {
  if (!points || !points.length) return ''
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${xScale(p.idx).toFixed(1)} ${yScale(p.trust).toFixed(1)}`).join(' ')
}

export default function TrajectoryComparison({ trajectories }) {
  const scenarioKeys = useMemo(() => Object.keys(trajectories || {}), [trajectories])
  const [selected, setSelected] = useState(scenarioKeys[0] || null)
  const activeKey = scenarioKeys.includes(selected) ? selected : scenarioKeys[0]

  if (!scenarioKeys.length) {
    return (
      <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-dim)' }}>
        No trajectory data in this result — re-run Analysis to generate it.
      </div>
    )
  }

  const data = trajectories[activeKey]
  const allPts = [...(data.static || []), ...(data.adaptive || [])]
  const idxs   = allPts.map(p => p.idx)
  if (data.attack_start_idx != null) idxs.push(data.attack_start_idx)
  const minIdx = Math.min(...idxs)
  const maxIdx = Math.max(...idxs)
  const span   = Math.max(1, maxIdx - minIdx)

  const xScale = idx   => PAD_L + ((idx - minIdx) / span) * (CHART_W - PAD_L - PAD_R)
  const yScale = trust => PAD_T + (1 - trust) * (CHART_H - PAD_T - PAD_B)

  const staticPath   = buildPath(data.static, xScale, yScale)
  const adaptivePath = buildPath(data.adaptive, xScale, yScale)
  const attackX = data.attack_start_idx != null ? xScale(data.attack_start_idx) : null

  return (
    <div>
      {/* Scenario selector */}
      <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginBottom:12 }}>
        {scenarioKeys.map(sc => {
          const active = sc === activeKey
          return (
            <button
              key={sc}
              onClick={() => setSelected(sc)}
              style={{
                fontFamily:'var(--font-mono)', fontSize:9, fontWeight:600, padding:'4px 10px', borderRadius:11,
                cursor:'pointer', letterSpacing:'.03em',
                border:`1px solid ${active ? ADAPTIVE_COLOR : 'var(--border)'}`,
                background: active ? `${ADAPTIVE_COLOR}18` : 'transparent',
                color: active ? '#c4b5fd' : 'var(--text-dim)',
              }}
            >
              {trajectories[sc].label}
            </button>
          )
        })}
      </div>

      <div style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'var(--text-dim)', marginBottom:8 }}>
        {data.label} ({data.tactic}) — trust score of the attacked identity over time, same injected attack under both conditions
      </div>

      <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} style={{ width:'100%', height:'auto', display:'block' }}>
        {/* Zone background bands, matching the dashboard's zone color convention */}
        <rect x={PAD_L} y={yScale(1)}          width={CHART_W-PAD_L-PAD_R} height={yScale(THRESH_MFA)-yScale(1)}          fill="#10b98112" />
        <rect x={PAD_L} y={yScale(THRESH_MFA)} width={CHART_W-PAD_L-PAD_R} height={yScale(THRESH_RO)-yScale(THRESH_MFA)}   fill="#f59e0b12" />
        <rect x={PAD_L} y={yScale(THRESH_RO)}  width={CHART_W-PAD_L-PAD_R} height={yScale(THRESH_QUAR)-yScale(THRESH_RO)}  fill="#f9731612" />
        <rect x={PAD_L} y={yScale(THRESH_QUAR)}width={CHART_W-PAD_L-PAD_R} height={yScale(0)-yScale(THRESH_QUAR)}         fill="#ef444412" />

        {/* Threshold reference lines */}
        {[THRESH_MFA, THRESH_RO, THRESH_QUAR].map(t => (
          <line key={t} x1={PAD_L} x2={CHART_W-PAD_R} y1={yScale(t)} y2={yScale(t)}
                stroke="var(--border)" strokeWidth={0.6} strokeDasharray="3 3" />
        ))}
        <text x={PAD_L+4} y={yScale(THRESH_MFA)-3}  fontSize="8" fill="#f59e0b" fontFamily="var(--font-mono)">MFA 0.80</text>
        <text x={PAD_L+4} y={yScale(THRESH_RO)-3}   fontSize="8" fill="#f97316" fontFamily="var(--font-mono)">READ-ONLY 0.60</text>
        <text x={PAD_L+4} y={yScale(THRESH_QUAR)-3} fontSize="8" fill="#ef4444" fontFamily="var(--font-mono)">QUARANTINE 0.40</text>

        {/* Attack-injected marker */}
        {attackX != null && (
          <>
            <line x1={attackX} x2={attackX} y1={PAD_T} y2={CHART_H-PAD_B}
                  stroke="#f59e0b" strokeWidth={1.1} strokeDasharray="4 3" />
            <text x={attackX+4} y={PAD_T+10} fontSize="8" fontWeight="700" fill="#f59e0b" fontFamily="var(--font-mono)">
              ⚠ attack injected
            </text>
          </>
        )}

        {/* Trust curves */}
        <path d={staticPath}   fill="none" stroke={STATIC_COLOR}   strokeWidth={1.8} />
        <path d={adaptivePath} fill="none" stroke={ADAPTIVE_COLOR} strokeWidth={1.8} />

        {/* Y axis labels */}
        {[0, 0.25, 0.5, 0.75, 1.0].map(t => (
          <text key={t} x={PAD_L-5} y={yScale(t)+3} fontSize="8" fill="var(--text-dim)"
                fontFamily="var(--font-mono)" textAnchor="end">{t.toFixed(2)}</text>
        ))}

        {/* X axis label */}
        <text x={(PAD_L + CHART_W - PAD_R) / 2} y={CHART_H-4} fontSize="9" fill="var(--text-sec)"
              fontFamily="var(--font-mono)" textAnchor="middle">Event index</text>
      </svg>

      {/* Legend */}
      <div style={{ display:'flex', gap:16, marginTop:8, fontFamily:'var(--font-mono)', fontSize:9, color:'var(--text-sec)' }}>
        <span><span style={{ color: STATIC_COLOR, fontWeight:700 }}>▬</span> Static λ/ρ (Condition B) — exploitable</span>
        <span><span style={{ color: ADAPTIVE_COLOR, fontWeight:700 }}>▬</span> Adaptive UCB (Condition C) — holds</span>
      </div>
    </div>
  )
}