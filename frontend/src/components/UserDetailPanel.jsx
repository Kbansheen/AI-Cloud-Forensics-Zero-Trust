import React, { useState } from 'react'
import { ComposedChart, Line, XAxis, YAxis, ReferenceLine, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const ZONE_COLOURS = {
  normal_access: '#10b981',
  step_up_mfa:   '#f59e0b',
  read_only:     '#f97316',
  quarantine:    '#ef4444',
}

const TAB_STYLE = (active) => ({
  padding:'3px 10px', fontSize:10, borderRadius:3, cursor:'pointer',
  fontFamily:'var(--font-mono)', background: active ? 'rgba(124,58,237,.15)' : 'transparent',
  border:`1px solid ${active ? 'var(--z-purple)' : 'var(--border)'}`,
  color: active ? '#c4b5fd' : 'var(--text-sec)',
})

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const d = payload[0]?.payload
  return (
    <div style={{ background:'var(--bg-card)', border:'1px solid var(--border)', padding:'8px 12px', borderRadius:6, fontSize:10, fontFamily:'var(--font-mono)' }}>
      <div style={{ color:'var(--text-sec)', marginBottom:3 }}>Event #{d?.idx}</div>
      <div style={{ color: ZONE_COLOURS[d?.zone] || '#fff', fontWeight:700 }}>T = {(d?.trust*100)?.toFixed(1)}%</div>
      {d?.lambda_ !== undefined && <div style={{ color:'#93c5fd', marginTop:2 }}>λ = {d?.lambda_?.toFixed(3)}  ρ = {d?.rho?.toFixed(3)}</div>}
      <div style={{ color:'var(--text-dim)', marginTop:2 }}>{d?.action}</div>
    </div>
  )
}

export default function UserDetailPanel({ user, history, ucb }) {
  const [chartMode, setChartMode] = useState('trust')   // 'trust' | 'params'

  if (!user) return (
    <div style={{ height:'100%', display:'flex', alignItems:'center', justifyContent:'center', color:'var(--text-dim)', fontFamily:'var(--font-mono)', fontSize:11 }}>
      Select an identity to view detail
    </div>
  )

  const zoneColor = ZONE_COLOURS[user.zone] || '#3b82f6'
  const data = (history || []).slice(-200)

  return (
    <div style={{ height:'100%', display:'flex', flexDirection:'column' }}>

      {/* Header row */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:10 }}>
        <div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:12, fontWeight:700, color:'var(--text-pri)' }}>{user.user_id}</div>
          <div style={{ fontSize:10, color:'var(--text-sec)', marginTop:1 }}>{user.role}</div>
        </div>
        <div style={{ textAlign:'right' }}>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:26, fontWeight:700, color:zoneColor, lineHeight:1 }}>
            {(user.trust*100).toFixed(1)}<span style={{ fontSize:11, color:'var(--text-sec)' }}>%</span>
          </div>
          <div style={{ fontSize:9, color:zoneColor, textTransform:'uppercase', letterSpacing:'.1em' }}>{user.zone?.replace('_',' ')}</div>
        </div>
      </div>

      {/* Stats strip */}
      <div style={{ display:'flex', gap:14, marginBottom:8, flexWrap:'wrap' }}>
        {[
          ['Events', user.event_count?.toLocaleString()],
          ['Quarantines', user.quarantine_count],
          ['σ (volatility)', user.volatility?.toFixed(4)],
          ['Last score', user.last_score?.toFixed(3)],
          ['λ (decay)', user.lambda_?.toFixed(3)],
          ['ρ (recovery)', user.rho?.toFixed(3)],
        ].map(([label, val]) => (
          <div key={label} style={{ fontSize:9, color:'var(--text-dim)' }}>
            <span style={{ color:'var(--text-sec)' }}>{label}: </span>
            <span style={{ fontFamily:'var(--font-mono)', color:'var(--text-pri)' }}>{val ?? '—'}</span>
          </div>
        ))}
      </div>

      {/* Chart mode tabs */}
      <div style={{ display:'flex', gap:4, marginBottom:8 }}>
        <button style={TAB_STYLE(chartMode==='trust')}  onClick={() => setChartMode('trust')}>Trust trajectory</button>
        <button style={TAB_STYLE(chartMode==='params')} onClick={() => setChartMode('params')}>UCB λ/ρ evolution</button>
      </div>

      {/* Chart */}
      <div style={{ flex:1, minHeight:0 }}>
        {data.length > 1 ? (
          <ResponsiveContainer width="100%" height="100%">
            {chartMode === 'trust' ? (
              <ComposedChart data={data} margin={{ top:4, right:4, left:-20, bottom:0 }}>
                <XAxis dataKey="idx" tick={{ fontSize:8, fill:'var(--text-dim)', fontFamily:'var(--font-mono)' }}/>
                <YAxis domain={[0,1]} ticks={[0,.4,.6,.8,1]} tick={{ fontSize:8, fill:'var(--text-dim)', fontFamily:'var(--font-mono)' }}/>
                <Tooltip content={<CustomTooltip />}/>
                <ReferenceLine y={0.80} stroke="#10b981" strokeDasharray="4 3" strokeWidth={1}
                  label={{ value:'MFA', fill:'#10b981', fontSize:8, position:'insideTopRight' }}/>
                <ReferenceLine y={0.60} stroke="#f59e0b" strokeDasharray="4 3" strokeWidth={1}
                  label={{ value:'RO',  fill:'#f59e0b', fontSize:8, position:'insideTopRight' }}/>
                <ReferenceLine y={0.40} stroke="#ef4444" strokeDasharray="4 3" strokeWidth={1}
                  label={{ value:'QU',  fill:'#ef4444', fontSize:8, position:'insideTopRight' }}/>
                <Line type="monotone" dataKey="trust" stroke={zoneColor} strokeWidth={1.5} dot={false} isAnimationActive={false}/>
              </ComposedChart>
            ) : (
              <ComposedChart data={data} margin={{ top:4, right:4, left:-20, bottom:0 }}>
                <XAxis dataKey="idx" tick={{ fontSize:8, fill:'var(--text-dim)', fontFamily:'var(--font-mono)' }}/>
                <YAxis domain={[0,.35]} tick={{ fontSize:8, fill:'var(--text-dim)', fontFamily:'var(--font-mono)' }}/>
                <Tooltip content={<CustomTooltip />}/>
                <ReferenceLine y={0.15} stroke="#93c5fd" strokeDasharray="4 3" strokeWidth={1}
                  label={{ value:'λ P1', fill:'#93c5fd', fontSize:8, position:'insideTopRight' }}/>
                <ReferenceLine y={0.05} stroke="#86efac" strokeDasharray="4 3" strokeWidth={1}
                  label={{ value:'ρ P1', fill:'#86efac', fontSize:8, position:'insideTopRight' }}/>
                <Line type="stepAfter" dataKey="lambda_" stroke="#3b82f6" strokeWidth={1.5} dot={false} name="λ (decay)" isAnimationActive={false}/>
                <Line type="stepAfter" dataKey="rho" stroke="#10b981" strokeWidth={1.5} dot={false} name="ρ (recovery)" isAnimationActive={false}/>
                <Legend wrapperStyle={{ fontSize:9, fontFamily:'var(--font-mono)' }}/>
              </ComposedChart>
            )}
          </ResponsiveContainer>
        ) : (
          <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'100%', color:'var(--text-dim)', fontSize:10, fontFamily:'var(--font-mono)' }}>
            Run simulation to populate
          </div>
        )}
      </div>

      {/* Last action */}
      {user.last_action && (
        <div style={{ marginTop:6, padding:'4px 8px', background:'var(--bg-surface)', borderRadius:3, fontSize:9, fontFamily:'var(--font-mono)', color:'var(--text-sec)' }}>
          Last: <span style={{ color:'var(--text-pri)' }}>{user.last_action}</span>
        </div>
      )}
    </div>
  )
}
