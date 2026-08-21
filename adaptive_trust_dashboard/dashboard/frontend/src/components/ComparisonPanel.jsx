import React, { useEffect, useRef, useState } from 'react'

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
const COND_LETTER_COLOUR = { A:'#10b981', B:'#f97316', C:'#7c3aed' }

const COND_LABELS = [
  'A — Static parameters, no adversary',
  'B — Static parameters + evasion attack',
  'C — Adaptive UCB + evasion attack',
]

// Classify a log line so it can be coloured/iconed consistently with
// the rest of the dashboard's palette instead of one flat grey stream.
function classify(message) {
  const condMatch = message.match(/^\[([ABC])\]/)
  const cond = condMatch ? condMatch[1] : null

  if (message.includes('✓ detected')) {
    return { icon:'✓', color:'#10b981', weight:700, cond }
  }
  if (message.includes('⚠ attack injected')) {
    return { icon:'⚠', color:'#f59e0b', weight:700, cond }
  }
  if (message.includes('complete —') || message === 'Analysis complete.') {
    return { icon:'●', color: cond ? COND_LETTER_COLOUR[cond] : '#7c3aed', weight:700, cond }
  }
  if (message.startsWith('Starting Condition')) {
    return { icon:'▶', color: cond ? COND_LETTER_COLOUR[cond] : '#c4b5fd', weight:700, cond }
  }
  if (message.includes('events processed')) {
    return { icon:'·', color:'var(--text-dim)', weight:400, cond }
  }
  return { icon:'·', color:'var(--text-sec)', weight:400, cond }
}

function LiveLog({ log, height = 320, autoScroll = true, showCursor = false }) {
  const boxRef = useRef(null)

  useEffect(() => {
    if (autoScroll && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight
    }
  }, [log, autoScroll])

  return (
    <div
      ref={boxRef}
      style={{
        height, overflowY:'auto', background:'#05070d',
        border:'1px solid var(--border)', borderRadius:6,
        padding:'10px 12px', fontFamily:'var(--font-mono)', fontSize:10.5,
        lineHeight:1.7,
      }}
    >
      {log.length === 0 && (
        <div style={{ color:'var(--text-dim)' }}>waiting for engine output…</div>
      )}
      {log.map((entry, i) => {
        const { icon, color, weight } = classify(entry.message)
        return (
          <div key={i} style={{ display:'flex', gap:8, whiteSpace:'pre-wrap' }}>
            <span style={{ color:'var(--text-dim)', flexShrink:0 }}>{entry.time}</span>
            <span style={{ color, flexShrink:0, width:12, textAlign:'center' }}>{icon}</span>
            <span style={{ color, fontWeight:weight }}>{entry.message}</span>
          </div>
        )
      })}
      {showCursor && (
        <div style={{ display:'flex', gap:8 }}>
          <span style={{ color:'var(--text-dim)' }}>{new Date().toTimeString().slice(0,8)}</span>
          <span style={{ color:'#7c3aed' }} className="ztlog-cursor">▊</span>
        </div>
      )}
      <style>{`
        @keyframes ztlog-blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }
        .ztlog-cursor { animation: ztlog-blink 1s step-end infinite; }
        @keyframes ztlog-pulse { 0%{opacity:.4} 50%{opacity:1} 100%{opacity:.4} }
      `}</style>
    </div>
  )
}

function RunningHeader({ log }) {
  const last = log[log.length - 1]
  // Pull "N/Total events" out of the most recent progress line, if present,
  // to drive a lightweight progress bar without needing a separate field.
  let pct = null
  if (last) {
    const m = last.message.match(/([\d,]+)\/([\d,]+) events processed/)
    if (m) {
      const done  = parseInt(m[1].replace(/,/g, ''), 10)
      const total = parseInt(m[2].replace(/,/g, ''), 10)
      if (total > 0) pct = Math.min(100, (done / total) * 100)
    }
  }
  const activeCond = last?.message.match(/^\[([ABC])\]/)?.[1]

  return (
    <div style={{ padding:'16px 16px 0' }}>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
        <span style={{
          width:8, height:8, borderRadius:'50%', background:'#7c3aed', flexShrink:0,
          animation:'ztlog-pulse 1.1s ease-in-out infinite',
        }}/>
        <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-pri)', fontWeight:700 }}>
          Running 3-condition analysis…
        </span>
        {activeCond && (
          <span style={{
            fontFamily:'var(--font-mono)', fontSize:9, padding:'2px 7px', borderRadius:4,
            color: COND_LETTER_COLOUR[activeCond],
            border:`1px solid ${COND_LETTER_COLOUR[activeCond]}55`,
            background:`${COND_LETTER_COLOUR[activeCond]}15`,
          }}>
            condition {activeCond}
          </span>
        )}
        <span style={{ marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:9, color:'var(--text-dim)' }}>
          {log.length} log lines
        </span>
      </div>

      {pct !== null ? (
        <div style={{ marginBottom:12 }}>
          <div style={{ height:4, borderRadius:2, background:'var(--bg-card)', overflow:'hidden' }}>
            <div style={{
              height:'100%', width:`${pct}%`, borderRadius:2,
              background: activeCond ? COND_LETTER_COLOUR[activeCond] : '#7c3aed',
              transition:'width .4s ease',
            }}/>
          </div>
        </div>
      ) : (
        <div style={{ marginBottom:12 }}/>
      )}
    </div>
  )
}

export default function ComparisonPanel({ results, running, log = [] }) {
  const [showLog, setShowLog] = useState(false)

  if (running) {
    return (
      <div>
        <RunningHeader log={log}/>
        <div style={{ padding:'0 16px 16px' }}>
          <LiveLog log={log} height={360} showCursor/>
        </div>
      </div>
    )
  }

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

      {/* Collapsible run log — preserved after completion for transparency */}
      {log.length > 0 && (
        <div>
          <button
            onClick={() => setShowLog(s => !s)}
            style={{
              display:'flex', alignItems:'center', gap:6, background:'none', border:'none',
              cursor:'pointer', padding:0, marginBottom: showLog ? 8 : 0,
              fontFamily:'var(--font-mono)', fontSize:9, textTransform:'uppercase',
              letterSpacing:'.1em', color:'var(--text-dim)',
            }}
          >
            <span style={{ transform: showLog ? 'rotate(90deg)' : 'none', transition:'transform .15s' }}>▸</span>
            {showLog ? 'Hide' : 'View'} run log ({log.length} lines)
          </button>
          {showLog && <LiveLog log={log} height={280} autoScroll={false}/>}
        </div>
      )}
    </div>
  )
}