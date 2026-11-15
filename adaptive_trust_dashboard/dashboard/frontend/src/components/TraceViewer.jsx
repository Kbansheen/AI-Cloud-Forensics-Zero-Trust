import React, { useState, useEffect, useCallback } from 'react'

/**
 * Shows the actual CloudTrail trace the simulator produced.
 *
 * Two modes:
 *   compact — a few fields per event, several rows at a time
 *   json    — the full raw record, exactly as it will be scored
 *
 * Data comes from GET /api/trace/sample, so what you see is the trace itself,
 * not a reconstruction of it.
 */

const C = {
  card: 'var(--bg-card)', surface: 'var(--bg-surface)', border: 'var(--border)',
  pri: 'var(--text-pri)', sec: '#a9bcd6', dim: 'var(--text-dim)', hint: '#8ea3c0',
  mono: 'var(--font-mono)',
  green: 'var(--z-green)', red: 'var(--z-red)', yellow: 'var(--z-yellow)',
}

const FIELD = (label, value, colour) => (
  <div style={{ display: 'flex', gap: 6, minWidth: 0 }}>
    <span style={{ fontFamily: C.mono, fontSize: 9, color: C.hint, width: 66, flexShrink: 0,
                   textTransform: 'uppercase', letterSpacing: '.05em' }}>{label}</span>
    <span style={{ fontFamily: C.mono, fontSize: 10.5, color: colour || C.pri,
                   whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{value}</span>
  </div>
)

/** One event as a compact row of fields. */
export function EventRow({ ev, idx }) {
  const attack = ev.eventName && (ev.readOnly === false || ev.__attack)
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '150px 150px 1fr 130px 110px',
                  gap: 10, padding: '4px 8px', borderBottom: `1px solid ${C.border}`,
                  background: idx % 2 ? 'transparent' : '#ffffff05' }}>
      <span style={{ fontFamily: C.mono, fontSize: 10, color: C.hint }}>
        {String(ev.eventTime || '').replace('T', ' ').replace('Z', '')}
      </span>
      <span style={{ fontFamily: C.mono, fontSize: 10, color: C.sec }}>
        {ev.userName || '—'}
      </span>
      <span style={{ fontFamily: C.mono, fontSize: 10.5, color: C.pri,
                     overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {(ev.eventSource || '').replace('.amazonaws.com', '')}:{ev.eventName}
      </span>
      <span style={{ fontFamily: C.mono, fontSize: 10, color: C.hint }}>
        {ev.sourceIPAddress}
      </span>
      <span style={{ fontFamily: C.mono, fontSize: 9.5,
                     color: ev.readOnly ? C.green : C.yellow }}>
        {ev.readOnly ? 'read-only' : 'write'}
      </span>
    </div>
  )
}

/** Full JSON of one event. */
export function EventJSON({ ev }) {
  if (!ev) return null
  return (
    <pre style={{
      fontFamily: C.mono, fontSize: 9.5, lineHeight: 1.5, color: C.sec,
      background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4,
      padding: '8px 10px', margin: 0, overflowX: 'auto',
      maxHeight: full ? 520 : 240,
    }}>
      {JSON.stringify(ev, null, 2)}
    </pre>
  )
}

export default function TraceViewer({ title = 'EVENT TRACE', defaultOnly = 'all', full = false }) {
  // full = rendered as its own tab rather than an inset panel: more rows per
  // page, taller JSON pane.
  const PAGE = full ? 20 : 6
  const [data, setData] = useState(null)
  const [offset, setOffset] = useState(0)
  const [only, setOnly] = useState(defaultOnly)
  const [showJson, setShowJson] = useState(false)
  const [err, setErr] = useState(null)

  const load = useCallback(async () => {
    try {
      const r = await fetch(`/api/trace/sample?offset=${offset}&limit=${PAGE}&only=${only}`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setData(await r.json())
      setErr(null)
    } catch (e) { setErr(e.message) }
  }, [offset, only, PAGE])

  useEffect(() => { load() }, [load])

  const btn = (label, onClick, active) => (
    <button onClick={onClick} style={{
      fontFamily: C.mono, fontSize: 9.5, letterSpacing: '.05em',
      color: active ? '#04101f' : C.sec,
      background: active ? C.yellow : 'transparent',
      border: `1px solid ${active ? C.yellow : C.border}`,
      borderRadius: 3, padding: '2px 8px', cursor: 'pointer',
    }}>{label}</button>
  )

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 5,
                  padding: '10px 12px', marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8,
                    flexWrap: 'wrap' }}>
        <span style={{ fontFamily: C.mono, fontSize: full ? 11.5 : 10, color: C.sec,
                       letterSpacing: '.07em' }}>{title}</span>
        <span style={{ fontFamily: C.mono, fontSize: 9.5, color: C.hint }}>
          {data ? `${data.total.toLocaleString()} events` : '…'}
        </span>
        <div style={{ display: 'flex', gap: 5, marginLeft: 'auto' }}>
          {btn('all', () => { setOnly('all'); setOffset(0) }, only === 'all')}
          {btn('attack', () => { setOnly('attack'); setOffset(0) }, only === 'attack')}
          {btn('benign', () => { setOnly('benign'); setOffset(0) }, only === 'benign')}
          {btn(showJson ? 'fields' : 'raw JSON', () => setShowJson(!showJson), showJson)}
        </div>
      </div>

      {err && (
        <div style={{ fontFamily: C.mono, fontSize: 10, color: C.red }}>
          Could not load trace: {err}
        </div>
      )}

      {data && !showJson && (
        <div style={{ border: `1px solid ${C.border}`, borderRadius: 4, overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '150px 150px 1fr 130px 110px',
                        gap: 10, padding: '4px 8px', background: C.surface,
                        borderBottom: `1px solid ${C.border}` }}>
            {['timestamp', 'identity', 'api call', 'source ip', 'access'].map(h => (
              <span key={h} style={{ fontFamily: C.mono, fontSize: 8.5, color: C.hint,
                                     letterSpacing: '.06em', textTransform: 'uppercase' }}>{h}</span>
            ))}
          </div>
          {data.events.map((ev, i) => <EventRow key={offset + i} ev={ev} idx={i} />)}
        </div>
      )}

      {data && showJson && <EventJSON ev={data.raw_first} />}

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
        <span style={{ fontFamily: C.mono, fontSize: 9.5, color: C.hint }}>
          showing {data ? `${data.offset + 1}–${Math.min(data.offset + data.limit, data.total)}` : '—'}
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 5 }}>
          {btn('‹ prev', () => setOffset(Math.max(0, offset - PAGE)), false)}
          {btn('next ›', () => setOffset(offset + PAGE), false)}
        </div>
      </div>
    </div>
  )
}
