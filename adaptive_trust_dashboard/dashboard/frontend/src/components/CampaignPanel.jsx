import React, { useState, useEffect } from 'react'

/**
 * Per-campaign breakdown of the injected attacks.
 *
 * One row per MITRE technique: which identity was attacked, how many malicious
 * events it produced, the span they cover, when the identity was restricted and
 * how many of its events fell inside that detection window.
 *
 * All of this is measured from the generated trace — nothing here is derived
 * from a summary.
 */

const C = {
  card: 'var(--bg-card)', surface: 'var(--bg-surface)', border: 'var(--border)',
  pri: 'var(--text-pri)', sec: '#a9bcd6', hint: '#8ea3c0', dim: 'var(--text-dim)',
  mono: 'var(--font-mono)',
  green: 'var(--z-green)', red: 'var(--z-red)', yellow: 'var(--z-yellow)', purple: 'var(--z-purple)',
}

const fmtTime = s => (s ? String(s).replace('T', ' ').replace('Z', '').slice(0, 16) : '—')
const fmtLat = m => (m == null ? '—' : m < 90 ? `${Math.round(m)} min`
                          : `${Math.floor(m / 60)} h ${String(Math.round(m % 60)).padStart(2, '0')}`)

export default function CampaignPanel() {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(null)
  const [err, setErr] = useState(null)

  useEffect(() => {
    let alive = true
    fetch('/api/campaigns')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then(d => alive && setData(d))
      .catch(e => alive && setErr(e.message))
    return () => { alive = false }
  }, [])

  if (err) return (
    <div style={{ padding: 20, fontFamily: C.mono, fontSize: 11, color: C.red }}>
      Could not load campaigns: {err}
    </div>
  )
  if (!data) return (
    <div style={{ padding: 20, fontFamily: C.mono, fontSize: 11, color: C.hint }}>
      Loading campaign breakdown…
    </div>
  )
  if (!data.campaigns?.length) return (
    <div style={{ padding: 20, fontFamily: C.mono, fontSize: 11, color: C.hint }}>
      No campaigns yet — initialise the simulation first.
    </div>
  )

  const th = (t, w) => (
    <th style={{ width: w, padding: '5px 8px', textAlign: 'left', fontFamily: C.mono,
                 fontSize: 8.5, letterSpacing: '.06em', textTransform: 'uppercase',
                 color: C.hint, fontWeight: 600 }}>{t}</th>
  )

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 4 }}>
        <span style={{ fontFamily: C.mono, fontSize: 11.5, color: C.sec, letterSpacing: '.08em' }}>
          ATTACK CAMPAIGNS · INJECTED INTO THE LIVE RUN
        </span>
        <span style={{ fontFamily: C.mono, fontSize: 10, color: C.hint }}>
          {data.detected} of {data.total} restricted
        </span>
      </div>
      <div style={{ fontFamily: C.mono, fontSize: 10.5, color: C.hint, lineHeight: 1.6,
                    marginBottom: 12, maxWidth: 900 }}>
        Each campaign is one MITRE technique against one identity. It emits many malicious events
        over several days. “Restricted after” is measured from the campaign’s first malicious
        event to the moment that identity was cut off; “in window” is how many of its events
        happened before that. Click a row for the full detail.
      </div>

      <div style={{ border: `1px solid ${C.border}`, borderRadius: 5, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: C.surface, borderBottom: `1px solid ${C.border}` }}>
              {th('Campaign', 150)}{th('Tactic', 62)}{th('Identity', 88)}
              {th('Events', 62)}{th('Days', 52)}{th('First attack', 132)}
              {th('Restricted at', 132)}{th('Restricted after', 118)}{th('In window', 72)}
            </tr>
          </thead>
          <tbody>
            {data.campaigns.map((r, i) => {
              const det = r.detected
              const isOpen = open === r.scenario
              return (
                <React.Fragment key={r.scenario}>
                  <tr onClick={() => setOpen(isOpen ? null : r.scenario)}
                      style={{ borderBottom: `1px solid ${C.border}`, cursor: 'pointer',
                               background: isOpen ? C.purple + '18' : (i % 2 ? 'transparent' : '#ffffff04') }}>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10.5, color: C.pri }}>
                      {det ? '' : '⚠ '}{r.label}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10, color: C.hint }}>
                      {r.tactic}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10, color: C.sec }}>
                      {r.victim}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10.5, color: C.pri }}>
                      {r.n_events}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10, color: C.hint }}>
                      {r.days_spanned}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 9.5, color: C.hint }}>
                      {fmtTime(r.first_attack)}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 9.5,
                                 color: det ? C.pri : C.red }}>
                      {det ? fmtTime(r.restricted_at) : 'not restricted'}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10.5,
                                 fontWeight: 700, color: det ? C.yellow : C.red }}>
                      {det ? fmtLat(r.latency_min) : '—'}
                    </td>
                    <td style={{ padding: '6px 8px', fontFamily: C.mono, fontSize: 10,
                                 color: det ? C.sec : C.dim }}>
                      {det ? `${r.events_in_window} of ${r.n_events}` : '—'}
                    </td>
                  </tr>

                  {isOpen && (
                    <tr style={{ background: C.surface }}>
                      <td colSpan={9} style={{ padding: '10px 14px' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)',
                                      gap: 10, fontFamily: C.mono, fontSize: 10.5 }}>
                          <div>
                            <div style={{ color: C.hint, fontSize: 9, marginBottom: 2 }}>IDENTITY</div>
                            <div style={{ color: C.pri }}>{r.victim} · {r.role}</div>
                          </div>
                          <div>
                            <div style={{ color: C.hint, fontSize: 9, marginBottom: 2 }}>CAMPAIGN SPAN</div>
                            <div style={{ color: C.pri }}>
                              {fmtTime(r.first_attack)} → {fmtTime(r.last_attack)}
                              {r.span_hours != null && (
                                <span style={{ color: C.hint }}>
                                  {' '}({r.span_hours < 48
                                    ? `${r.span_hours.toFixed(1)} h`
                                    : `${Math.floor(r.span_hours / 24)} d ${Math.round(r.span_hours % 24)} h`})
                                </span>
                              )}
                            </div>
                          </div>
                          <div>
                            <div style={{ color: C.hint, fontSize: 9, marginBottom: 2 }}>API CALLS USED</div>
                            <div style={{ color: C.pri }}>{r.actions.join(', ')}</div>
                          </div>
                        </div>
                        <div style={{ marginTop: 8, fontFamily: C.mono, fontSize: 10, color: C.hint,
                                      lineHeight: 1.6 }}>
                          {det
                            ? `${r.events_in_window} of its ${r.n_events} malicious events happened before the
                               identity was restricted — the remaining ${r.n_events - r.events_in_window}
                               still appear in the trace afterwards, because the timeline is generated
                               up-front for reproducibility rather than curtailed by enforcement.`
                            : `Never restricted. This campaign uses only quiet, read-shaped calls, so trust
                               never fell below the 0.55 boundary.`}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 10, fontFamily: C.mono, fontSize: 10, color: C.hint, lineHeight: 1.6 }}>
        Sorted fastest to slowest. Median across the detected campaigns is what the
        “Scenarios” tile reports.
      </div>
    </div>
  )
}
