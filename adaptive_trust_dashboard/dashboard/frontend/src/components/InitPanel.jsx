import React, { useState, useEffect, useRef } from 'react'

/**
 * Shown in place of the identity grid when no identities exist yet.
 *
 * Instead of a blank window, this narrates what the engine is actually doing
 * while it builds the simulation: loading real CloudTrail logs, registering
 * identities, training one Isolation Forest per identity, generating the
 * 90-day trace, and placing the attack campaigns. Progress is read from
 * /api/init-progress, which the backend updates stage by stage from a worker
 * thread, so it stays live while initialisation is still running.
 */

const STAGES = [
  { n: 1, label: 'Load real CloudTrail logs',
    hint: 'Read the real AWS exports in real_logs/ and count valid events per IAM role.' },
  { n: 2, label: 'Create identities',
    hint: 'Give every identity its own trust bucket, starting at 0.85.' },
  { n: 3, label: 'Train one Isolation Forest per identity',
    hint: 'Each identity gets its own model of "what is normal for me", from their real logs plus synthetic padding.' },
  { n: 4, label: 'Generate the 90-day event trace',
    hint: 'Produce every CloudTrail-format event the simulation will replay.' },
  { n: 5, label: 'Register the MITRE ATT&CK scenarios',
    hint: 'Place the 8 attack campaigns on their start days.' },
]

const C = {
  green: 'var(--z-green)', yellow: 'var(--z-yellow)', orange: 'var(--z-orange)',
  red: 'var(--z-red)', purple: 'var(--z-purple)',
  card: 'var(--bg-card)', surface: 'var(--bg-surface)', border: 'var(--border)',
  pri: 'var(--text-pri)', sec: 'var(--text-sec)', dim: 'var(--text-dim)',
  // --text-dim (#3d5270) is used elsewhere for faint chrome, but it is too dark
  // for body copy on the #070c18 background. These two tones keep the panel
  // readable while still reading as secondary text.
  sub:  '#a9bcd6',   // stage titles, future stages
  hint: '#8ea3c0',   // the one-line explanation under each stage
  mono: 'var(--font-mono)',
}

export default function InitPanel({ onInit }) {
  const [p, setP] = useState(null)
  const timer = useRef(null)

  useEffect(() => {
    let alive = true
    const poll = async () => {
      try {
        const r = await fetch('/api/init-progress')
        if (r.ok && alive) setP(await r.json())
      } catch { /* backend not up yet — ignore */ }
    }
    poll()
    timer.current = setInterval(poll, 500)
    return () => { alive = false; clearInterval(timer.current) }
  }, [])

  const running = !!p?.running
  const done    = !!p?.done
  const failed  = p?.failed
  const stage   = p?.stage || 0

  // Overall progress: each completed stage is a fifth; stage 3 is weighted by
  // how many forests have been trained.
  let frac = stage / 5
  if (stage === 3 && p?.users_total) frac = (2 + p.users_done / p.users_total) / 5
  if (done) frac = 1

  const stageState = (n) => {
    if (done) return 'done'
    if (stage > n) return 'done'
    if (stage === n) return 'running'
    return 'pending'
  }

  const badge = failed
    ? { text: 'FAILED', colour: C.red }
    : running ? { text: 'INITIALISING', colour: C.yellow }
    : done ? { text: 'READY', colour: C.green }
    : { text: 'NOT STARTED', colour: C.sub }

  return (
    <div style={{ maxWidth: 980, margin: '0 auto', padding: '18px 4px' }}>

      {/* ── header ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
        <span style={{ fontFamily: C.mono, fontSize: 13, fontWeight: 700,
                       letterSpacing: '.09em', color: C.pri }}>
          IDENTITY INITIALISATION
        </span>
        <span style={{ fontFamily: C.mono, fontSize: 10, fontWeight: 700, letterSpacing: '.07em',
                       color: badge.colour, background: badge.colour + '18',
                       border: `1px solid ${badge.colour}55`, borderRadius: 4, padding: '2px 7px' }}>
          {badge.text}
        </span>
        {running && (
          <span style={{ fontFamily: C.mono, fontSize: 11, color: C.sec, marginLeft: 'auto' }}>
            {p?.elapsed_s?.toFixed(1)}s
          </span>
        )}
        {done && (
          <span style={{ fontFamily: C.mono, fontSize: 11, color: C.sec, marginLeft: 'auto' }}>
            finished in {p?.elapsed_s?.toFixed(1)}s
          </span>
        )}
      </div>

      <div style={{ fontFamily: C.mono, fontSize: 11, color: C.sub, marginBottom: 14, lineHeight: 1.5 }}>
        Building the simulation: 50 identities, each with its own behavioural baseline, then the
        event trace they will be judged against. Nothing is scored until this finishes.
      </div>

      {/* ── overall bar ────────────────────────────────────────────────── */}
      <div style={{ height: 4, background: C.surface, borderRadius: 2, overflow: 'hidden', marginBottom: 18 }}>
        <div style={{ height: '100%', width: `${Math.round(frac * 100)}%`,
                      background: failed ? C.red : (done ? C.green : C.yellow),
                      transition: 'width .45s ease' }} />
      </div>

      {/* ── stages ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {STAGES.map(s => {
          const st = stageState(s.n)
          const dot = st === 'done' ? '✓' : st === 'running' ? '▶' : '○'
          const col = st === 'done' ? C.green : st === 'running' ? C.yellow : C.sub
          const isCur = st === 'running'
          return (
            <div key={s.n} style={{
              display: 'flex', gap: 12, alignItems: 'flex-start',
              padding: '9px 12px', borderRadius: 5,
              background: isCur ? C.yellow + '0e' : 'transparent',
              border: `1px solid ${isCur ? C.yellow + '44' : 'transparent'}`,
            }}>
              <span style={{ fontFamily: C.mono, fontSize: 12, color: col, width: 14, lineHeight: '17px' }}>
                {dot}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                  <span style={{ fontFamily: C.mono, fontSize: 12,
                                 color: st === 'pending' ? C.sub : C.pri }}>
                    {s.n}. {s.label}
                  </span>
                  {isCur && p?.detail && (
                    <span style={{ fontFamily: C.mono, fontSize: 10.5, color: C.yellow,
                                   whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {p.detail}
                    </span>
                  )}
                  {st === 'done' && s.n === 3 && p?.users_total > 0 && (
                    <span style={{ fontFamily: C.mono, fontSize: 10.5, color: C.hint }}>
                      {p.users_total} models
                    </span>
                  )}
                  {st === 'done' && s.n === 1 && p?.real_events > 0 && (
                    <span style={{ fontFamily: C.mono, fontSize: 10.5, color: C.hint }}>
                      {p.real_events.toLocaleString()} events
                    </span>
                  )}
                  {st === 'done' && s.n === 4 && p?.events > 0 && (
                    <span style={{ fontFamily: C.mono, fontSize: 10.5, color: C.hint }}>
                      {p.events.toLocaleString()} events
                    </span>
                  )}
                  {st === 'done' && s.n === 5 && p?.scenarios &&
                   Object.keys(p.scenarios).length > 0 && (
                    <span style={{ fontFamily: C.mono, fontSize: 10.5, color: C.hint }}>
                      {Object.keys(p.scenarios).length} campaigns
                    </span>
                  )}
                </div>
                <div style={{ fontFamily: C.mono, fontSize: 10.5, color: C.hint,
                              marginTop: 2, lineHeight: 1.45 }}>
                  {s.hint}
                </div>
                {/* per-stage progress bar for the forest training */}
                {isCur && s.n === 3 && p?.users_total > 0 && (
                  <div style={{ height: 2, background: C.surface, borderRadius: 1,
                                marginTop: 6, overflow: 'hidden' }}>
                    <div style={{ height: '100%', background: C.yellow,
                                  width: `${Math.round(100 * p.users_done / p.users_total)}%`,
                                  transition: 'width .3s ease' }} />
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* ── real events per role, once known ───────────────────────────── */}
      {p?.real_per_role && Object.keys(p.real_per_role).length > 0 && (
        <div style={{ marginTop: 16, padding: '10px 12px', background: C.card,
                      border: `1px solid ${C.border}`, borderRadius: 5 }}>
          <div style={{ fontFamily: C.mono, fontSize: 10, color: C.sec,
                        letterSpacing: '.07em', marginBottom: 6 }}>
            REAL CLOUDTRAIL EVENTS USED PER ROLE
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {Object.entries(p.real_per_role).map(([role, n]) => (
              <span key={role} style={{
                fontFamily: C.mono, fontSize: 10, color: C.sec,
                background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 3, padding: '2px 6px' }}>
                {role} <span style={{ color: C.pri }}>{n.toLocaleString()}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── live log ───────────────────────────────────────────────────── */}
      {p?.log?.length > 0 && (
        <div style={{ marginTop: 10, padding: '10px 12px', background: C.card,
                      border: `1px solid ${C.border}`, borderRadius: 5 }}>
          <div style={{ fontFamily: C.mono, fontSize: 10, color: C.sec,
                        letterSpacing: '.07em', marginBottom: 6 }}>
            WORK LOG
          </div>
          {/* maxHeight + overflowY scrolls the log. The lines are flex children,
              and flex children shrink by default (flex-shrink: 1) — with 40 of
              them inside a 132px box each row was being squashed to ~3px and
              clipped mid-glyph, which rendered as a column of unreadable dashes
              rather than a scrolling list. flexShrink: 0 keeps each line at its
              natural height so the container scrolls instead of crushing it. */}
          <div style={{ maxHeight: 150, overflowY: 'auto', display: 'flex',
                        flexDirection: 'column', gap: 1 }}>
            {p.log.slice(-40).map((line, i) => (
              <div key={i} style={{ fontFamily: C.mono, fontSize: 10.5, color: C.sub,
                                    lineHeight: 1.5, whiteSpace: 'nowrap',
                                    overflow: 'hidden', textOverflow: 'ellipsis',
                                    flexShrink: 0 }}>
                {line}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── failure ────────────────────────────────────────────────────── */}
      {failed && (
        <div style={{ marginTop: 12, padding: '10px 12px', background: C.red + '14',
                      border: `1px solid ${C.red}55`, borderRadius: 5,
                      fontFamily: C.mono, fontSize: 11, color: C.red, lineHeight: 1.5 }}>
          Initialisation failed: {failed}
        </div>
      )}

      {/* ── call to action when idle ───────────────────────────────────── */}
      {!running && !done && !failed && (
        <div style={{ marginTop: 18, display: 'flex', alignItems: 'center', gap: 12 }}>
          <button onClick={onInit} style={{
            fontFamily: C.mono, fontSize: 11.5, fontWeight: 700, letterSpacing: '.04em',
            color: '#04101f', background: C.purple, border: 'none', cursor: 'pointer',
            borderRadius: 5, padding: '8px 16px' }}>
            ⚡ INITIALISE IDENTITIES
          </button>
          <span style={{ fontFamily: C.mono, fontSize: 11, color: C.hint }}>
            takes about 20 seconds · everything above runs in that time
          </span>
        </div>
      )}
    </div>
  )
}
