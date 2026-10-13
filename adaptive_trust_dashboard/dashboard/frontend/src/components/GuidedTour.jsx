import React, { useEffect, useState, useLayoutEffect } from 'react'

export const TOUR_STEPS = [
  {
    target: '[data-tour="header"]',
    title: 'Zero Trust Trust Engine',
    body: 'A behavioral-drift trust engine for cloud identities — every AWS action is scored for anomaly, and trust decays or recovers over time based on that score. This tour walks through the main pieces of the dashboard.',
  },
  {
    target: '[data-tour="control-panel"]',
    title: 'Control panel',
    body: 'Initialise the simulation, step through events or run them continuously, inject MITRE ATT&CK scenarios, toggle adaptive (UCB) mode, and kick off the full 3-condition comparison analysis.',
  },
  {
    target: '[data-tour="view-toggle"]',
    title: 'Three views',
    body: '"Live Monitor" shows every identity in real time. "Analysis Report" has the detailed per-scenario A/B/C tables once an analysis has run. "Baseline vs Adaptive" is the headline scorecard comparing the static baseline against the UCB-adaptive fix.',
  },
  {
    target: '[data-tour="trust-grid"]',
    title: 'Live Monitor',
    body: 'Each card is one identity: current trust score, enforcement zone, role, and a REAL/SYNTH badge showing whether that role\u2019s baseline was trained on real CloudTrail logs. Click any card to open its detail panel below.',
  },
  {
    target: '[data-tour="alerts"]',
    title: 'Alerts',
    body: 'Zone-change events stream in here live. Click an alert to open a SHAP explanation of exactly why the Isolation Forest flagged that action.',
  },
  {
    target: '[data-tour="detail-panel"]',
    title: 'Identity detail',
    body: 'Trust trajectory, \u03bb/\u03c1 over time, and (in adaptive mode) UCB arm convergence for the selected identity. Drag the top edge to resize this panel.',
  },
  {
    target: '[data-tour="metrics-bar"]',
    title: 'Aggregate metrics',
    body: 'Rolled-up counts across every identity, updating live as the simulation runs. That\u2019s the tour \u2014 you can replay it any time from the ? button.',
  },
]

function getRect(selector) {
  const el = document.querySelector(selector)
  if (!el) return null
  return el.getBoundingClientRect()
}

function Spotlight({ rect }) {
  if (!rect) return null
  const pad = 6
  return (
    <div
      style={{
        position: 'fixed',
        top: rect.top - pad,
        left: rect.left - pad,
        width: rect.width + pad * 2,
        height: rect.height + pad * 2,
        borderRadius: 8,
        boxShadow: '0 0 0 9999px rgba(3,5,10,.72)',
        border: '1px solid var(--z-purple)',
        pointerEvents: 'none',
        zIndex: 9998,
        transition: 'top .25s ease, left .25s ease, width .25s ease, height .25s ease',
      }}
    />
  )
}

function TourTooltip({ rect, step, stepIndex, total, onNext, onBack, onSkip }) {
  const [pos, setPos] = useState({ top: 100, left: 100 })

  useLayoutEffect(() => {
    if (!rect) return
    const tooltipWidth = 300
    const margin = 14
    let top = rect.bottom + margin
    let left = Math.min(Math.max(rect.left, margin), window.innerWidth - tooltipWidth - margin)

    // If there isn't room below, place it above the target instead.
    if (top + 160 > window.innerHeight) {
      top = Math.max(rect.top - 160 - margin, margin)
    }
    setPos({ top, left })
  }, [rect])

  return (
    <div
      style={{
        position: 'fixed', top: pos.top, left: pos.left, width: 300, zIndex: 9999,
        background: 'var(--bg-card)', border: '1px solid var(--z-purple)', borderRadius: 10,
        padding: '14px 16px', boxShadow: '0 8px 30px rgba(0,0,0,.5)',
        fontFamily: 'var(--font-mono)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontSize: 9, color: '#c4b5fd', letterSpacing: '.08em', textTransform: 'uppercase' }}>
          Step {stepIndex + 1} / {total}
        </span>
        <button onClick={onSkip} style={{
          background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 11, padding: 0,
        }}>✕</button>
      </div>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-pri)', marginBottom: 6 }}>
        {step.title}
      </div>
      <div style={{ fontSize: 10.5, color: 'var(--text-sec)', lineHeight: 1.6, marginBottom: 14 }}>
        {step.body}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button onClick={onSkip} style={{
          background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 9,
        }}>Skip tour</button>
        <div style={{ display: 'flex', gap: 6 }}>
          {stepIndex > 0 && (
            <button onClick={onBack} style={{
              padding: '4px 10px', fontSize: 10, borderRadius: 4, cursor: 'pointer',
              background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-sec)',
            }}>Back</button>
          )}
          <button onClick={onNext} style={{
            padding: '4px 12px', fontSize: 10, borderRadius: 4, cursor: 'pointer',
            background: 'var(--z-purple)', border: '1px solid var(--z-purple)', color: '#fff', fontWeight: 700,
          }}>{stepIndex === total - 1 ? 'Done' : 'Next'}</button>
        </div>
      </div>
    </div>
  )
}

export default function GuidedTour({ stepIndex, onNext, onBack, onClose }) {
  const [rect, setRect] = useState(null)
  const step = TOUR_STEPS[stepIndex]

  useEffect(() => {
    if (stepIndex === null || stepIndex === undefined) return
    const el = document.querySelector(step.target)
    const update = () => setRect(getRect(step.target))
    if (el) {
      el.scrollIntoView({ block: 'center', behavior: 'smooth' })
      setTimeout(update, 260)
    } else {
      setRect(null)
    }
    window.addEventListener('resize', update)
    window.addEventListener('scroll', update, true)
    return () => {
      window.removeEventListener('resize', update)
      window.removeEventListener('scroll', update, true)
    }
  }, [stepIndex])

  if (stepIndex === null || stepIndex === undefined || !step) return null

  return (
    <>
      <Spotlight rect={rect} />
      {rect ? (
        <TourTooltip
          rect={rect} step={step} stepIndex={stepIndex} total={TOUR_STEPS.length}
          onNext={onNext} onBack={onBack} onSkip={onClose}
        />
      ) : (
        // Target not currently on screen (e.g. different centreView active) — show a
        // centered card instead of nothing, rather than silently skipping the step.
        <div style={{
          position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
          width: 300, zIndex: 9999, background: 'var(--bg-card)', border: '1px solid var(--z-purple)',
          borderRadius: 10, padding: '14px 16px', boxShadow: '0 8px 30px rgba(0,0,0,.5)', fontFamily: 'var(--font-mono)',
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-pri)', marginBottom: 6 }}>{step.title}</div>
          <div style={{ fontSize: 10.5, color: 'var(--text-sec)', lineHeight: 1.6, marginBottom: 14 }}>{step.body}</div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
            {stepIndex > 0 && (
              <button onClick={onBack} style={{ padding: '4px 10px', fontSize: 10, borderRadius: 4, cursor: 'pointer', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-sec)' }}>Back</button>
            )}
            <button onClick={onNext} style={{ padding: '4px 12px', fontSize: 10, borderRadius: 4, cursor: 'pointer', background: 'var(--z-purple)', border: '1px solid var(--z-purple)', color: '#fff', fontWeight: 700 }}>
              {stepIndex === TOUR_STEPS.length - 1 ? 'Done' : 'Next'}
            </button>
          </div>
        </div>
      )}
    </>
  )
}
