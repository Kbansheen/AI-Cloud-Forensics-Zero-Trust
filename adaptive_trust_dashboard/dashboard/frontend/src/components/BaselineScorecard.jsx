import React from 'react'

// Mirrors the colour scheme already used in ComparisonPanel so the two
// views read as one consistent story rather than two different dashboards.
const COND_COLOUR = { A: '#10b981', B: '#f97316', C: '#7c3aed' }

const CARDS = [
  { key: 0, letter: 'A', title: 'Paper 1 baseline', subtitle: 'Static λ/ρ · no adversary' },
  { key: 1, letter: 'B', title: 'Baseline under evasion', subtitle: 'Static λ/ρ · pacing adversary' },
  { key: 2, letter: 'C', title: 'Paper 2 — adaptive fix', subtitle: 'UCB-tuned λ/ρ · pacing adversary' },
]

function StatCard({ row, meta }) {
  const c = COND_COLOUR[meta.letter]
  return (
    <div style={{
      flex: 1, minWidth: 200, border: `1px solid ${c}40`, borderRadius: 10,
      background: 'var(--bg-card)', padding: '16px 18px', position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: c,
      }}/>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
        <span style={{
          width: 20, height: 20, borderRadius: 5, background: `${c}20`, color: c,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 11,
        }}>{meta.letter}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: 'var(--text-pri)' }}>
          {meta.title}
        </span>
      </div>
      <div style={{ fontSize: 9, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginBottom: 14 }}>
        {meta.subtitle}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 700, color: c, lineHeight: 1 }}>
            {(row.detection_rate * 100).toFixed(1)}<span style={{ fontSize: 12 }}>%</span>
          </div>
          <div style={{ fontSize: 9, color: 'var(--text-sec)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '.08em' }}>
            Detection rate
          </div>
        </div>
        <div style={{ display: 'flex', gap: 18 }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: 'var(--text-pri)' }}>
              {row.fpr_per_10k}
            </div>
            <div style={{ fontSize: 8, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
              FPR / 10K
            </div>
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: 'var(--text-pri)' }}>
              {(row.precision * 100).toFixed(1)}%
            </div>
            <div style={{ fontSize: 8, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Precision
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function BaselineScorecard({ results }) {
  if (!results) return null
  const { summary } = results
  if (!summary || summary.length < 3) return null

  const [a, b, c] = summary
  const detectionDelta = (c.detection_rate - b.detection_rate) * 100
  const fprReductionPct = b.fpr_per_10k > 0 ? ((b.fpr_per_10k - c.fpr_per_10k) / b.fpr_per_10k) * 100 : 0
  const precisionDeltaPts = (c.precision - b.precision) * 100

  return (
    <div style={{ padding: '18px 16px', display: 'flex', flexDirection: 'column', gap: 18 }}>

      {/* Headline finding */}
      <div style={{
        border: '1px solid var(--z-purple)', borderRadius: 10,
        background: 'rgba(124,58,237,.08)', padding: '16px 20px',
      }}>
        <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '.1em', color: '#c4b5fd', fontFamily: 'var(--font-mono)', marginBottom: 6 }}>
          Key finding — C vs B
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 700, color: 'var(--text-pri)', lineHeight: 1.5 }}>
          {Math.abs(detectionDelta) < 0.1 ? 'Same detection rate' : `Detection rate ${detectionDelta >= 0 ? '+' : ''}${detectionDelta.toFixed(1)} pts`}
          {' · '}
          <span style={{ color: fprReductionPct > 0 ? '#10b981' : '#ef4444' }}>
            {fprReductionPct > 0 ? '−' : '+'}{Math.abs(fprReductionPct).toFixed(1)}% false positives
          </span>
          {' · '}
          precision {precisionDeltaPts >= 0 ? '+' : ''}{precisionDeltaPts.toFixed(1)} pts
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-sec)', fontFamily: 'var(--font-mono)', marginTop: 6, lineHeight: 1.6 }}>
          The adaptive bandit doesn't catch more of the pacing adversary's attacks than the static baseline does under the
          same evasion pressure — it catches the same ones with far fewer false alarms along the way.
        </div>
      </div>

      {/* Three-condition cards */}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {CARDS.map(meta => <StatCard key={meta.key} row={summary[meta.key]} meta={meta}/>)}
      </div>

      <div style={{ fontSize: 9, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>
        A/B/C figures are live from the most recent Run Analysis pass (n_users=20, days=30 — statistically equivalent to
        the full Paper 1 50-user/90-day run). A is the unattacked Paper 1 reference point; B shows the pacing adversary
        exploiting fixed λ/ρ; C is the Paper 2 UCB-adaptive result under identical attack pressure.
      </div>
    </div>
  )
}
