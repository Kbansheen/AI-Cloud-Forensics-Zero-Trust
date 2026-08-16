import React, { useRef, useEffect } from 'react'

const ZONE_STYLE = {
  normal_access: { bg: 'var(--z-green-bg)',  border: 'var(--z-green)',  color: 'var(--z-green)' },
  step_up_mfa:   { bg: 'var(--z-yellow-bg)', border: 'var(--z-yellow)', color: 'var(--z-yellow)' },
  read_only:     { bg: 'var(--z-orange-bg)', border: 'var(--z-orange)', color: 'var(--z-orange)' },
  quarantine:    { bg: 'var(--z-red-bg)',    border: 'var(--z-red)',    color: 'var(--z-red)' },
}

const ZONE_LABELS = {
  normal_access: 'NORMAL',
  step_up_mfa:   'MFA',
  read_only:     'RO',
  quarantine:    'QUAR',
}

function TrustBar({ trust, zone }) {
  const z = ZONE_STYLE[zone] || ZONE_STYLE.normal_access
  return (
    <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, marginTop: 6, overflow: 'hidden' }}>
      <div style={{
        height: '100%',
        width: `${Math.round(trust * 100)}%`,
        background: z.color,
        borderRadius: 2,
        transition: 'width 0.4s ease, background 0.3s',
      }} />
    </div>
  )
}

function UserCard({ user, onClick, selected }) {
  const z = ZONE_STYLE[user.zone] || ZONE_STYLE.normal_access
  const prevTrust = useRef(user.trust)
  const flash = useRef(false)
  const [isFlashing, setIsFlashing] = React.useState(false)

  useEffect(() => {
    if (Math.abs(user.trust - prevTrust.current) > 0.02) {
      setIsFlashing(true)
      setTimeout(() => setIsFlashing(false), 400)
    }
    prevTrust.current = user.trust
  }, [user.trust])

  return (
    <div
      onClick={() => onClick(user)}
      style={{
        padding: '10px 12px',
        background: selected ? z.bg : (isFlashing ? z.bg : 'var(--bg-card)'),
        border: `1px solid ${selected ? z.border : (user.zone === 'quarantine' ? 'var(--z-red)' : 'var(--border)')}`,
        borderRadius: 6,
        cursor: 'pointer',
        transition: 'background 0.3s, border 0.3s',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Quarantine pulse ring */}
      {user.zone === 'quarantine' && (
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
          border: '1px solid var(--z-red)',
          borderRadius: 6,
          animation: 'pulse-ring 1.5s ease-out infinite',
          pointerEvents: 'none',
        }} />
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 2 }}>
        <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-sec)', fontWeight: 600 }}>
          {user.user_id}
        </span>
        <span style={{
          fontSize: 9, fontFamily: 'var(--font-mono)', fontWeight: 700,
          color: z.color, letterSpacing: '0.05em',
        }}>
          {ZONE_LABELS[user.zone] || '—'}
        </span>
      </div>

      <div style={{ fontSize: 9, color: 'var(--text-dim)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {user.role}
      </div>

      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 20, fontWeight: 700, color: z.color, lineHeight: 1 }}>
        {(user.trust * 100).toFixed(0)}
        <span style={{ fontSize: 10, fontWeight: 400, color: 'var(--text-sec)', marginLeft: 1 }}>%</span>
      </div>

      <TrustBar trust={user.trust} zone={user.zone} />
    </div>
  )
}

export default function TrustGrid({ users, onSelectUser, selectedUser }) {
  const sorted = [...users].sort((a, b) => a.trust - b.trust)

  return (
    <div>
      <style>{`
        @keyframes pulse-ring {
          0%   { opacity: 1; transform: scale(1); }
          100% { opacity: 0; transform: scale(1.05); }
        }
      `}</style>

      {/* Zone legend */}
      <div style={{ display: 'flex', gap: 16, padding: '8px 0 12px', borderBottom: '1px solid var(--border)', marginBottom: 12 }}>
        {Object.entries(ZONE_STYLE).map(([zone, style]) => (
          <div key={zone} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: style.color }} />
            <span style={{ fontSize: 10, color: 'var(--text-sec)', fontFamily: 'var(--font-mono)' }}>
              {ZONE_LABELS[zone]}
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>
              ({users.filter(u => u.zone === zone).length})
            </span>
          </div>
        ))}
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))',
        gap: 6,
      }}>
        {sorted.map(user => (
          <UserCard
            key={user.user_id}
            user={user}
            onClick={onSelectUser}
            selected={selectedUser?.user_id === user.user_id}
          />
        ))}
      </div>

      {users.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          No users yet — initialise simulation first
        </div>
      )}
    </div>
  )
}
