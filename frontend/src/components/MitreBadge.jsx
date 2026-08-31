import React from 'react';

const MitreBadge = ({ tactic, techniqueId, techniqueName }) => {
  if (!techniqueId) return null;

  return (
    <span
      title={techniqueName ? `${techniqueName} (${tactic || 'Technique'})` : `MITRE ATT&CK ${techniqueId}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        background: 'rgba(15, 23, 42, 0.8)',
        border: '1px solid rgba(6, 182, 212, 0.35)',
        borderRadius: '4px',
        fontSize: '0.7rem',
        overflow: 'hidden',
        lineHeight: 1.2,
        userSelect: 'none',
        whiteSpace: 'nowrap'
      }}
    >
      <span
        className="font-mono"
        style={{
          background: 'rgba(6, 182, 212, 0.2)',
          color: '#06b6d4',
          fontWeight: 700,
          padding: '0.15rem 0.4rem',
          borderRight: '1px solid rgba(6, 182, 212, 0.25)'
        }}
      >
        {techniqueId}
      </span>
      {tactic && (
        <span
          style={{
            color: 'var(--text-muted)',
            padding: '0.15rem 0.45rem',
            fontSize: '0.68rem'
          }}
        >
          {tactic}
        </span>
      )}
    </span>
  );
};

export default MitreBadge;
