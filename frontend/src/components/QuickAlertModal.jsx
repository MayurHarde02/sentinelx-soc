import React from 'react';
import { AlertCircle, X, ShieldAlert, ArrowRight, CheckCircle2 } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';

const QuickAlertModal = ({ alert, isOpen, onClose, onUpdateStatus, onEscalate }) => {
  if (!isOpen || !alert) return null;

  let details = {};
  try {
    details = alert.details_json ? JSON.parse(alert.details_json) : {};
  } catch (e) {
    details = {};
  }

  return (
    <div className="modal-backdrop">
      <div className="modal-container" style={{ padding: '1.5rem', maxWidth: '680px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Alert #{alert.id}</span>
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 600 }}>{alert.alert_type}</h3>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Overview Box */}
        <div style={{ background: 'var(--bg-main)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', marginBottom: '1.25rem' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-main)', marginBottom: '0.75rem', lineHeight: 1.5 }}>
            {alert.description}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem', fontSize: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)' }}>
            <div>
              <span style={{ color: 'var(--text-dim)', display: 'block' }}>Attacker Source IP</span>
              <span className="font-mono" style={{ fontWeight: 600, color: 'var(--color-primary)' }}>{alert.source_ip}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-dim)', display: 'block' }}>Detection Rule</span>
              <span className="font-mono" style={{ fontWeight: 600 }}>{alert.rule}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-dim)', display: 'block' }}>Timestamp</span>
              <span className="font-mono">{new Date(alert.timestamp).toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* Trigger Telemetry Details */}
        {Object.keys(details).length > 0 && (
          <div style={{ marginBottom: '1.25rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
              Rule Trigger Payload Telemetry
            </div>
            <pre className="font-mono" style={{ background: 'var(--bg-surface-raised)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.75rem', overflowX: 'auto', border: '1px solid var(--border-subtle)', color: '#38bdf8' }}>
              {JSON.stringify(details, null, 2)}
            </pre>
          </div>
        )}

        {/* Actions bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Quick Status:</span>
            {['Open', 'Investigating', 'Resolved', 'False Positive'].map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => onUpdateStatus(alert.id, st)}
                className="btn btn-sm"
                style={{
                  fontSize: '0.7rem',
                  background: alert.status === st ? 'var(--bg-surface-active)' : 'transparent',
                  borderColor: alert.status === st ? 'var(--color-primary)' : 'var(--border-subtle)'
                }}
              >
                {st}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => onEscalate(alert)}
              className="btn btn-danger btn-sm"
            >
              <ShieldAlert size={14} />
              Escalate to Incident
            </button>
            <button onClick={onClose} className="btn btn-sm">Close</button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuickAlertModal;
