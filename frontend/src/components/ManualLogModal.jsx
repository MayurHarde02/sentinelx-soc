import React, { useState } from 'react';
import { Terminal, Send, X, CheckCircle, AlertTriangle } from 'lucide-react';
import api from '../api/client';

const SAMPLE_LOGS = [
  "2026-08-18 20:15:10 LOGIN_FAILED user=admin ip=192.168.1.22 port=22 status=FAILURE",
  '{"event_type": "PORT_SCAN", "source_ip": "198.51.100.42", "port": 8080, "status": "BLOCKED"}',
  "Aug 18 20:15:10 firewall sshd[1234]: Failed password for root from 45.33.32.156 port 2222",
  "2026-08-18 20:15:12 LOGIN_SUCCESS user=admin ip=192.168.1.22 port=443 status=SUCCESS",
  "192.168.1.55 - - [18/Aug/2026:20:15:10 +0000] \"POST /api/v1/auth/login HTTP/1.1\" 401 245"
];

const ManualLogModal = ({ isOpen, onClose, onLogIngested }) => {
  const [logText, setLogText] = useState(SAMPLE_LOGS[0]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleIngest = async (e) => {
    e.preventDefault();
    if (!logText.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.post('/events/raw', { log_line: logText.trim() });
      setResult(res.data);
      if (onLogIngested) onLogIngested();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to ingest log');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div style={{ background: 'var(--color-primary-glow)', color: 'var(--color-primary)', padding: '0.4rem', borderRadius: '6px' }}>
              <Terminal size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Ingest Raw Security Log</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Paste syslog, auth log, JSON payload, or SentinelX format</p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Quick Sample Selector */}
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '0.4rem', fontWeight: 500 }}>Load Sample Preset:</div>
          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
            {SAMPLE_LOGS.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setLogText(sample)}
                className="btn btn-sm"
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem', background: 'var(--bg-surface-raised)' }}
              >
                Sample #{idx + 1}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={handleIngest}>
          <textarea
            className="soc-input font-mono"
            style={{ width: '100%', height: '110px', resize: 'vertical', fontSize: '0.82rem', marginBottom: '1rem' }}
            value={logText}
            onChange={(e) => setLogText(e.target.value)}
            placeholder="e.g. 2026-08-18 20:15:10 LOGIN_FAILED user=admin ip=192.168.1.22 port=22"
          />

          {error && (
            <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div style={{ padding: '0.75rem', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '6px', color: '#34d399', fontSize: '0.8rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                <CheckCircle size={16} />
                <span>Log Parsed & Ingested (Event ID #{result.event_id})</span>
              </div>
              <div style={{ marginTop: '0.4rem', color: 'var(--text-main)', fontSize: '0.75rem' }}>
                Type: <strong>{result.event?.event_type}</strong> | Source IP: <strong>{result.event?.source_ip}</strong> | Alerts Triggered: <strong>{result.alerts_triggered}</strong>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button type="button" onClick={onClose} className="btn">Cancel</button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              <Send size={15} />
              {loading ? 'Ingesting...' : 'Ingest & Evaluate'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ManualLogModal;
