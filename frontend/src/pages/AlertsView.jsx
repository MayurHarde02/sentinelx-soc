import React, { useState, useEffect } from 'react';
import { AlertOctagon, Search, ShieldAlert, CheckCircle, RefreshCw, X, Plus } from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import MitreBadge from '../components/MitreBadge';
import CreateRuleModal from '../components/CreateRuleModal';
import { useWebSocket } from '../context/WebSocketContext';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES   = ['Open', 'Investigating', 'Resolved', 'False Positive'];

const AlertsView = ({ onOpenAlert, onEscalateAlert }) => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  // Multi-select chip filters
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [selectedStatuses, setSelectedStatuses]     = useState([]);
  const [selectedType, setSelectedType]             = useState('ALL');
  const [searchIp, setSearchIp]                     = useState('');
  const [limit, setLimit]                           = useState(50);

  const [isCreateRuleOpen, setIsCreateRuleOpen] = useState(false);

  const { newAlertCount } = useWebSocket();

  const ALERT_TYPES = ['ALL', 'BRUTE_FORCE', 'PORT_SCAN', 'SUSPICIOUS_LOGIN', 'EVENT_FLOOD', 'ANOMALY_DETECTION', 'KNOWN_MALICIOUS_IP', 'CUSTOM'];

  const fetchAlerts = async () => {
    try {
      let url = `/alerts?limit=${limit}`;
      if (selectedSeverities.length === 1) url += `&severity=${selectedSeverities[0]}`;
      if (selectedStatuses.length === 1)   url += `&status=${encodeURIComponent(selectedStatuses[0])}`;
      if (selectedType !== 'ALL')          url += `&alert_type=${selectedType}`;
      if (searchIp.trim())                 url += `&source_ip=${encodeURIComponent(searchIp.trim())}`;

      const res = await api.get(url);
      let data = res.data;

      // Client-side multi-filter when multiple selections
      if (selectedSeverities.length > 1) {
        data = data.filter(a => selectedSeverities.includes(a.severity));
      }
      if (selectedStatuses.length > 1) {
        data = data.filter(a => selectedStatuses.includes(a.status));
      }

      setAlerts(data);
    } catch (e) {
      console.error('Failed to load alerts', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 4000);
    return () => clearInterval(interval);
  }, [selectedSeverities, selectedStatuses, selectedType, searchIp, limit]);

  // Refresh when new WS alerts arrive
  useEffect(() => {
    if (newAlertCount > 0) fetchAlerts();
  }, [newAlertCount]);

  const toggleSeverity = (sev) => {
    setSelectedSeverities(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  const toggleStatus = (st) => {
    setSelectedStatuses(prev =>
      prev.includes(st) ? prev.filter(s => s !== st) : [...prev, st]
    );
  };

  const handleUpdateStatus = async (alertId, newStatus, e) => {
    e.stopPropagation();
    try {
      await api.patch(`/alerts/${alertId}/status`, { status: newStatus });
      fetchAlerts();
    } catch (err) {
      console.error('Failed to update alert status', err);
    }
  };

  const SEV_COLORS = {
    CRITICAL: { bg: 'rgba(220,38,38,0.15)', color: '#f87171', border: 'rgba(220,38,38,0.4)' },
    HIGH:     { bg: 'rgba(239,68,68,0.15)',  color: '#fca5a5', border: 'rgba(239,68,68,0.4)' },
    MEDIUM:   { bg: 'rgba(245,158,11,0.15)', color: '#fbbf24', border: 'rgba(245,158,11,0.4)' },
    LOW:      { bg: 'rgba(59,130,246,0.15)', color: '#93c5fd', border: 'rgba(59,130,246,0.4)' },
  };

  const ST_COLORS = {
    'Open':           { bg: 'rgba(239,68,68,0.12)',  color: '#f87171', border: 'rgba(239,68,68,0.3)' },
    'Investigating':  { bg: 'rgba(245,158,11,0.12)', color: '#fbbf24', border: 'rgba(245,158,11,0.3)' },
    'Resolved':       { bg: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: 'rgba(16,185,129,0.3)' },
    'False Positive': { bg: 'rgba(100,116,139,0.15)',color: '#94a3b8', border: 'rgba(100,116,139,0.3)' },
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <AlertOctagon size={22} color="var(--color-danger)" />
            <span>Alerts Triage Queue</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Investigate threat detections, update status, and escalate to incidents
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={() => setIsCreateRuleOpen(true)} className="btn btn-primary btn-sm">
            <Plus size={14} />
            <span>Custom Rule</span>
          </button>
          <button onClick={fetchAlerts} className="btn btn-sm">
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="soc-card" style={{ padding: '0.85rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {/* Row 1: Search + Type filter */}
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1', minWidth: '180px' }}>
            <Search size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
            <input
              type="text"
              className="soc-input font-mono"
              style={{ width: '100%', paddingLeft: '32px' }}
              placeholder="Filter by Source IP..."
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Type:</span>
            <select
              className="soc-select"
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
            >
              {ALERT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
        </div>

        {/* Row 2: Severity multi-select chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Severity:
          </span>
          {SEVERITIES.map(sev => {
            const active = selectedSeverities.includes(sev);
            const c = SEV_COLORS[sev];
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                style={{
                  padding: '0.2rem 0.65rem',
                  borderRadius: '20px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: `1px solid ${active ? c.border : 'var(--border-subtle)'}`,
                  background: active ? c.bg : 'transparent',
                  color: active ? c.color : 'var(--text-dim)',
                  transition: 'all 0.15s ease'
                }}
              >
                {sev}
              </button>
            );
          })}
          {selectedSeverities.length > 0 && (
            <button
              onClick={() => setSelectedSeverities([])}
              style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.72rem' }}
            >
              <X size={12} /> Clear
            </button>
          )}
        </div>

        {/* Row 3: Status multi-select chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Status:
          </span>
          {STATUSES.map(st => {
            const active = selectedStatuses.includes(st);
            const c = ST_COLORS[st] || { bg: 'rgba(100,116,139,0.15)', color: '#94a3b8', border: 'rgba(100,116,139,0.3)' };
            return (
              <button
                key={st}
                onClick={() => toggleStatus(st)}
                style={{
                  padding: '0.2rem 0.65rem',
                  borderRadius: '20px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: `1px solid ${active ? c.border : 'var(--border-subtle)'}`,
                  background: active ? c.bg : 'transparent',
                  color: active ? c.color : 'var(--text-dim)',
                  transition: 'all 0.15s ease'
                }}
              >
                {st}
              </button>
            );
          })}
          {selectedStatuses.length > 0 && (
            <button
              onClick={() => setSelectedStatuses([])}
              style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.72rem' }}
            >
              <X size={12} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Result count */}
      <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
        Showing <strong style={{ color: 'var(--text-muted)' }}>{alerts.length}</strong> alerts
        {(selectedSeverities.length > 0 || selectedStatuses.length > 0) && (
          <span> — filtered</span>
        )}
      </div>

      {/* Alerts Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto', maxHeight: '600px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Alert Type</th>
                <th>Source IP</th>
                <th>Severity</th>
                <th>MITRE</th>
                <th>Description</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '3rem' }}>
                    No alerts match the selected criteria.
                  </td>
                </tr>
              ) : (
                alerts.map((al) => (
                  <tr key={al.id} onClick={() => onOpenAlert(al)} style={{ cursor: 'pointer' }}>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>#{al.id}</td>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(al.timestamp).toLocaleString()}
                    </td>
                    <td style={{ fontWeight: 600 }}>{al.alert_type}</td>
                    <td className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>{al.source_ip}</td>
                    <td><SeverityBadge severity={al.severity} /></td>
                    <td>
                      <MitreBadge
                        tactic={al.mitre_tactic}
                        techniqueId={al.mitre_technique_id}
                        techniqueName={al.mitre_technique_name}
                      />
                    </td>
                    <td style={{ fontSize: '0.8rem', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {al.description}
                    </td>
                    <td><StatusBadge status={al.status} /></td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.4rem' }} onClick={(e) => e.stopPropagation()}>
                        <select
                          className="soc-select"
                          style={{ padding: '0.2rem 0.4rem', fontSize: '0.7rem' }}
                          value={al.status}
                          onChange={(e) => handleUpdateStatus(al.id, e.target.value, e)}
                        >
                          <option value="Open">Open</option>
                          <option value="Investigating">Investigating</option>
                          <option value="Resolved">Resolved</option>
                          <option value="False Positive">False Positive</option>
                        </select>
                        <button
                          onClick={() => onEscalateAlert(al)}
                          className="btn btn-danger btn-sm"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.7rem' }}
                          title="Escalate to Incident"
                        >
                          <ShieldAlert size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <CreateRuleModal
        isOpen={isCreateRuleOpen}
        onClose={() => setIsCreateRuleOpen(false)}
        onRuleCreated={fetchAlerts}
      />
    </div>
  );
};

export default AlertsView;
