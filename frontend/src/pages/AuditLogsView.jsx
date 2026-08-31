import React, { useState, useEffect } from 'react';
import {
  ClipboardList,
  Search,
  RefreshCw,
  User,
  Shield,
  Clock,
  Filter,
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import api from '../api/client';

const ACTION_TYPES = [
  'ALL',
  'LOGIN',
  'LOGOUT',
  'ALERT_STATUS_CHANGE',
  'ALERT_ESCALATE',
  'INCIDENT_CREATE',
  'INCIDENT_UPDATE',
  'INCIDENT_NOTE',
  'RULE_CREATE',
  'RULE_DELETE',
  'FEED_ADD',
  'FEED_DELETE',
  'PASSWORD_CHANGE',
  'SIMULATION_TRIGGER'
];

const ACTION_COLORS = {
  LOGIN: { bg: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', border: 'rgba(16, 185, 129, 0.3)' },
  LOGOUT: { bg: 'rgba(100, 116, 139, 0.15)', color: '#94a3b8', border: 'rgba(100, 116, 139, 0.3)' },
  ALERT_STATUS_CHANGE: { bg: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: 'rgba(59, 130, 246, 0.3)' },
  ALERT_ESCALATE: { bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },
  INCIDENT_CREATE: { bg: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: 'rgba(168, 85, 247, 0.3)' },
  INCIDENT_UPDATE: { bg: 'rgba(6, 182, 212, 0.15)', color: '#67e8f9', border: 'rgba(6, 182, 212, 0.3)' },
  INCIDENT_NOTE: { bg: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: 'rgba(59, 130, 246, 0.3)' },
  RULE_CREATE: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)' },
  RULE_DELETE: { bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },
  FEED_ADD: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)' },
  FEED_DELETE: { bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },
  PASSWORD_CHANGE: { bg: 'rgba(234, 88, 12, 0.15)', color: '#fdba74', border: 'rgba(234, 88, 12, 0.3)' },
  SIMULATION_TRIGGER: { bg: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: 'rgba(168, 85, 247, 0.3)' }
};

const AuditLogsView = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actorSearch, setActorSearch] = useState('');
  const [selectedAction, setSelectedAction] = useState('ALL');
  const [limit, setLimit] = useState(100);

  const fetchAuditLogs = async () => {
    try {
      let url = `/audit?limit=${limit}`;
      if (selectedAction !== 'ALL') url += `&action=${selectedAction}`;
      if (actorSearch.trim()) url += `&actor=${encodeURIComponent(actorSearch.trim())}`;

      const res = await api.get(url);
      setLogs(res.data);
    } catch (err) {
      console.error('Failed to fetch audit logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
    const interval = setInterval(fetchAuditLogs, 8000);
    return () => clearInterval(interval);
  }, [actorSearch, selectedAction, limit]);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ClipboardList size={22} color="var(--color-primary)" />
            <span>SOC Audit Trail &amp; Compliance Log</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Immutable historical record of all analyst operations, configuration changes, and threat mitigations
          </p>
        </div>
        <button onClick={fetchAuditLogs} className="btn btn-sm">
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="soc-card" style={{ padding: '0.85rem 1.25rem', display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: '1', minWidth: '180px' }}>
          <Search size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
          <input
            type="text"
            className="soc-input"
            style={{ width: '100%', paddingLeft: '32px' }}
            placeholder="Search by analyst username..."
            value={actorSearch}
            onChange={(e) => setActorSearch(e.target.value)}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Action:</span>
          <select
            className="soc-select font-mono"
            style={{ fontSize: '0.75rem' }}
            value={selectedAction}
            onChange={(e) => setSelectedAction(e.target.value)}
          >
            {ACTION_TYPES.map(act => (
              <option key={act} value={act}>{act}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Limit:</span>
          <select
            className="soc-select"
            value={limit}
            onChange={(e) => setLimit(parseInt(e.target.value))}
          >
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={200}>200</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto', maxHeight: '640px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Analyst (Actor)</th>
                <th>Action</th>
                <th>Target Entity</th>
                <th>Client IP</th>
                <th>Operation Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '3rem' }}>
                    No audit records match the current filter.
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const style = ACTION_COLORS[log.action] || { bg: 'rgba(100, 116, 139, 0.15)', color: '#94a3b8', border: 'rgba(100, 116, 139, 0.3)' };

                  return (
                    <tr key={log.id}>
                      <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        #{log.id}
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--color-primary)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                          <User size={13} color="var(--text-dim)" />
                          <span>{log.actor_username}</span>
                        </div>
                      </td>
                      <td>
                        <span
                          className="font-mono"
                          style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            background: style.bg,
                            color: style.color,
                            border: `1px solid ${style.border}`,
                            display: 'inline-block'
                          }}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-main)' }}>
                        {log.target_entity || '—'}
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        {log.client_ip || '127.0.0.1'}
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {log.details || '—'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AuditLogsView;
