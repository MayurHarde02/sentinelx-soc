import React, { useState, useEffect } from 'react';
import { AlertOctagon, Search, ShieldAlert, CheckCircle, RefreshCw, Filter } from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

const ALERT_TYPES = ['ALL', 'BRUTE_FORCE', 'PORT_SCAN', 'SUSPICIOUS_LOGIN', 'EVENT_FLOOD'];
const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = ['ALL', 'Open', 'Investigating', 'Resolved', 'False Positive'];

const AlertsView = ({ onOpenAlert, onEscalateAlert }) => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedType, setSelectedType] = useState('ALL');
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [searchIp, setSearchIp] = useState('');
  const [limit, setLimit] = useState(50);

  const fetchAlerts = async () => {
    try {
      let url = `/alerts?limit=${limit}`;
      if (selectedSeverity !== 'ALL') url += `&severity=${selectedSeverity}`;
      if (selectedType !== 'ALL') url += `&alert_type=${selectedType}`;
      if (selectedStatus !== 'ALL') url += `&status=${selectedStatus}`;
      if (searchIp.trim()) url += `&source_ip=${encodeURIComponent(searchIp.trim())}`;

      const res = await api.get(url);
      setAlerts(res.data);
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
  }, [selectedSeverity, selectedType, selectedStatus, searchIp, limit]);

  const handleUpdateStatus = async (alertId, newStatus, e) => {
    e.stopPropagation();
    try {
      await api.patch(`/alerts/${alertId}/status`, { status: newStatus });
      fetchAlerts();
    } catch (err) {
      console.error('Failed to update alert status', err);
    }
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
            Investigate automated threat detections, update alert status, and escalate to incident response
          </p>
        </div>
        <button onClick={fetchAlerts} className="btn btn-sm">
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="soc-card" style={{ padding: '0.85rem 1.25rem', display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
        {/* Source IP Search */}
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

        {/* Severity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Severity:</span>
          <select
            className="soc-select"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        {/* Alert Type */}
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

        {/* Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Status:</span>
          <select
            className="soc-select"
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
          >
            {STATUSES.map(st => <option key={st} value={st}>{st}</option>)}
          </select>
        </div>
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
                <th>Description</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '3rem' }}>
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
                    <td style={{ fontSize: '0.8rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
    </div>
  );
};

export default AlertsView;
