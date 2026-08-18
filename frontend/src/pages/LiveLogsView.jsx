import React, { useState, useEffect } from 'react';
import { Activity, Search, Filter, Terminal, RefreshCw, Trash2 } from 'lucide-react';
import api from '../api/client';
import StatusBadge from '../components/StatusBadge';

const EVENT_TYPES = [
  'ALL',
  'LOGIN_FAILED',
  'LOGIN_SUCCESS',
  'PORT_SCAN',
  'NETWORK_CONNECTION',
  'FILE_ACCESS',
  'UNAUTHORIZED_ACCESS'
];

const LiveLogsView = ({ onOpenManualLog }) => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedType, setSelectedType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [limit, setLimit] = useState(50);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchEvents = async () => {
    try {
      let url = `/events?limit=${limit}`;
      if (selectedType !== 'ALL') url += `&event_type=${selectedType}`;
      if (selectedStatus !== 'ALL') url += `&status=${selectedStatus}`;
      if (searchQuery.trim()) url += `&search=${encodeURIComponent(searchQuery.trim())}`;

      const res = await api.get(url);
      setEvents(res.data);
    } catch (e) {
      console.error('Failed to load events', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 3500); // 3.5s auto poll for live streaming
    return () => clearInterval(interval);
  }, [selectedType, selectedStatus, searchQuery, limit]);

  const handleClearLogs = async () => {
    if (window.confirm('Clear all security events and alerts in database?')) {
      await api.delete('/events/clear');
      fetchEvents();
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header & Action Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Activity size={22} color="var(--color-primary)" />
            <span>Normalized Security Event Stream</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Real-time normalized security logs parsed from application, authentication, and network telemetry
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
          <button onClick={onOpenManualLog} className="btn btn-primary btn-sm">
            <Terminal size={14} />
            <span>Inject Raw Log</span>
          </button>
          <button onClick={handleClearLogs} className="btn btn-danger btn-sm" title="Clear all logs">
            <Trash2 size={14} />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="soc-card" style={{ padding: '0.85rem 1.25rem', display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: '1', minWidth: '220px' }}>
          <Search size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
          <input
            type="text"
            className="soc-input"
            style={{ width: '100%', paddingLeft: '32px' }}
            placeholder="Search by IP, username, raw log string..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* Type Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Type:</span>
          <select
            className="soc-select"
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
          >
            {EVENT_TYPES.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        {/* Status Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Status:</span>
          <select
            className="soc-select"
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
          >
            <option value="ALL">ALL</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="FAILURE">FAILURE</option>
            <option value="BLOCKED">BLOCKED</option>
            <option value="INFO">INFO</option>
          </select>
        </div>

        {/* Limit */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Limit:</span>
          <select
            className="soc-select"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={200}>200</option>
          </select>
        </div>

        <button onClick={fetchEvents} className="btn btn-sm" style={{ marginLeft: 'auto' }}>
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Events Table */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto', maxHeight: '600px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Source IP</th>
                <th>Dst IP:Port</th>
                <th>User</th>
                <th>Status</th>
                <th>Raw / Details</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '3rem' }}>
                    No security events found matching the criteria. Click "Inject Raw Log" or "Seed Attacks".
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id} onClick={() => setSelectedEvent(ev)} style={{ cursor: 'pointer' }}>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>#{ev.id}</td>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="font-mono" style={{
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        color: ev.event_type.includes('FAIL') ? '#f87171' : ev.event_type.includes('SUCCESS') ? '#34d399' : 'var(--color-primary)'
                      }}>
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>{ev.source_ip}</td>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {ev.destination_ip || '—'}{ev.port ? `:${ev.port}` : ''}
                    </td>
                    <td className="font-mono" style={{ color: ev.username ? 'var(--text-main)' : 'var(--text-dim)' }}>
                      {ev.username || '—'}
                    </td>
                    <td><StatusBadge status={ev.status} /></td>
                    <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.raw_log || '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Event Details Modal / Drawer */}
      {selectedEvent && (
        <div className="modal-backdrop">
          <div className="modal-container" style={{ padding: '1.5rem', maxWidth: '650px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Activity size={18} color="var(--color-primary)" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Event #{selectedEvent.id} Inspector</h3>
              </div>
              <button onClick={() => setSelectedEvent(null)} className="btn btn-sm">Close</button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', background: 'var(--bg-main)', padding: '1rem', borderRadius: '6px', marginBottom: '1rem', fontSize: '0.8rem' }}>
              <div><span style={{ color: 'var(--text-dim)' }}>Timestamp:</span> <span className="font-mono">{new Date(selectedEvent.timestamp).toLocaleString()}</span></div>
              <div><span style={{ color: 'var(--text-dim)' }}>Event Type:</span> <span className="font-mono" style={{ fontWeight: 600 }}>{selectedEvent.event_type}</span></div>
              <div><span style={{ color: 'var(--text-dim)' }}>Source IP:</span> <span className="font-mono" style={{ color: 'var(--color-primary)' }}>{selectedEvent.source_ip}</span></div>
              <div><span style={{ color: 'var(--text-dim)' }}>Destination:</span> <span className="font-mono">{selectedEvent.destination_ip || 'N/A'}:{selectedEvent.port || 'N/A'}</span></div>
              <div><span style={{ color: 'var(--text-dim)' }}>User Account:</span> <span className="font-mono">{selectedEvent.username || 'N/A'}</span></div>
              <div><span style={{ color: 'var(--text-dim)' }}>Status:</span> <StatusBadge status={selectedEvent.status} /></div>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '0.4rem', fontWeight: 600 }}>RAW LOG PAYLOAD</div>
              <pre className="font-mono" style={{ background: 'var(--bg-surface-raised)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.75rem', color: '#38bdf8', overflowX: 'auto', border: '1px solid var(--border-subtle)' }}>
                {selectedEvent.raw_log}
              </pre>
            </div>

            {selectedEvent.metadata_json && (
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '0.4rem', fontWeight: 600 }}>NORMALIZED METADATA</div>
                <pre className="font-mono" style={{ background: 'var(--bg-surface-raised)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.75rem', color: '#a78bfa', overflowX: 'auto', border: '1px solid var(--border-subtle)' }}>
                  {JSON.stringify(JSON.parse(selectedEvent.metadata_json || '{}'), null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveLogsView;
