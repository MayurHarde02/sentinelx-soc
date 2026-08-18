import React, { useState, useEffect } from 'react';
import { Globe, Search, ShieldAlert, ShieldCheck, Activity, AlertTriangle, ArrowRight, X } from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

const IpIntelligenceView = () => {
  const [ipProfiles, setIpProfiles] = useState([]);
  const [search, setSearch] = useState('');
  const [selectedIpDetail, setSelectedIpDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchIps = async () => {
    try {
      let url = '/ip-intelligence?limit=100';
      if (search.trim()) url += `&search=${encodeURIComponent(search.trim())}`;
      const res = await api.get(url);
      setIpProfiles(res.data);
    } catch (e) {
      console.error('Failed to load IP intel', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIps();
  }, [search]);

  const handleInspectIp = async (ip) => {
    try {
      const res = await api.get(`/ip-intelligence/${ip}`);
      setSelectedIpDetail(res.data);
    } catch (e) {
      console.error('Failed to load IP profile', e);
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Globe size={22} color="var(--color-primary)" />
          <span>IP Intelligence & Source Reputation Tracking</span>
        </h2>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Profile and score external & internal IP addresses based on event frequency, attack patterns, and alert history
        </p>
      </div>

      {/* Search Toolbar */}
      <div className="soc-card" style={{ padding: '0.85rem 1.25rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: '1', maxWidth: '350px' }}>
          <Search size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
          <input
            type="text"
            className="soc-input font-mono"
            style={{ width: '100%', paddingLeft: '32px' }}
            placeholder="Search IP address..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
          Tracking {ipProfiles.length} unique source addresses
        </span>
      </div>

      {/* IP Profiles Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
        {ipProfiles.length === 0 ? (
          <div className="soc-card" style={{ gridColumn: '1 / -1', textAlign: 'center', color: 'var(--text-dim)', padding: '3rem' }}>
            No IP records found. Ingest logs or run attack simulations.
          </div>
        ) : (
          ipProfiles.map((item) => (
            <div
              key={item.ip}
              className="soc-card"
              style={{
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                borderColor: item.threat_score >= 60 ? 'rgba(239, 68, 68, 0.35)' : 'var(--border-subtle)'
              }}
              onClick={() => handleInspectIp(item.ip)}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <div className="font-mono" style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-primary)' }}>
                    {item.ip}
                  </div>
                  <span
                    className="font-mono"
                    style={{
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      background: item.threat_score >= 70 ? 'rgba(220, 38, 38, 0.2)' : item.threat_score >= 40 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: item.threat_score >= 70 ? '#f87171' : item.threat_score >= 40 ? '#fbbf24' : '#34d399',
                      border: `1px solid ${item.threat_score >= 70 ? 'rgba(220, 38, 38, 0.4)' : item.threat_score >= 40 ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`
                    }}
                  >
                    {item.threat_level} ({item.threat_score}/100)
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.75rem', background: 'var(--bg-main)', padding: '0.65rem', borderRadius: '6px', marginBottom: '0.75rem' }}>
                  <div><span style={{ color: 'var(--text-dim)' }}>Events:</span> <strong className="font-mono">{item.total_events}</strong></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Alerts:</span> <strong className="font-mono" style={{ color: item.total_alerts > 0 ? '#f87171' : 'inherit' }}>{item.total_alerts}</strong></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>First:</span> <span className="font-mono">{item.first_seen ? new Date(item.first_seen).toLocaleTimeString() : '—'}</span></div>
                  <div><span style={{ color: 'var(--text-dim)' }}>Last:</span> <span className="font-mono">{item.last_seen ? new Date(item.last_seen).toLocaleTimeString() : '—'}</span></div>
                </div>

                {/* Target Users */}
                {item.associated_usernames?.length > 0 && (
                  <div style={{ fontSize: '0.75rem', marginBottom: '0.4rem' }}>
                    <span style={{ color: 'var(--text-dim)' }}>Targeted Users: </span>
                    <span className="font-mono" style={{ color: 'var(--text-main)' }}>{item.associated_usernames.join(', ')}</span>
                  </div>
                )}

                {/* Alert Types */}
                {item.alert_types?.length > 0 && (
                  <div style={{ fontSize: '0.75rem', marginBottom: '0.4rem' }}>
                    <span style={{ color: 'var(--text-dim)' }}>Attack Vectors: </span>
                    <span style={{ color: '#fbbf24', fontWeight: 600 }}>{item.alert_types.join(', ')}</span>
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-primary)', display: 'flex', alignItems: 'center', gap: '0.3rem', fontWeight: 600 }}>
                  Inspect Full Footprint <ArrowRight size={13} />
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Detailed IP Inspection Modal */}
      {selectedIpDetail && (
        <div className="modal-backdrop">
          <div className="modal-container" style={{ padding: '1.5rem', maxWidth: '750px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <h3 className="font-mono" style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--color-primary)' }}>{selectedIpDetail.ip}</h3>
                  <span
                    className="font-mono"
                    style={{
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      padding: '0.2rem 0.6rem',
                      borderRadius: '4px',
                      background: selectedIpDetail.threat_score >= 70 ? 'rgba(220, 38, 38, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                      color: selectedIpDetail.threat_score >= 70 ? '#f87171' : '#fbbf24',
                      border: '1px solid currentColor'
                    }}
                  >
                    THREAT SCORE: {selectedIpDetail.threat_score}/100 ({selectedIpDetail.threat_level})
                  </span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Total Events Recorded: {selectedIpDetail.total_events} • Alerts Triggered: {selectedIpDetail.total_alerts}
                </div>
              </div>
              <button onClick={() => setSelectedIpDetail(null)} className="btn btn-sm">Close</button>
            </div>

            {/* Targeted Ports & Users */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
              <div style={{ background: 'var(--bg-main)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.78rem' }}>
                <div style={{ color: 'var(--text-dim)', marginBottom: '0.3rem', fontWeight: 600 }}>TARGETED PORTS</div>
                <div className="font-mono" style={{ color: 'var(--color-primary)' }}>
                  {selectedIpDetail.targeted_ports?.length > 0 ? selectedIpDetail.targeted_ports.join(', ') : 'None probed'}
                </div>
              </div>

              <div style={{ background: 'var(--bg-main)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.78rem' }}>
                <div style={{ color: 'var(--text-dim)', marginBottom: '0.3rem', fontWeight: 600 }}>ASSOCIATED USER ACCOUNTS</div>
                <div className="font-mono" style={{ color: 'var(--text-main)' }}>
                  {selectedIpDetail.associated_usernames?.length > 0 ? selectedIpDetail.associated_usernames.join(', ') : 'None recorded'}
                </div>
              </div>
            </div>

            {/* Recent Alerts from this IP */}
            {selectedIpDetail.recent_alerts?.length > 0 && (
              <div style={{ marginBottom: '1.25rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Triggered Threat Detections ({selectedIpDetail.recent_alerts.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '160px', overflowY: 'auto' }}>
                  {selectedIpDetail.recent_alerts.map(al => (
                    <div key={al.id} style={{ background: 'var(--bg-surface-raised)', padding: '0.5rem 0.75rem', borderRadius: '4px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span style={{ fontWeight: 600, fontSize: '0.8rem' }}>{al.alert_type}</span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginLeft: '0.5rem' }}>{al.description}</span>
                      </div>
                      <SeverityBadge severity={al.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recent Event Log Stream from this IP */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                Recent Event Footprint (Last {selectedIpDetail.recent_events?.length || 0})
              </div>
              <div style={{ background: 'var(--bg-main)', padding: '0.5rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', maxHeight: '180px', overflowY: 'auto' }}>
                {selectedIpDetail.recent_events?.map(ev => (
                  <div key={ev.id} className="font-mono" style={{ fontSize: '0.72rem', padding: '0.3rem 0.4rem', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                    <span>{new Date(ev.timestamp).toLocaleTimeString()} - <strong>{ev.event_type}</strong></span>
                    <span style={{ color: ev.status === 'SUCCESS' ? '#34d399' : ev.status === 'FAILURE' ? '#f87171' : 'inherit' }}>{ev.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IpIntelligenceView;
