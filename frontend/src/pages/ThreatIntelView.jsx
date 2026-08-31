import React, { useState, useEffect } from 'react';
import {
  Shield,
  Plus,
  Trash2,
  Globe,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Search,
  MapPin,
  Server,
  Radio
} from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

const ThreatIntelView = () => {
  const [feedItems, setFeedItems] = useState([]);
  const [loading, setLoading] = useState(true);

  // Add feed item form state
  const [ipCidr, setIpCidr] = useState('');
  const [threatType, setThreatType] = useState('KNOWN_MALICIOUS_IP');
  const [source, setSource] = useState('SOC Analyst Blocklist');
  const [severity, setSeverity] = useState('HIGH');
  const [formError, setFormError] = useState('');
  const [formSuccess, setFormSuccess] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // GeoIP Lookup state
  const [lookupIp, setLookupIp] = useState('');
  const [geoResult, setGeoResult] = useState(null);
  const [geoLoading, setGeoLoading] = useState(false);
  const [geoError, setGeoError] = useState('');

  const fetchFeed = async () => {
    try {
      setLoading(true);
      const res = await api.get('/threat-intel/feed');
      setFeedItems(res.data);
    } catch (err) {
      console.error('Failed to load threat feed', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFeed();
  }, []);

  const handleAddFeedItem = async (e) => {
    e.preventDefault();
    if (!ipCidr.trim()) return;
    setFormError('');
    setFormSuccess('');
    setSubmitting(true);

    try {
      await api.post('/threat-intel/feed', {
        ip_cidr: ipCidr.trim(),
        threat_type: threatType,
        source: source.trim() || 'SOC Analyst',
        severity: severity
      });
      setFormSuccess(`Successfully registered ${ipCidr.trim()} to active blocklist.`);
      setIpCidr('');
      fetchFeed();
      setTimeout(() => setFormSuccess(''), 3500);
    } catch (err) {
      setFormError(err.response?.data?.detail || 'Failed to add threat feed item');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteItem = async (id, ip) => {
    try {
      await api.delete(`/threat-intel/feed/${id}`);
      setFeedItems(prev => prev.filter(item => item.id !== id));
    } catch (err) {
      console.error('Failed to delete feed item', err);
    }
  };

  const handleGeoLookup = async (e) => {
    e?.preventDefault();
    const target = lookupIp.trim();
    if (!target) return;

    setGeoLoading(true);
    setGeoError('');
    setGeoResult(null);

    try {
      const res = await api.get(`/threat-intel/geoip/${encodeURIComponent(target)}`);
      setGeoResult(res.data);
    } catch (err) {
      setGeoError(err.response?.data?.detail || 'Failed to resolve IP location');
    } finally {
      setGeoLoading(false);
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Shield size={22} color="var(--color-primary)" />
            <span>Threat Intelligence &amp; Feed Manager</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Manage known malicious C2/botnet IP blocklists, query GeoIP/ASN intelligence, and review threat feeds
          </p>
        </div>
        <button onClick={fetchFeed} className="btn btn-sm">
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Grid: Left Blocklist form + GeoIP lookup, Right Blocklist Table */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.25rem', alignItems: 'start' }}>
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Add Known Bad IP Form */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div className="soc-card-title">
                <Plus size={16} color="var(--color-primary)" />
                <span>Add IP to Malicious Blocklist</span>
              </div>
            </div>

            {formError && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.78rem', marginBottom: '0.75rem' }}>
                {formError}
              </div>
            )}
            {formSuccess && (
              <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#6ee7b7', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.78rem', marginBottom: '0.75rem' }}>
                {formSuccess}
              </div>
            )}

            <form onSubmit={handleAddFeedItem} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div>
                <label style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Target IP or CIDR Subnet *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.44 or 198.51.100.0/24"
                  className="soc-input font-mono"
                  style={{ width: '100%' }}
                  value={ipCidr}
                  onChange={(e) => setIpCidr(e.target.value)}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                <div>
                  <label style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Threat Category
                  </label>
                  <select
                    className="soc-select"
                    style={{ width: '100%' }}
                    value={threatType}
                    onChange={(e) => setThreatType(e.target.value)}
                  >
                    <option value="KNOWN_MALICIOUS_IP">Malicious IP</option>
                    <option value="C2_SERVER">C2 Server</option>
                    <option value="TOR_EXIT_NODE">Tor Exit Node</option>
                    <option value="BOTNET_NODE">Botnet Node</option>
                    <option value="SCANNER_IP">Scanner / Prober</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                    Severity
                  </label>
                  <select
                    className="soc-select"
                    style={{ width: '100%' }}
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.25rem' }}>
                  Intel Source / Description
                </label>
                <input
                  type="text"
                  placeholder="e.g. AbuseIPDB 100% Confidence"
                  className="soc-input"
                  style={{ width: '100%' }}
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                />
              </div>

              <button type="submit" className="btn btn-primary btn-sm" disabled={submitting} style={{ marginTop: '0.25rem' }}>
                <Plus size={14} />
                <span>{submitting ? 'Registering...' : 'Register to Blocklist'}</span>
              </button>
            </form>
          </div>

          {/* GeoIP & ASN Resolution Widget */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div className="soc-card-title">
                <Globe size={16} color="#06b6d4" />
                <span>GeoIP &amp; ASN Telemetry Lookup</span>
              </div>
            </div>

            <form onSubmit={handleGeoLookup} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <input
                type="text"
                placeholder="Enter IP (e.g. 198.51.100.44)..."
                className="soc-input font-mono"
                style={{ flex: 1 }}
                value={lookupIp}
                onChange={(e) => setLookupIp(e.target.value)}
              />
              <button type="submit" className="btn btn-sm" disabled={geoLoading}>
                <Search size={14} />
                <span>{geoLoading ? '...' : 'Query'}</span>
              </button>
            </form>

            {geoError && (
              <div style={{ color: '#f87171', fontSize: '0.75rem', padding: '0.5rem 0' }}>
                {geoError}
              </div>
            )}

            {geoResult && (
              <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-mono" style={{ fontWeight: 700, color: 'var(--color-primary)', fontSize: '0.85rem' }}>
                    {geoResult.ip}
                  </span>
                  <span style={{ fontSize: '1.1rem' }}>{geoResult.country_flag || '🌐'}</span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <MapPin size={13} color="var(--text-dim)" />
                  <span>{geoResult.city}, {geoResult.country} ({geoResult.country_code})</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Server size={13} color="var(--text-dim)" />
                  <span className="font-mono">{geoResult.asn}</span> — {geoResult.isp}
                </div>
                {geoResult.is_known_threat && (
                  <div style={{ marginTop: '0.3rem', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', padding: '0.25rem 0.5rem', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600, border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                    ⚠️ MATCHED ACTIVE MALICIOUS BLOCKLIST
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Active Blocklist Table */}
        <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontWeight: 700, fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Radio size={16} color="var(--color-danger)" />
              <span>Active Threat Intel Blocklist ({feedItems.length})</span>
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Auto-matched on ingestion by RULE_KNOWN_MALICIOUS_IP
            </span>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '640px' }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>IP / Subnet</th>
                  <th>Threat Category</th>
                  <th>Source / Intel</th>
                  <th>Severity</th>
                  <th>Added At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {feedItems.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '3rem' }}>
                      No malicious IPs in blocklist. Add one using the form on the left.
                    </td>
                  </tr>
                ) : (
                  feedItems.map((item) => (
                    <tr key={item.id}>
                      <td className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
                        {item.ip_cidr}
                      </td>
                      <td style={{ fontSize: '0.78rem', fontWeight: 600 }}>
                        {item.threat_type}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {item.source}
                      </td>
                      <td>
                        <SeverityBadge severity={item.severity} />
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        {new Date(item.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <button
                          onClick={() => handleDeleteItem(item.id, item.ip_cidr)}
                          className="btn btn-danger btn-sm"
                          style={{ padding: '0.2rem 0.45rem' }}
                          title="Remove from blocklist"
                        >
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelView;
