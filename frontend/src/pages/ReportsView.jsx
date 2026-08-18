import React, { useState, useEffect } from 'react';
import { FileBarChart, Download, ShieldCheck, Printer, RefreshCw, CheckCircle, Flame } from 'lucide-react';
import api from '../api/client';

const ReportsView = () => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchReport = async () => {
    try {
      const res = await api.get('/reports/summary');
      setReport(res.data);
    } catch (e) {
      console.error('Failed to load report', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handleExportCsv = (type) => {
    window.open(`/api/reports/export/csv?data_type=${type}`, '_blank');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FileBarChart size={22} color="var(--color-primary)" />
            <span>Security Operations Summary & Compliance Report</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Comprehensive SOC incident metrics, threat vectors, threat actor attribution, and raw CSV data exports
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={handlePrint} className="btn btn-sm">
            <Printer size={14} />
            <span>Print Report</span>
          </button>
          <button onClick={fetchReport} className="btn btn-sm">
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* CSV Export Quick Action Toolbar */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>Raw Telemetry CSV Data Exports</div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Download complete structured tables for external SIEM integration or compliance archiving</div>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem' }}>
          <button onClick={() => handleExportCsv('alerts')} className="btn btn-primary btn-sm">
            <Download size={14} />
            <span>Export Alerts (.csv)</span>
          </button>
          <button onClick={() => handleExportCsv('events')} className="btn btn-sm">
            <Download size={14} />
            <span>Export Events (.csv)</span>
          </button>
          <button onClick={() => handleExportCsv('incidents')} className="btn btn-sm">
            <Download size={14} />
            <span>Export Incidents (.csv)</span>
          </button>
        </div>
      </div>

      {/* Executive Report Card */}
      {report && (
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', background: '#0e1524' }}>
          {/* Banner */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem' }}>
            <div>
              <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--color-primary)', fontWeight: 700 }}>SENTINELX SOC AUDIT SUMMARY</span>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginTop: '0.2rem' }}>Executive Threat & Telemetry Review</h3>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                Generated: {new Date(report.generated_at).toUTCString()} • Window: {report.time_window}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <span
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  padding: '0.25rem 0.6rem',
                  borderRadius: '4px',
                  background: report.system_health === 'HEALTHY' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                  color: report.system_health === 'HEALTHY' ? '#34d399' : '#f87171',
                  border: '1px solid currentColor'
                }}
              >
                POSTURE: {report.system_health}
              </span>
            </div>
          </div>

          {/* Key Totals Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '1rem' }}>
            <div style={{ background: 'var(--bg-main)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>TOTAL EVENTS</div>
              <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.2rem' }}>{report.total_events}</div>
            </div>
            <div style={{ background: 'var(--bg-main)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>ALERTS TRIGGERED</div>
              <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fbbf24', marginTop: '0.2rem' }}>{report.total_alerts}</div>
            </div>
            <div style={{ background: 'var(--bg-main)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>ACTIVE INCIDENTS</div>
              <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f87171', marginTop: '0.2rem' }}>{report.active_incidents}</div>
            </div>
            <div style={{ background: 'var(--bg-main)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>RESOLVED INCIDENTS</div>
              <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: '#34d399', marginTop: '0.2rem' }}>{report.resolved_incidents}</div>
            </div>
          </div>

          {/* Breakdown: Top Vectors and Top IPs */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            {/* Top Attack Vectors */}
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.6rem', textTransform: 'uppercase' }}>
                Primary Attack Vectors
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {report.top_attack_vectors?.length === 0 ? (
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>No threat vectors recorded.</div>
                ) : (
                  report.top_attack_vectors.map(vec => (
                    <div key={vec.attack_type} style={{ background: 'var(--bg-main)', padding: '0.6rem 0.8rem', borderRadius: '4px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{vec.attack_type}</span>
                      <div style={{ textAlign: 'right' }}>
                        <span className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>{vec.count} alerts</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginLeft: '0.4rem' }}>({vec.percentage}%)</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Top Malicious Source IPs */}
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.6rem', textTransform: 'uppercase' }}>
                Top Suspicious Sources
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {report.top_suspicious_ips?.length === 0 ? (
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>No suspicious sources identified.</div>
                ) : (
                  report.top_suspicious_ips.map(ipStat => (
                    <div key={ipStat.ip} style={{ background: 'var(--bg-main)', padding: '0.6rem 0.8rem', borderRadius: '4px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span className="font-mono" style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--color-primary)' }}>{ipStat.ip}</span>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{ipStat.event_count} events • {ipStat.alert_count} alerts</div>
                      </div>
                      <span className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 700, color: ipStat.threat_score >= 60 ? '#f87171' : '#fbbf24' }}>
                        SCORE: {ipStat.threat_score}/100
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportsView;
