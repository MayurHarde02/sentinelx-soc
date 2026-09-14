import React, { useState, useEffect } from 'react';
import {
  Bot,
  Play,
  CheckCircle,
  AlertTriangle,
  Clock,
  Shield,
  Zap,
  RefreshCw,
  X,
  UserCheck,
  Search,
  Activity,
  ChevronRight,
  Terminal,
  Lock
} from 'lucide-react';
import api from '../api/client';

const CATEGORY_COLORS = {
  CONTAINMENT: { bg: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: 'rgba(239, 68, 68, 0.3)' },
  FORENSICS: { bg: 'rgba(6, 182, 212, 0.15)', color: '#67e8f9', border: 'rgba(6, 182, 212, 0.3)' },
  REMEDIATION: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)' },
  NOTIFICATION: { bg: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: 'rgba(168, 85, 247, 0.3)' }
};

const PlaybooksView = () => {
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  // Execution Modal state
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [targetValue, setTargetValue] = useState('');
  const [incidentId, setIncidentId] = useState('');
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [executionError, setExecutionError] = useState('');

  // Log drawer modal
  const [viewingLogs, setViewingLogs] = useState(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [pbRes, exRes, metRes] = await Promise.all([
        api.get('/soar/playbooks'),
        api.get('/soar/executions?limit=50'),
        api.get('/soar/metrics')
      ]);
      setPlaybooks(pbRes.data);
      setExecutions(exRes.data);
      setMetrics(metRes.data);
    } catch (err) {
      console.error('Failed to load SOAR data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleTogglePlaybook = async (code) => {
    try {
      const res = await api.patch(`/soar/playbooks/${code}/toggle`);
      setPlaybooks(prev => prev.map(pb => pb.code === code ? res.data : pb));
    } catch (err) {
      console.error('Failed to toggle playbook', err);
    }
  };

  const handleOpenRunModal = (pb) => {
    setSelectedPlaybook(pb);
    setTargetValue('');
    setIncidentId('');
    setExecutionResult(null);
    setExecutionError('');
  };

  const handleExecutePlaybook = async (e) => {
    e.preventDefault();
    if (!selectedPlaybook || !targetValue.trim()) return;

    setExecuting(true);
    setExecutionError('');
    setExecutionResult(null);

    try {
      const payload = {
        target_value: targetValue.trim(),
        incident_id: incidentId ? parseInt(incidentId) : null
      };
      const res = await api.post(`/soar/playbooks/${selectedPlaybook.code}/execute`, payload);
      setExecutionResult(res.data);
      fetchData();
    } catch (err) {
      setExecutionError(err.response?.data?.detail || 'Execution failed');
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Bot size={24} color="var(--color-primary)" />
            <span>SOAR Security Automation &amp; Playbooks</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Orchestrate automated containment actions, compromised account lockouts, forensic dossier compilation, and MTTD/MTTR reduction
          </p>
        </div>
        <button onClick={fetchData} className="btn btn-sm">
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {/* SecOps KPI Metric Banner */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
        <div className="soc-card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '8px', background: 'rgba(6, 182, 212, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Clock size={20} color="var(--color-primary)" />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>MTTD (Mean Time to Detect)</div>
            <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--color-primary)' }}>
              {metrics?.mttd_display || '1.2s'}
            </div>
            <div style={{ fontSize: '0.68rem', color: '#10b981' }}>⚡ Sub-second event correlation</div>
          </div>
        </div>

        <div className="soc-card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Zap size={20} color="#10b981" />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>MTTR (Mean Time to Respond)</div>
            <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: '#10b981' }}>
              {metrics?.mttr_display || '4.8s'}
            </div>
            <div style={{ fontSize: '0.68rem', color: '#10b981' }}>📉 95% faster with SOAR playbooks</div>
          </div>
        </div>

        <div className="soc-card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '8px', background: 'rgba(168, 85, 247, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Bot size={20} color="#c084fc" />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>Total Playbook Executions</div>
            <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: '#c084fc' }}>
              {metrics?.total_executions || 0}
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
              {metrics?.successful_executions || 0} successful remediations
            </div>
          </div>
        </div>

        <div className="soc-card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={20} color="#f87171" />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>Zero-Touch Autonomous Blocks</div>
            <div className="font-mono" style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f87171' }}>
              {metrics?.auto_contained_threats || 0}
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Auto-contained on CRITICAL alerts</div>
          </div>
        </div>
      </div>

      {/* Playbook Catalog Grid */}
      <div>
        <div style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Activity size={16} color="var(--color-primary)" />
          <span>Active SOAR Playbook Catalog ({playbooks.length})</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
          {playbooks.map((pb) => {
            const catStyle = CATEGORY_COLORS[pb.category] || CATEGORY_COLORS.CONTAINMENT;
            const actions = pb.actions_json ? JSON.parse(pb.actions_json) : [];

            return (
              <div key={pb.id} className="soc-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', border: pb.is_active ? '1px solid var(--border-subtle)' : '1px dashed var(--border-subtle)', opacity: pb.is_active ? 1 : 0.65 }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.6rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: catStyle.bg,
                          color: catStyle.color,
                          border: `1px solid ${catStyle.border}`
                        }}
                      >
                        {pb.category}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                        TARGET: {pb.target_type}
                      </span>
                    </div>

                    {/* Toggle Switch */}
                    <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', gap: '0.4rem' }} title="Toggle auto-trigger state">
                      <span style={{ fontSize: '0.68rem', color: pb.is_active ? '#10b981' : 'var(--text-dim)' }}>
                        {pb.is_active ? 'ACTIVE' : 'OFF'}
                      </span>
                      <input
                        type="checkbox"
                        checked={pb.is_active}
                        onChange={() => handleTogglePlaybook(pb.code)}
                        style={{ cursor: 'pointer' }}
                      />
                    </label>
                  </div>

                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.4rem' }}>
                    {pb.name}
                  </h3>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.45, marginBottom: '0.75rem' }}>
                    {pb.description}
                  </div>

                  {/* Actions checklist */}
                  <div style={{ background: 'var(--bg-main)', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', marginBottom: '0.75rem' }}>
                    <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                      Orchestration Steps:
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      {actions.map((act, idx) => (
                        <li key={idx}>{act}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem', marginTop: '0.5rem' }}>
                  <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                    Triggered: <strong>{pb.execution_count || 0}</strong> times
                  </span>
                  <button
                    onClick={() => handleOpenRunModal(pb)}
                    className="btn btn-primary btn-sm"
                    style={{ padding: '0.3rem 0.75rem', fontSize: '0.75rem' }}
                  >
                    <Play size={13} />
                    <span>Run Playbook</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Execution Audit History */}
      <div className="soc-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={16} color="var(--color-primary)" />
            <span>Recent Playbook Execution Audit History ({executions.length})</span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
            Real-time SecOps orchestration telemetry
          </span>
        </div>

        <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Playbook</th>
                <th>Target</th>
                <th>Triggered By</th>
                <th>Duration</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {executions.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '2.5rem' }}>
                    No playbooks executed yet. Click "Run Playbook" above to launch an automated response.
                  </td>
                </tr>
              ) : (
                executions.map((ex) => (
                  <tr key={ex.id}>
                    <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                      #{ex.id}
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      {new Date(ex.created_at).toLocaleString()}
                    </td>
                    <td style={{ fontWeight: 600, fontSize: '0.82rem' }}>
                      {ex.playbook_name}
                    </td>
                    <td className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
                      {ex.target_value}
                    </td>
                    <td>
                      <span style={{ fontSize: '0.75rem', color: ex.triggered_by === 'SOAR_DAEMON' ? '#c084fc' : 'var(--text-muted)', fontWeight: ex.triggered_by === 'SOAR_DAEMON' ? 700 : 400 }}>
                        {ex.triggered_by}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: '#10b981' }}>
                      {ex.duration_ms}ms
                    </td>
                    <td>
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: ex.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          color: ex.status === 'SUCCESS' ? '#6ee7b7' : '#f87171',
                          border: `1px solid ${ex.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                        }}
                      >
                        {ex.status}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => setViewingLogs(ex)}
                        className="btn btn-sm"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                      >
                        View Logs
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Interactive Playbook Runner */}
      {selectedPlaybook && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.8)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div className="soc-card" style={{ width: '100%', maxWidth: '520px', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Play size={18} color="var(--color-primary)" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Run: {selectedPlaybook.name}</h3>
              </div>
              <button onClick={() => setSelectedPlaybook(null)} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            {executionError && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '0.6rem 0.8rem', borderRadius: '6px', fontSize: '0.8rem', marginBottom: '1rem' }}>
                {executionError}
              </div>
            )}

            {executionResult && (
              <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#6ee7b7', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8rem', marginBottom: '1rem' }}>
                <div style={{ fontWeight: 700, marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <CheckCircle size={16} />
                  <span>Playbook executed successfully in {executionResult.duration_ms}ms!</span>
                </div>
                {executionResult.execution_log_json && (
                  <div style={{ background: '#0f172a', padding: '0.5rem', borderRadius: '4px', fontSize: '0.72rem', color: '#94a3b8', maxHeight: '160px', overflowY: 'auto', fontFamily: 'monospace' }}>
                    {JSON.parse(executionResult.execution_log_json).map((lg, i) => (
                      <div key={i}>[{lg.step}] {lg.message}</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <form onSubmit={handleExecutePlaybook} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                  Target {selectedPlaybook.target_type} *
                </label>
                <input
                  type="text"
                  required
                  className="soc-input font-mono"
                  style={{ width: '100%' }}
                  placeholder={selectedPlaybook.target_type === 'IP' ? 'e.g. 198.51.100.44' : 'e.g. jdoe_admin'}
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                  Associate with Incident ID (Optional)
                </label>
                <input
                  type="number"
                  className="soc-input font-mono"
                  style={{ width: '100%' }}
                  placeholder="e.g. 1"
                  value={incidentId}
                  onChange={(e) => setIncidentId(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem' }}>
                <button type="button" onClick={() => setSelectedPlaybook(null)} className="btn">
                  Close
                </button>
                <button type="submit" className="btn btn-primary" disabled={executing}>
                  {executing ? 'Executing Actions...' : 'Launch Playbook'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: View Execution Step Logs */}
      {viewingLogs && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.8)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div className="soc-card" style={{ width: '100%', maxWidth: '580px', maxHeight: '80vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Execution Logs: {viewingLogs.playbook_name}</h3>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  Target: <strong style={{ color: 'var(--color-primary)' }}>{viewingLogs.target_value}</strong> • Duration: {viewingLogs.duration_ms}ms
                </div>
              </div>
              <button onClick={() => setViewingLogs(null)} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {viewingLogs.execution_log_json ? (
                JSON.parse(viewingLogs.execution_log_json).map((st, idx) => (
                  <div key={idx} style={{ background: 'var(--bg-main)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                      <span className="font-mono" style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-primary)' }}>
                        STEP {idx + 1}: {st.step}
                      </span>
                      <span style={{ fontSize: '0.68rem', color: '#10b981', fontWeight: 600 }}>{st.status}</span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-main)' }}>{st.message}</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', marginTop: '0.25rem', fontFamily: 'monospace' }}>{st.timestamp}</div>
                  </div>
                ))
              ) : (
                <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '1rem 0' }}>No detailed logs available.</div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button onClick={() => setViewingLogs(null)} className="btn btn-sm">
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PlaybooksView;
