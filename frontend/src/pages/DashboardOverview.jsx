import React, { useState, useEffect } from 'react';
import {
  Activity,
  AlertTriangle,
  Flame,
  ShieldCheck,
  ShieldAlert,
  Server,
  ArrowUpRight,
  TrendingUp,
  Clock,
  ExternalLink,
  Wifi,
  Bot,
  Zap
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import api from '../api/client';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import { useWebSocket } from '../context/WebSocketContext';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const MITRE_COLORS = {
  'Credential Access': '#ef4444',
  'Reconnaissance':    '#f59e0b',
  'Persistence':       '#8b5cf6',
  'Impact':            '#dc2626',
  'Command and Control': '#06b6d4',
  'Execution':         '#10b981',
  'Defense Evasion':   '#64748b',
};

const DashboardOverview = ({ onOpenAlert, onNavigateTab }) => {
  const [eventStats, setEventStats] = useState(null);
  const [alertStats, setAlertStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [incidentCount, setIncidentCount] = useState({ active: 0, resolved: 0 });
  const [soarMetrics, setSoarMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const { isConnected, newAlertCount, clearNewAlerts } = useWebSocket();

  const fetchOverviewData = async () => {
    try {
      const [evRes, alRes, alListRes, ipRes, incRes, soarRes] = await Promise.all([
        api.get('/events/stats'),
        api.get('/alerts/stats'),
        api.get('/alerts?limit=6'),
        api.get('/ip-intelligence?limit=5'),
        api.get('/incidents?limit=100'),
        api.get('/soar/metrics').catch(() => ({ data: null }))
      ]);

      setEventStats(evRes.data);
      setAlertStats(alRes.data);
      setRecentAlerts(alListRes.data);
      setTopIps(ipRes.data);
      if (soarRes && soarRes.data) setSoarMetrics(soarRes.data);


      const active = incRes.data.filter(i => ['Open', 'Investigating'].includes(i.status)).length;
      const resolved = incRes.data.filter(i => ['Resolved', 'Closed'].includes(i.status)).length;
      setIncidentCount({ active, resolved });
    } catch (err) {
      console.error('Failed to load SOC overview telemetry', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverviewData();
    const interval = setInterval(fetchOverviewData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Refresh when new alerts arrive via WebSocket
  useEffect(() => {
    if (newAlertCount > 0) {
      fetchOverviewData();
    }
  }, [newAlertCount]);

  // Activity chart
  const timeLabels = eventStats?.events_per_minute?.map(p => p.time.split(' ')[1] || p.time) || ['00:00', '00:05', '00:10', '00:15'];
  const eventDataPoints = eventStats?.events_per_minute?.map(p => p.count) || [0, 0, 0, 0];

  const activityChartData = {
    labels: timeLabels.length > 0 ? timeLabels : ['No recent activity'],
    datasets: [
      {
        label: 'Events / Min',
        data: eventDataPoints.length > 0 ? eventDataPoints : [0],
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.12)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointBackgroundColor: '#06b6d4',
        pointRadius: 3
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#111827',
        borderColor: '#2d3d54',
        borderWidth: 1,
        titleColor: '#f3f4f6',
        bodyColor: '#9ca3af',
      }
    },
    scales: {
      x: {
        grid: { color: '#1f2a3c' },
        ticks: { color: '#6b7280', font: { size: 10 } }
      },
      y: {
        grid: { color: '#1f2a3c' },
        ticks: { color: '#6b7280', font: { size: 10 }, beginAtZero: true }
      }
    }
  };

  // Severity Doughnut
  const sevDist = alertStats?.severity_distribution || {};
  const doughnutData = {
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    datasets: [
      {
        data: [
          sevDist['CRITICAL'] || 0,
          sevDist['HIGH'] || 0,
          sevDist['MEDIUM'] || 0,
          sevDist['LOW'] || 0
        ],
        backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6'],
        borderWidth: 0
      }
    ]
  };

  // MITRE ATT&CK tactic distribution bar chart
  const mitreDist = alertStats?.mitre_tactics_distribution || {};
  const mitreLabels = Object.keys(mitreDist);
  const mitreValues = Object.values(mitreDist);
  const mitreBarData = {
    labels: mitreLabels,
    datasets: [
      {
        label: 'Alerts',
        data: mitreValues,
        backgroundColor: mitreLabels.map(l => MITRE_COLORS[l] || '#475569'),
        borderRadius: 4,
        borderWidth: 0
      }
    ]
  };

  const barOptions = {
    ...chartOptions,
    plugins: {
      ...chartOptions.plugins,
      legend: { display: false }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#6b7280', font: { size: 9 }, maxRotation: 35 }
      },
      y: {
        grid: { color: '#1f2a3c' },
        ticks: { color: '#6b7280', font: { size: 10 }, beginAtZero: true, precision: 0 }
      }
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

      {/* Live WS Status + new alert banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: isConnected ? '#10b981' : '#6b7280',
            boxShadow: isConnected ? '0 0 6px #10b981' : 'none'
          }} />
          <span style={{ fontSize: '0.72rem', color: isConnected ? '#10b981' : 'var(--text-dim)', fontWeight: 600 }}>
            {isConnected ? 'WS: LIVE' : 'WS: OFFLINE'}
          </span>
        </div>
        {newAlertCount > 0 && (
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              borderRadius: '6px',
              padding: '0.3rem 0.75rem',
              fontSize: '0.78rem',
              color: '#f87171',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
            onClick={() => { clearNewAlerts(); fetchOverviewData(); }}
          >
            <span style={{ fontWeight: 700 }}>{newAlertCount} new alert{newAlertCount > 1 ? 's' : ''}</span>
            <span style={{ color: 'var(--text-dim)' }}>— click to refresh</span>
          </div>
        )}
      </div>

      {/* Metric Cards Banner */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        <StatCard
          title="Total Events"
          value={eventStats?.total_events || 0}
          subtitle="Processed by Engine"
          icon={Activity}
          color="var(--color-primary)"
        />
        <StatCard
          title="Total Alerts"
          value={alertStats?.total_alerts || 0}
          subtitle={`${alertStats?.open_alerts || 0} Unresolved Open`}
          icon={AlertTriangle}
          color="var(--color-warning)"
        />
        <StatCard
          title="Critical Threats"
          value={alertStats?.critical_alerts || 0}
          subtitle="Immediate Action Req."
          icon={Flame}
          color="var(--color-critical)"
        />
        <StatCard
          title="High Severity"
          value={alertStats?.high_alerts || 0}
          subtitle="Brute Force / Scans"
          icon={ShieldAlert}
          color="var(--color-danger)"
        />
        <StatCard
          title="Active Incidents"
          value={incidentCount.active}
          subtitle={`${incidentCount.resolved} Resolved`}
          icon={Server}
          color="#a855f7"
        />
      </div>

      {/* SOAR Automation & SLA Metrics Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.08), rgba(168, 85, 247, 0.08))',
        border: '1px solid rgba(6, 182, 212, 0.25)',
        borderRadius: '8px',
        padding: '0.85rem 1.25rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '6px', background: 'rgba(6, 182, 212, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Bot size={20} color="var(--color-primary)" />
          </div>
          <div>
            <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span>SOAR Automated Response Engine</span>
              <span style={{ fontSize: '0.65rem', background: 'rgba(16, 185, 129, 0.2)', color: '#10b981', padding: '0.1rem 0.4rem', borderRadius: '4px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>ONLINE</span>
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Active Playbooks: <strong style={{ color: 'var(--text-muted)' }}>{soarMetrics?.active_playbooks ?? 4}</strong> • Automated Actions: <strong style={{ color: 'var(--color-primary)' }}>{soarMetrics?.total_executions ?? 0}</strong>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>MTTD (Detection)</div>
            <div className="font-mono" style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--color-primary)' }}>
              {soarMetrics?.mttd_display || '1.2s'}
            </div>
          </div>

          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>MTTR (Resolution)</div>
            <div className="font-mono" style={{ fontSize: '1.15rem', fontWeight: 700, color: '#10b981' }}>
              {soarMetrics?.mttr_display || '4.8s'}
            </div>
          </div>

          <button
            onClick={() => onNavigateTab('playbooks')}
            className="btn btn-sm btn-primary"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <span>Launch Playbook</span>
            <ArrowUpRight size={14} />
          </button>
        </div>
      </div>


      {/* Main Visuals Row: Activity Graph + Severity Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem' }}>
        {/* Event Ingestion Velocity */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="soc-card-header">
            <div className="soc-card-title">
              <TrendingUp size={16} color="var(--color-primary)" />
              <span>Event Activity Velocity</span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Events per minute</span>
          </div>
          <div style={{ height: '220px', width: '100%', marginTop: '0.5rem' }}>
            <Line data={activityChartData} options={chartOptions} />
          </div>
        </div>

        {/* Severity Breakdown Doughnut */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="soc-card-header">
            <div className="soc-card-title">
              <Flame size={16} color="var(--color-danger)" />
              <span>Alert Severity Distribution</span>
            </div>
          </div>
          <div style={{ height: '170px', position: 'relative', display: 'flex', justifyContent: 'center' }}>
            {(alertStats?.total_alerts || 0) === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                No active alerts
              </div>
            ) : (
              <Doughnut
                data={doughnutData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      position: 'bottom',
                      labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 10 }
                    }
                  },
                  cutout: '70%'
                }}
              />
            )}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Tactic Distribution */}
      {mitreLabels.length > 0 && (
        <div className="soc-card">
          <div className="soc-card-header">
            <div className="soc-card-title">
              <ShieldCheck size={16} color="#8b5cf6" />
              <span>MITRE ATT&amp;CK Tactic Distribution</span>
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
              enterprise-attack v14
            </span>
          </div>
          <div style={{ height: '160px', width: '100%', marginTop: '0.5rem' }}>
            <Bar data={mitreBarData} options={barOptions} />
          </div>
        </div>
      )}

      {/* Second Row: Top Suspicious IPs & Quick Alerts Triage Table */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.25rem' }}>
        {/* Top Suspicious IPs Card */}
        <div className="soc-card">
          <div className="soc-card-header">
            <div className="soc-card-title">
              <ShieldAlert size={16} color="#f87171" />
              <span>High Risk Threat Actors</span>
            </div>
            <button
              onClick={() => onNavigateTab('ip_intel')}
              className="btn btn-sm"
              style={{ padding: '0.2rem 0.4rem', fontSize: '0.7rem' }}
            >
              View All
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {topIps.length === 0 ? (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem', padding: '1rem 0' }}>
                No IP telemetry yet. Use "Seed Attacks" to populate data.
              </div>
            ) : (
              topIps.map((actor) => (
                <div
                  key={actor.ip}
                  style={{
                    background: 'var(--bg-surface-raised)',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <div className="font-mono" style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--color-primary)' }}>
                      {actor.ip}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                      {actor.total_events} events • {actor.total_alerts} alerts
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span
                      className="font-mono"
                      style={{
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        background: actor.threat_score >= 60 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                        color: actor.threat_score >= 60 ? '#f87171' : '#fbbf24',
                        border: `1px solid ${actor.threat_score >= 60 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`
                      }}
                    >
                      SCORE: {actor.threat_score}/100
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recent Alerts Feed Table */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="soc-card-header">
            <div className="soc-card-title">
              <AlertTriangle size={16} color="var(--color-warning)" />
              <span>Real-Time Alert Feed</span>
            </div>
            <button
              onClick={() => onNavigateTab('alerts')}
              className="btn btn-sm"
              style={{ padding: '0.2rem 0.4rem', fontSize: '0.7rem' }}
            >
              Full Queue
            </button>
          </div>

          <div style={{ overflowX: 'auto', flex: 1 }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Alert Type</th>
                  <th>Source IP</th>
                  <th>Severity</th>
                  <th>MITRE</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '2rem' }}>
                      No alerts triggered yet. Launch an attack in Attack Simulator.
                    </td>
                  </tr>
                ) : (
                  recentAlerts.map((al) => (
                    <tr key={al.id} style={{ cursor: 'pointer' }} onClick={() => onOpenAlert(al)}>
                      <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(al.timestamp).toLocaleTimeString()}
                      </td>
                      <td style={{ fontWeight: 600 }}>{al.alert_type}</td>
                      <td className="font-mono" style={{ color: 'var(--color-primary)' }}>{al.source_ip}</td>
                      <td><SeverityBadge severity={al.severity} /></td>
                      <td>
                        {al.mitre_technique_id ? (
                          <span style={{
                            fontFamily: 'monospace',
                            fontSize: '0.7rem',
                            background: 'rgba(6,182,212,0.1)',
                            color: '#06b6d4',
                            border: '1px solid rgba(6,182,212,0.25)',
                            borderRadius: '3px',
                            padding: '0.1rem 0.35rem'
                          }}>
                            {al.mitre_technique_id}
                          </span>
                        ) : <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>—</span>}
                      </td>
                      <td><StatusBadge status={al.status} /></td>
                      <td>
                        <button
                          onClick={(e) => { e.stopPropagation(); onOpenAlert(al); }}
                          className="btn btn-sm"
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                        >
                          Details
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

export default DashboardOverview;
