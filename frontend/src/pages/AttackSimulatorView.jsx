import React, { useState } from 'react';
import { Zap, Play, Terminal, Shield, AlertTriangle, CheckCircle, Radio, Server, Flame } from 'lucide-react';
import api from '../api/client';

const SCENARIOS = [
  {
    id: 'brute_force',
    name: 'SSH / Web Brute Force Attack',
    category: 'Credential Access',
    severity: 'HIGH / CRITICAL',
    description: 'Fires 6+ rapid failed authentication attempts targeting administrative accounts from a single IP.',
    rule: 'RULE_BRUTE_FORCE',
    defaultIp: '192.168.1.105',
    color: '#ef4444'
  },
  {
    id: 'port_scan',
    name: 'Nmap Multi-Port Reconnaissance Scan',
    category: 'Reconnaissance',
    severity: 'HIGH',
    description: 'Probes 12+ distinct ports (SSH, HTTP, MySQL, RDP, etc.) in rapid succession to identify listening services.',
    rule: 'RULE_PORT_SCAN',
    defaultIp: '198.51.100.42',
    color: '#f59e0b'
  },
  {
    id: 'suspicious_login',
    name: 'Credential Stuffing & Suspicious Login',
    category: 'Initial Access',
    severity: 'HIGH',
    description: 'Executes multiple failed password guesses followed immediately by a successful login event.',
    rule: 'RULE_SUSPICIOUS_LOGIN',
    defaultIp: '185.220.101.5',
    color: '#06b6d4'
  },
  {
    id: 'flood',
    name: 'High-Frequency Event Flood (DDoS)',
    category: 'Impact / Availability',
    severity: 'MEDIUM / HIGH',
    description: 'Bursts 105+ requests in under a minute from a single source to trigger high-frequency anomaly detection.',
    rule: 'RULE_EVENT_FLOOD',
    defaultIp: '10.0.0.99',
    color: '#ec4899'
  },
  {
    id: 'benign',
    name: 'Normal Workstation & User Traffic',
    category: 'Baseline Noise',
    severity: 'BENIGN (0 Alerts)',
    description: 'Simulates legitimate internal network actions, file access, and authorized login sessions.',
    rule: 'N/A',
    defaultIp: '192.168.1.50',
    color: '#10b981'
  }
];

const AttackSimulatorView = ({ onSimulationTriggered }) => {
  const [selectedScenario, setSelectedScenario] = useState(SCENARIOS[0].id);
  const [customIp, setCustomIp] = useState(SCENARIOS[0].defaultIp);
  const [intensity, setIntensity] = useState(1);
  const [loading, setLoading] = useState(false);
  const [logsOutput, setLogsOutput] = useState([]);

  const handleSelectScenario = (sc) => {
    setSelectedScenario(sc.id);
    setCustomIp(sc.defaultIp);
  };

  const handleLaunchAttack = async (scenarioId) => {
    const sc = SCENARIOS.find(s => s.id === (scenarioId || selectedScenario));
    const ip = customIp || sc.defaultIp;

    setLoading(true);
    const ts = new Date().toLocaleTimeString();

    try {
      const res = await api.post('/simulation/trigger', {
        scenario: sc.id,
        target_ip: ip,
        intensity: Number(intensity)
      });

      const entry = {
        time: ts,
        scenario: sc.name,
        ip: ip,
        events: res.data.events_generated,
        alerts: res.data.alerts_triggered,
        msg: res.data.message,
        success: true
      };

      setLogsOutput(prev => [entry, ...prev]);
      if (onSimulationTriggered) onSimulationTriggered();
    } catch (err) {
      const entry = {
        time: ts,
        scenario: sc.name,
        ip: ip,
        events: 0,
        alerts: 0,
        msg: err.response?.data?.detail || 'Execution failed',
        success: false
      };
      setLogsOutput(prev => [entry, ...prev]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Zap size={22} color="var(--color-primary)" />
          <span>Attack Scenario Simulator & SOC Playground</span>
        </h2>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Execute simulated attack scenarios to test SentinelX detection rules, alert generation, and incident triage
        </p>
      </div>

      {/* Scenario Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
        {SCENARIOS.map((sc) => {
          const isSelected = selectedScenario === sc.id;
          return (
            <div
              key={sc.id}
              className="soc-card"
              onClick={() => handleSelectScenario(sc)}
              style={{
                cursor: 'pointer',
                borderColor: isSelected ? 'var(--color-primary)' : 'var(--border-subtle)',
                background: isSelected ? 'var(--bg-surface-raised)' : 'var(--bg-surface)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'all 0.15s ease'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.72rem', fontWeight: 700, color: sc.color, textTransform: 'uppercase' }}>
                    {sc.category}
                  </span>
                  <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                    {sc.severity}
                  </span>
                </div>

                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.4rem' }}>
                  {sc.name}
                </div>

                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.4, marginBottom: '0.75rem' }}>
                  {sc.description}
                </div>
              </div>

              <div style={{ paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  Rule: {sc.rule}
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleLaunchAttack(sc.id);
                  }}
                  disabled={loading}
                  className="btn btn-primary btn-sm"
                  style={{ padding: '0.25rem 0.6rem', fontSize: '0.72rem' }}
                >
                  <Play size={12} />
                  <span>Launch</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulator Execution Console */}
      <div className="soc-card">
        <div className="soc-card-header">
          <div className="soc-card-title">
            <Terminal size={16} color="var(--color-primary)" />
            <span>Simulation Execution Console</span>
          </div>
          <button
            onClick={() => setLogsOutput([])}
            className="btn btn-sm"
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            Clear Log
          </button>
        </div>

        <div style={{ background: 'var(--bg-main)', padding: '1rem', borderRadius: '6px', minHeight: '160px', maxHeight: '250px', overflowY: 'auto', border: '1px solid var(--border-subtle)' }}>
          {logsOutput.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem', textAlign: 'center', padding: '2rem 0' }}>
              Simulator console ready. Select a scenario above and click "Launch".
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {logsOutput.map((log, idx) => (
                <div
                  key={idx}
                  className="font-mono"
                  style={{
                    fontSize: '0.78rem',
                    padding: '0.5rem',
                    borderRadius: '4px',
                    background: log.success ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                    borderLeft: `3px solid ${log.success ? 'var(--color-success)' : 'var(--color-danger)'}`
                  }}
                >
                  <span style={{ color: 'var(--text-dim)' }}>[{log.time}] </span>
                  <span style={{ fontWeight: 600, color: 'var(--color-primary)' }}>{log.scenario}</span>
                  <span style={{ color: 'var(--text-muted)' }}> (IP: {log.ip}) </span>
                  <span style={{ color: log.alerts > 0 ? '#f87171' : '#34d399', fontWeight: 600 }}>
                    → {log.events} Events Generated | {log.alerts} Alerts Triggered
                  </span>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                    {log.msg}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AttackSimulatorView;
