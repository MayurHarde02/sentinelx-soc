import React, { useState, useEffect } from 'react';
import { Sliders, Shield, Check, RotateCcw, AlertTriangle } from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

const DetectionRulesView = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingRuleId, setEditingRuleId] = useState(null);
  const [editValues, setEditValues] = useState({});
  const [saveSuccess, setSaveSuccess] = useState(false);

  const fetchRules = async () => {
    try {
      const res = await api.get('/rules');
      setRules(res.data);
    } catch (e) {
      console.error('Failed to load rules', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggleEnable = async (rule) => {
    try {
      await api.patch(`/rules/${rule.id}`, { is_enabled: !rule.is_enabled });
      fetchRules();
    } catch (e) {
      console.error('Failed to toggle rule', e);
    }
  };

  const handleStartEdit = (rule) => {
    setEditingRuleId(rule.id);
    setEditValues({
      threshold: rule.threshold,
      window_minutes: rule.window_minutes,
      severity: rule.severity
    });
  };

  const handleSaveEdit = async (ruleId) => {
    try {
      await api.patch(`/rules/${ruleId}`, editValues);
      setEditingRuleId(null);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2500);
      fetchRules();
    } catch (e) {
      console.error('Failed to save rule update', e);
    }
  };

  const handleResetDefaults = async () => {
    if (window.confirm('Reset all detection rules and thresholds to defaults?')) {
      await api.post('/rules/reset');
      fetchRules();
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Sliders size={22} color="var(--color-primary)" />
            <span>Threat Detection Rules Engine</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Configure active SIEM detection heuristics, adjust sliding time windows, and customize sensitivity thresholds
          </p>
        </div>
        <button onClick={handleResetDefaults} className="btn btn-sm">
          <RotateCcw size={14} />
          <span>Reset Defaults</span>
        </button>
      </div>

      {saveSuccess && (
        <div style={{ padding: '0.75rem', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '6px', color: '#34d399', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Check size={16} />
          <span>Detection rule parameters updated successfully.</span>
        </div>
      )}

      {/* Rules List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {rules.map((rule) => {
          const isEditing = editingRuleId === rule.id;
          return (
            <div
              key={rule.id}
              className="soc-card"
              style={{
                borderLeft: `4px solid ${rule.is_enabled ? 'var(--color-primary)' : 'var(--text-dim)'}`,
                opacity: rule.is_enabled ? 1 : 0.7
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem' }}>
                    <span className="font-mono" style={{ fontWeight: 700, fontSize: '0.8rem', color: 'var(--color-primary)' }}>{rule.code}</span>
                    <SeverityBadge severity={rule.severity} />
                    <span style={{
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      padding: '0.1rem 0.4rem',
                      borderRadius: '4px',
                      background: rule.is_enabled ? 'rgba(16, 185, 129, 0.15)' : 'rgba(107, 114, 128, 0.15)',
                      color: rule.is_enabled ? '#34d399' : '#9ca3af'
                    }}>
                      {rule.is_enabled ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </div>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>{rule.name}</h3>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    onClick={() => handleToggleEnable(rule)}
                    className="btn btn-sm"
                    style={{ fontSize: '0.75rem' }}
                  >
                    {rule.is_enabled ? 'Disable' : 'Enable'}
                  </button>
                  {!isEditing ? (
                    <button
                      onClick={() => handleStartEdit(rule)}
                      className="btn btn-primary btn-sm"
                      style={{ fontSize: '0.75rem' }}
                    >
                      Configure
                    </button>
                  ) : (
                    <button
                      onClick={() => handleSaveEdit(rule.id)}
                      className="btn btn-primary btn-sm"
                      style={{ fontSize: '0.75rem', background: '#10b981', borderColor: '#10b981' }}
                    >
                      Save
                    </button>
                  )}
                </div>
              </div>

              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1rem', lineHeight: 1.4 }}>
                {rule.description}
              </div>

              {/* Threshold & Sliding Window Parameters */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', background: 'var(--bg-main)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)', display: 'block', marginBottom: '0.2rem' }}>Activation Threshold</span>
                  {isEditing ? (
                    <input
                      type="number"
                      min={1}
                      className="soc-input"
                      style={{ width: '100px', padding: '0.25rem 0.5rem' }}
                      value={editValues.threshold}
                      onChange={(e) => setEditValues({ ...editValues, threshold: Number(e.target.value) })}
                    />
                  ) : (
                    <strong className="font-mono" style={{ fontSize: '0.9rem', color: 'var(--text-main)' }}>
                      {rule.threshold} occurrences
                    </strong>
                  )}
                </div>

                <div>
                  <span style={{ color: 'var(--text-dim)', display: 'block', marginBottom: '0.2rem' }}>Sliding Window Time</span>
                  {isEditing ? (
                    <input
                      type="number"
                      min={1}
                      className="soc-input"
                      style={{ width: '100px', padding: '0.25rem 0.5rem' }}
                      value={editValues.window_minutes}
                      onChange={(e) => setEditValues({ ...editValues, window_minutes: Number(e.target.value) })}
                    />
                  ) : (
                    <strong className="font-mono" style={{ fontSize: '0.9rem', color: 'var(--text-main)' }}>
                      {rule.window_minutes} minute(s)
                    </strong>
                  )}
                </div>

                <div>
                  <span style={{ color: 'var(--text-dim)', display: 'block', marginBottom: '0.2rem' }}>Alert Severity</span>
                  {isEditing ? (
                    <select
                      className="soc-select"
                      style={{ padding: '0.25rem 0.5rem' }}
                      value={editValues.severity}
                      onChange={(e) => setEditValues({ ...editValues, severity: e.target.value })}
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  ) : (
                    <SeverityBadge severity={rule.severity} />
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default DetectionRulesView;
