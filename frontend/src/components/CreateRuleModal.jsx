import React, { useState } from 'react';
import { X, ShieldPlus, AlertCircle, CheckCircle } from 'lucide-react';
import api from '../api/client';

const CreateRuleModal = ({ isOpen, onClose, onRuleCreated }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    event_type_filter: 'LOGIN_FAILED',
    status_filter: 'FAILURE',
    threshold: 5,
    window_seconds: 300,
    severity: 'HIGH',
    alert_type: 'CUSTOM_BRUTE_FORCE',
    mitre_tactic: 'Credential Access',
    mitre_technique_id: 'T1110',
    mitre_technique_name: 'Brute Force'
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  if (!isOpen) return null;

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: name === 'threshold' || name === 'window_seconds' ? parseInt(value) || 0 : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.post('/rules', {
        ...formData,
        is_custom: true,
        is_active: true
      });
      setSuccess(true);
      setTimeout(() => {
        setSuccess(false);
        if (onRuleCreated) onRuleCreated();
        onClose();
      }, 1000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create detection rule');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '1rem'
    }}>
      <div
        className="soc-card"
        style={{
          width: '100%',
          maxWidth: '560px',
          maxHeight: '90vh',
          overflowY: 'auto',
          boxShadow: '0 10px 40px rgba(0,0,0,0.8)',
          border: '1px solid var(--border-subtle)'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldPlus size={20} color="var(--color-primary)" />
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Add Custom Detection Rule</h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '0.6rem 0.8rem', borderRadius: '6px', fontSize: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#6ee7b7', padding: '0.6rem 0.8rem', borderRadius: '6px', fontSize: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <CheckCircle size={16} />
            <span>Custom detection rule deployed successfully!</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
          {/* Rule Name */}
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
              Rule Name *
            </label>
            <input
              type="text"
              name="name"
              required
              className="soc-input"
              style={{ width: '100%' }}
              placeholder="e.g., Aggressive Auth Failure Spike"
              value={formData.name}
              onChange={handleChange}
            />
          </div>

          {/* Description */}
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
              Description
            </label>
            <input
              type="text"
              name="description"
              className="soc-input"
              style={{ width: '100%' }}
              placeholder="e.g., Flags 10+ failed logins within 1 minute from the same IP"
              value={formData.description}
              onChange={handleChange}
            />
          </div>

          {/* Grid: Event Filter & Status */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                Event Type Filter *
              </label>
              <input
                type="text"
                name="event_type_filter"
                required
                className="soc-input font-mono"
                style={{ width: '100%' }}
                placeholder="LOGIN_FAILED or *"
                value={formData.event_type_filter}
                onChange={handleChange}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                Status Filter
              </label>
              <input
                type="text"
                name="status_filter"
                className="soc-input font-mono"
                style={{ width: '100%' }}
                placeholder="FAILURE, SUCCESS, or *"
                value={formData.status_filter}
                onChange={handleChange}
              />
            </div>
          </div>

          {/* Grid: Threshold & Window */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                Threshold (Event Count) *
              </label>
              <input
                type="number"
                name="threshold"
                min="1"
                required
                className="soc-input font-mono"
                style={{ width: '100%' }}
                value={formData.threshold}
                onChange={handleChange}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                Sliding Window (Seconds) *
              </label>
              <input
                type="number"
                name="window_seconds"
                min="10"
                required
                className="soc-input font-mono"
                style={{ width: '100%' }}
                value={formData.window_seconds}
                onChange={handleChange}
              />
            </div>
          </div>

          {/* Grid: Alert Type & Severity */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                Alert Type Tag *
              </label>
              <input
                type="text"
                name="alert_type"
                required
                className="soc-input font-mono"
                style={{ width: '100%' }}
                placeholder="e.g. CUSTOM_ATTACK"
                value={formData.alert_type}
                onChange={handleChange}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                Severity *
              </label>
              <select
                name="severity"
                className="soc-select"
                style={{ width: '100%' }}
                value={formData.severity}
                onChange={handleChange}
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                MITRE Tactic
              </label>
              <input
                type="text"
                name="mitre_tactic"
                className="soc-input"
                style={{ width: '100%' }}
                placeholder="e.g. Credential Access"
                value={formData.mitre_tactic}
                onChange={handleChange}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.3rem' }}>
                MITRE Technique ID
              </label>
              <input
                type="text"
                name="mitre_technique_id"
                className="soc-input font-mono"
                style={{ width: '100%' }}
                placeholder="e.g. T1110"
                value={formData.mitre_technique_id}
                onChange={handleChange}
              />
            </div>
          </div>

          {/* Buttons */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem' }}>
            <button type="button" onClick={onClose} className="btn" disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Deploying...' : 'Deploy Detection Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateRuleModal;
