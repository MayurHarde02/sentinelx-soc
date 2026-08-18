import React, { useState } from 'react';
import { ShieldAlert, X, CheckCircle, AlertTriangle } from 'lucide-react';
import api from '../api/client';

const CreateIncidentModal = ({ isOpen, onClose, alertToEscalate, onIncidentCreated }) => {
  const [title, setTitle] = useState(alertToEscalate ? `Incident: ${alertToEscalate.alert_type} from ${alertToEscalate.source_ip}` : '');
  const [description, setDescription] = useState(alertToEscalate ? `Triggered by Alert #${alertToEscalate.id}: ${alertToEscalate.description}` : '');
  const [severity, setSeverity] = useState(alertToEscalate?.severity || 'HIGH');
  const [assignedTo, setAssignedTo] = useState('analyst');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const payload = {
        title: title.trim(),
        description: description.trim(),
        severity,
        status: 'Investigating',
        assigned_to: assignedTo,
        alert_ids: alertToEscalate ? [alertToEscalate.id] : []
      };
      await api.post('/incidents', payload);
      if (onIncidentCreated) onIncidentCreated();
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create incident');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', padding: '0.4rem', borderRadius: '6px' }}>
              <ShieldAlert size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Create Security Incident</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Escalate alert into formal investigation workspace</p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 500 }}>Incident Title *</label>
            <input
              type="text"
              required
              className="soc-input"
              style={{ width: '100%' }}
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Brute Force Intrusion Attempt on SSH"
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 500 }}>Severity</label>
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

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 500 }}>Assignee</label>
              <select
                className="soc-select"
                style={{ width: '100%' }}
                value={assignedTo}
                onChange={(e) => setAssignedTo(e.target.value)}
              >
                <option value="analyst">analyst (Alex Rivera)</option>
                <option value="admin">admin (SOC Administrator)</option>
                <option value="unassigned">Unassigned</option>
              </select>
            </div>
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem', fontWeight: 500 }}>Description & Initial Findings</label>
            <textarea
              className="soc-input"
              style={{ width: '100%', height: '90px', resize: 'vertical' }}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Provide background, impact, and initial scope..."
            />
          </div>

          {error && (
            <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button type="button" onClick={onClose} className="btn">Cancel</button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateIncidentModal;
