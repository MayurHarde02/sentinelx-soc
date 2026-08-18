import React, { useState, useEffect } from 'react';
import { ShieldAlert, Plus, MessageSquare, CheckCircle, Clock, User, AlertTriangle, Send } from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import { useAuth } from '../context/AuthContext';

const IncidentsView = ({ onOpenCreateIncident }) => {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [noteText, setNoteText] = useState('');
  const [resolutionText, setResolutionText] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchIncidents = async () => {
    try {
      const res = await api.get('/incidents?limit=100');
      setIncidents(res.data);
      if (selectedIncident) {
        // Update selected incident if already open
        const updated = res.data.find(i => i.id === selectedIncident.id);
        if (updated) setSelectedIncident(updated);
      } else if (res.data.length > 0) {
        setSelectedIncident(res.data[0]);
      }
    } catch (e) {
      console.error('Failed to load incidents', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleSelectIncident = async (inc) => {
    try {
      const res = await api.get(`/incidents/${inc.id}`);
      setSelectedIncident(res.data);
    } catch (e) {
      setSelectedIncident(inc);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!noteText.trim() || !selectedIncident) return;
    try {
      await api.post(`/incidents/${selectedIncident.id}/notes?author=${encodeURIComponent(user?.username || 'analyst')}`, {
        note: noteText.trim()
      });
      setNoteText('');
      // Refresh selected incident
      const res = await api.get(`/incidents/${selectedIncident.id}`);
      setSelectedIncident(res.data);
      fetchIncidents();
    } catch (err) {
      console.error('Failed to add note', err);
    }
  };

  const handleUpdateIncidentStatus = async (newStatus) => {
    if (!selectedIncident) return;
    try {
      const payload = { status: newStatus };
      if (resolutionText.trim()) {
        payload.resolution_notes = resolutionText.trim();
      }
      await api.patch(`/incidents/${selectedIncident.id}`, payload);
      const res = await api.get(`/incidents/${selectedIncident.id}`);
      setSelectedIncident(res.data);
      fetchIncidents();
    } catch (err) {
      console.error('Failed to update incident', err);
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldAlert size={22} color="var(--color-danger)" />
            <span>Incident Response & Investigation</span>
          </h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Track security incidents, correlate triggered alerts, log analyst findings, and resolve threats
          </p>
        </div>
        <button onClick={onOpenCreateIncident} className="btn btn-primary btn-sm">
          <Plus size={15} />
          <span>New Incident</span>
        </button>
      </div>

      {/* Two-Pane Workspace Layout: Left Incident List, Right Detailed Workspace */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.25rem', alignItems: 'start' }}>
        {/* Left Column: Incidents List */}
        <div className="soc-card" style={{ padding: '0.75rem', maxHeight: '720px', overflowY: 'auto' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', padding: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
            Active Incident Queue ({incidents.length})
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.75rem' }}>
            {incidents.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '2rem 1rem', fontSize: '0.8rem' }}>
                No incidents created yet. Escalate an alert or click "New Incident".
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id;
                return (
                  <div
                    key={inc.id}
                    onClick={() => handleSelectIncident(inc)}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '6px',
                      background: isSelected ? 'var(--bg-surface-active)' : 'var(--bg-surface-raised)',
                      border: `1px solid ${isSelected ? 'var(--color-primary)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                      <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>INC-{inc.id}</span>
                      <div style={{ display: 'flex', gap: '0.3rem' }}>
                        <SeverityBadge severity={inc.severity} />
                        <StatusBadge status={inc.status} />
                      </div>
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                      {inc.title}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.4rem', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Assignee: {inc.assigned_to || 'Unassigned'}</span>
                      <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Incident Workspace */}
        {selectedIncident ? (
          <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Header / Title Bar */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--color-primary)', fontWeight: 700 }}>INCIDENT #{selectedIncident.id}</span>
                  <SeverityBadge severity={selectedIncident.severity} />
                  <StatusBadge status={selectedIncident.status} />
                </div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>{selectedIncident.title}</h3>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                  Created {new Date(selectedIncident.created_at).toLocaleString()} • Assigned to <strong>{selectedIncident.assigned_to || 'Unassigned'}</strong>
                </div>
              </div>

              {/* Status transition dropdown */}
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Status:</span>
                <select
                  className="soc-select"
                  value={selectedIncident.status}
                  onChange={(e) => handleUpdateIncidentStatus(e.target.value)}
                >
                  <option value="Open">Open</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Mitigated">Mitigated</option>
                  <option value="Resolved">Resolved</option>
                  <option value="Closed">Closed</option>
                </select>
              </div>
            </div>

            {/* Description & Scope */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Incident Scope & Description
              </div>
              <div style={{ background: 'var(--bg-main)', padding: '0.85rem', borderRadius: '6px', fontSize: '0.85rem', border: '1px solid var(--border-subtle)', lineHeight: 1.5 }}>
                {selectedIncident.description || 'No description provided.'}
              </div>
            </div>

            {/* Linked Alerts Evidence */}
            {selectedIncident.alerts && selectedIncident.alerts.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Correlated Alerts Evidence ({selectedIncident.alerts.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {selectedIncident.alerts.map(al => (
                    <div
                      key={al.id}
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
                        <div style={{ fontWeight: 600, fontSize: '0.82rem' }}>{al.alert_type} • <span className="font-mono" style={{ color: 'var(--color-primary)' }}>{al.source_ip}</span></div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>{al.description}</div>
                      </div>
                      <SeverityBadge severity={al.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Analyst Investigation Journal / Notes */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                Analyst Investigation Notes ({selectedIncident.notes?.length || 0})
              </div>

              <div style={{ background: 'var(--bg-main)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', maxHeight: '200px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.75rem' }}>
                {(!selectedIncident.notes || selectedIncident.notes.length === 0) ? (
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem', textAlign: 'center', padding: '1rem 0' }}>
                    No investigation notes recorded yet.
                  </div>
                ) : (
                  selectedIncident.notes.map(note => (
                    <div key={note.id} style={{ background: 'var(--bg-surface)', padding: '0.6rem', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>
                        <span style={{ fontWeight: 600, color: 'var(--color-primary)' }}>{note.author}</span>
                        <span>{new Date(note.created_at).toLocaleTimeString()}</span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-main)' }}>{note.note}</div>
                    </div>
                  ))
                )}
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  className="soc-input"
                  style={{ flex: 1 }}
                  placeholder="Add analyst observation / IP block action / containment note..."
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                />
                <button type="submit" className="btn btn-primary btn-sm">
                  <Send size={14} />
                  <span>Log Note</span>
                </button>
              </form>
            </div>
          </div>
        ) : (
          <div className="soc-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: 'var(--text-dim)' }}>
            Select an incident to view investigation workspace
          </div>
        )}
      </div>
    </div>
  );
};

export default IncidentsView;
