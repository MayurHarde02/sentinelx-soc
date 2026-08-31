import React from 'react';
import { ShieldAlert, AlertTriangle, MessageSquare, CheckCircle, Clock, Zap, Flag } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import MitreBadge from './MitreBadge';

const InvestigationTimeline = ({ incident }) => {
  if (!incident) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
        No incident selected.
      </div>
    );
  }

  // Aggregate all events into a unified forensic timeline
  const timelineNodes = [];

  // 1. Incident Creation Node
  if (incident.created_at) {
    timelineNodes.push({
      id: 'created',
      type: 'INCIDENT_CREATED',
      title: 'Incident Initialized',
      timestamp: new Date(incident.created_at),
      description: `Incident INC-${incident.id} opened by ${incident.assigned_to || 'System'}. Scope: ${incident.title}`,
      icon: Flag,
      color: '#06b6d4'
    });
  }

  // 2. Correlated Alert Triggers
  if (incident.alerts && Array.isArray(incident.alerts)) {
    incident.alerts.forEach((alert) => {
      timelineNodes.push({
        id: `alert-${alert.id}`,
        type: 'ALERT_TRIGGERED',
        title: `Threat Detection: ${alert.alert_type}`,
        timestamp: new Date(alert.timestamp),
        description: alert.description,
        source_ip: alert.source_ip,
        severity: alert.severity,
        mitre_tactic: alert.mitre_tactic,
        mitre_technique_id: alert.mitre_technique_id,
        mitre_technique_name: alert.mitre_technique_name,
        icon: AlertTriangle,
        color: alert.severity === 'CRITICAL' ? '#dc2626' : alert.severity === 'HIGH' ? '#ef4444' : '#f59e0b'
      });
    });
  }

  // 3. Analyst Investigation Notes
  if (incident.notes && Array.isArray(incident.notes)) {
    incident.notes.forEach((note) => {
      timelineNodes.push({
        id: `note-${note.id}`,
        type: 'ANALYST_NOTE',
        title: `Analyst Log (${note.author})`,
        timestamp: new Date(note.created_at),
        description: note.note,
        author: note.author,
        icon: MessageSquare,
        color: '#3b82f6'
      });
    });
  }

  // 4. Incident Resolution Node
  if (['Resolved', 'Closed', 'Mitigated'].includes(incident.status)) {
    timelineNodes.push({
      id: 'resolved',
      type: 'INCIDENT_RESOLVED',
      title: `Incident ${incident.status}`,
      timestamp: incident.updated_at ? new Date(incident.updated_at) : new Date(),
      description: incident.resolution_notes || `Threat contained and incident transitioned to ${incident.status}.`,
      icon: CheckCircle,
      color: '#10b981'
    });
  }

  // Sort chronological order (oldest to newest)
  timelineNodes.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  if (timelineNodes.length === 0) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
        No forensic timeline entries available.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0', padding: '0.5rem 0' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <Clock size={14} color="var(--color-primary)" />
        <span>Forensic Investigation Timeline ({timelineNodes.length} Events)</span>
      </div>

      <div style={{ position: 'relative', paddingLeft: '1.75rem' }}>
        {/* Vertical Line Connector */}
        <div
          style={{
            position: 'absolute',
            left: '11px',
            top: '8px',
            bottom: '12px',
            width: '2px',
            background: 'linear-gradient(to bottom, #06b6d4, var(--border-subtle), #10b981)'
          }}
        />

        {timelineNodes.map((node, idx) => {
          const Icon = node.icon;

          return (
            <div
              key={node.id}
              style={{
                position: 'relative',
                marginBottom: idx === timelineNodes.length - 1 ? '0' : '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem'
              }}
            >
              {/* Timeline Bullet Node */}
              <div
                style={{
                  position: 'absolute',
                  left: '-1.75rem',
                  top: '2px',
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: 'var(--bg-main)',
                  border: `2px solid ${node.color}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: `0 0 8px ${node.color}55`,
                  zIndex: 2
                }}
              >
                <Icon size={12} color={node.color} />
              </div>

              {/* Node Content Card */}
              <div
                style={{
                  background: 'var(--bg-surface-raised)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '0.75rem 0.9rem',
                  boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.3rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.82rem', color: node.color }}>
                      {node.title}
                    </span>
                    {node.severity && <SeverityBadge severity={node.severity} />}
                    {node.mitre_technique_id && (
                      <MitreBadge
                        tactic={node.mitre_tactic}
                        techniqueId={node.mitre_technique_id}
                        techniqueName={node.mitre_technique_name}
                      />
                    )}
                  </div>
                  <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                    {node.timestamp.toLocaleTimeString()} • {node.timestamp.toLocaleDateString()}
                  </span>
                </div>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-main)', lineHeight: 1.45 }}>
                  {node.description}
                </div>

                {node.source_ip && (
                  <div className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--color-primary)', marginTop: '0.35rem' }}>
                    Attacker IP: <strong>{node.source_ip}</strong>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default InvestigationTimeline;
