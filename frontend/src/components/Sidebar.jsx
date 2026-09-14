import React from 'react';
import {
  LayoutDashboard,
  Activity,
  AlertOctagon,
  ShieldAlert,
  Globe,
  Zap,
  Sliders,
  FileBarChart,
  Shield,
  ClipboardList,
  Bot
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'overview',    label: 'SOC Overview',      icon: LayoutDashboard },
  { id: 'logs',        label: 'Event Logs',         icon: Activity },
  { id: 'alerts',      label: 'Alerts Triage',      icon: AlertOctagon },
  { id: 'incidents',   label: 'Incidents',           icon: ShieldAlert },
  { id: 'playbooks',   label: 'SOAR Playbooks',     icon: Bot },
  { id: 'ip_intel',   label: 'IP Intelligence',     icon: Globe },
  { id: 'threat_intel',label: 'Threat Intel',        icon: Shield },
  { id: 'simulator',   label: 'Attack Simulator',    icon: Zap },
  { id: 'rules',       label: 'Detection Rules',     icon: Sliders },
  { id: 'reports',     label: 'Reports & Export',    icon: FileBarChart },
  { id: 'audit',       label: 'Audit Trail',         icon: ClipboardList },
];


const Sidebar = ({ activeTab, setActiveTab, alertCounts = {}, incidentCounts = {} }) => {
  return (
    <aside className="sidebar">
      <div style={{ padding: '1.25rem 0.75rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', flex: 1 }}>
        <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0 0.6rem 0.5rem' }}>
          Operations Center
        </div>

        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          let countBadge = null;
          if (item.id === 'alerts' && alertCounts.open_alerts > 0) {
            countBadge = (
              <span style={{
                marginLeft: 'auto',
                background: 'rgba(239, 68, 68, 0.2)',
                color: '#f87171',
                fontSize: '0.7rem',
                fontWeight: 700,
                padding: '0.1rem 0.45rem',
                borderRadius: '10px',
                border: '1px solid rgba(239, 68, 68, 0.3)'
              }}>
                {alertCounts.open_alerts}
              </span>
            );
          } else if (item.id === 'incidents' && incidentCounts.active > 0) {
            countBadge = (
              <span style={{
                marginLeft: 'auto',
                background: 'rgba(245, 158, 11, 0.2)',
                color: '#fbbf24',
                fontSize: '0.7rem',
                fontWeight: 700,
                padding: '0.1rem 0.45rem',
                borderRadius: '10px',
                border: '1px solid rgba(245, 158, 11, 0.3)'
              }}>
                {incidentCounts.active}
              </span>
            );
          }

          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                width: '100%',
                padding: '0.65rem 0.85rem',
                borderRadius: '6px',
                border: 'none',
                background: isActive ? 'var(--bg-surface-raised)' : 'transparent',
                color: isActive ? 'var(--color-primary)' : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.85rem',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease',
                borderLeft: isActive ? '3px solid var(--color-primary)' : '3px solid transparent'
              }}
            >
              <Icon size={18} style={{ color: isActive ? 'var(--color-primary)' : 'var(--text-dim)' }} />
              <span>{item.label}</span>
              {countBadge}
            </button>
          );
        })}
      </div>

      {/* Footer */}
      <div style={{ padding: '1rem 1.25rem', borderTop: '1px solid var(--border-subtle)', background: 'rgba(0,0,0,0.2)', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
        <div>Environment: <span style={{ color: 'var(--color-primary)' }}>SOC Sandbox</span></div>
        <div style={{ marginTop: '0.2rem' }}>DB: <span style={{ color: 'var(--text-muted)' }}>SQLite Local</span></div>
      </div>
    </aside>
  );
};

export default Sidebar;
