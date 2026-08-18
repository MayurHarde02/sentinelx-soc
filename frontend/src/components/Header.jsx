import React, { useState, useEffect } from 'react';
import { Shield, Radio, Terminal, Database, User, LogOut, RefreshCw, KeyRound } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../api/client';

const Header = ({ onOpenManualLog, onRefreshAll, onOpenChangePassword }) => {
  const { user, logout } = useAuth();
  const [streamActive, setStreamActive] = useState(false);
  const [seeding, setSeeding] = useState(false);

  useEffect(() => {
    // Check initial stream status
    api.get('/simulation/stream/status')
      .then(res => setStreamActive(res.data.live_stream_active))
      .catch(() => {});
  }, []);

  const handleToggleStream = async () => {
    try {
      const res = await api.post('/simulation/stream/toggle');
      setStreamActive(res.data.live_stream_active);
      if (onRefreshAll) onRefreshAll();
    } catch (e) {
      console.error('Failed to toggle stream', e);
    }
  };

  const handleSeedDemo = async () => {
    setSeeding(true);
    try {
      await api.post('/simulation/seed-demo');
      if (onRefreshAll) onRefreshAll();
    } catch (e) {
      console.error('Failed to seed demo', e);
    } finally {
      setSeeding(false);
    }
  };

  return (
    <header style={{
      background: 'var(--bg-surface)',
      borderBottom: '1px solid var(--border-subtle)',
      padding: '0.75rem 1.5rem',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      zIndex: 20
    }}>
      {/* Brand / SOC status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, #0891b2 0%, #0284c7 100%)',
            color: '#fff',
            padding: '0.45rem',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 12px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={20} />
          </div>
          <div>
            <div style={{ fontSize: '1.05rem', fontWeight: 800, letterSpacing: '0.04em', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              SENTINEL<span style={{ color: 'var(--color-primary)' }}>X</span>
              <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'var(--bg-surface-raised)', color: 'var(--text-muted)', border: '1px solid var(--border-subtle)', fontWeight: 600 }}>v1.0 SOC</span>
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', letterSpacing: '0.02em' }}>
              SECURITY OPERATIONS CENTER & SIEM
            </div>
          </div>
        </div>

        <div style={{ height: '24px', width: '1px', background: 'var(--border-subtle)' }} />

        {/* Telemetry Status Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem' }}>
          <span className="live-pulse" />
          <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>ENGINE ONLINE</span>
        </div>
      </div>

      {/* Action Controls & User info */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {/* Live background simulation toggle */}
        <button
          onClick={handleToggleStream}
          className="btn btn-sm"
          style={{
            background: streamActive ? 'rgba(16, 185, 129, 0.15)' : 'var(--bg-surface-raised)',
            borderColor: streamActive ? 'var(--color-success)' : 'var(--border-subtle)',
            color: streamActive ? '#34d399' : 'var(--text-muted)',
          }}
          title="Toggle automatic background simulated events stream"
        >
          <Radio size={14} className={streamActive ? 'live-pulse' : ''} />
          <span>Stream: <strong>{streamActive ? 'ACTIVE' : 'IDLE'}</strong></span>
        </button>

        {/* Manual Raw Log Ingest */}
        <button
          onClick={onOpenManualLog}
          className="btn btn-sm"
          title="Ingest raw text or JSON log"
        >
          <Terminal size={14} />
          <span>Inject Log</span>
        </button>

        {/* Seed Demo Dataset */}
        <button
          onClick={handleSeedDemo}
          disabled={seeding}
          className="btn btn-sm"
          title="Seed realistic attacks and benign logs into the database"
        >
          <Database size={14} />
          <span>{seeding ? 'Generating...' : 'Seed Attacks'}</span>
        </button>

        <div style={{ height: '24px', width: '1px', background: 'var(--border-subtle)' }} />

        {/* Refresh button */}
        <button
          onClick={onRefreshAll}
          className="btn btn-sm"
          title="Refresh telemetry"
          style={{ padding: '0.35rem 0.5rem' }}
        >
          <RefreshCw size={14} />
        </button>

        {/* User profile, Change Password & Logout */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginLeft: '0.25rem' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-main)' }}>{user?.username || 'Analyst'}</div>
            <div style={{ fontSize: '0.68rem', color: 'var(--color-primary)', textTransform: 'uppercase' }}>{user?.role || 'L1 SOC'}</div>
          </div>
          
          <button
            onClick={onOpenChangePassword}
            className="btn btn-sm"
            style={{ padding: '0.35rem 0.5rem', background: 'var(--bg-surface-raised)', color: 'var(--text-muted)' }}
            title="Change Account Password"
          >
            <KeyRound size={15} />
          </button>

          <button
            onClick={logout}
            className="btn btn-sm"
            style={{ padding: '0.35rem 0.5rem', background: 'transparent', color: 'var(--text-dim)' }}
            title="Log out"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;
