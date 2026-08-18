import React, { useState } from 'react';
import { Shield, Lock, User, KeyRound, AlertTriangle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const LoginView = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('analyst123');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const res = await login(username.trim(), password);
    if (!res.success) {
      setError(res.error || 'Invalid credentials');
    }
    setLoading(false);
  };

  const handleQuickFill = (u, p) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'radial-gradient(circle at 50% 30%, #172338 0%, #0b0f19 80%)',
      padding: '1.5rem'
    }}>
      <div className="soc-card" style={{ width: '100%', maxWidth: '440px', padding: '2rem', border: '1px solid var(--border-prominent)', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '52px',
            height: '52px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, #0891b2 0%, #0284c7 100%)',
            color: '#ffffff',
            boxShadow: '0 0 20px rgba(6, 182, 212, 0.5)',
            marginBottom: '1rem'
          }}>
            <Shield size={28} />
          </div>
          <h1 style={{ fontSize: '1.45rem', fontWeight: 800, letterSpacing: '0.04em' }}>
            SENTINEL<span style={{ color: 'var(--color-primary)' }}>X</span>
          </h1>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Security Operations Center & SIEM Portal
          </p>
        </div>

        {error && (
          <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '0.8rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
              Username
            </label>
            <div style={{ position: 'relative' }}>
              <User size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
              <input
                type="text"
                required
                className="soc-input"
                style={{ width: '100%', paddingLeft: '32px' }}
                placeholder="Enter SOC username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
              <input
                type="password"
                required
                className="soc-input"
                style={{ width: '100%', paddingLeft: '32px' }}
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: '100%', padding: '0.65rem', marginTop: '0.5rem', fontWeight: 600 }}
          >
            <KeyRound size={16} />
            <span>{loading ? 'Authenticating...' : 'Access SOC Console'}</span>
          </button>
        </form>

        {/* Demo Fast Login Presets */}
        <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-subtle)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.6rem' }}>
            DEMO ACCESS ROLES (ONE-CLICK LOGIN):
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
            <button
              type="button"
              onClick={() => handleQuickFill('analyst', 'analyst123')}
              className="btn btn-sm"
              style={{ fontSize: '0.72rem', padding: '0.3rem 0.6rem' }}
            >
              L2 Analyst Account
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill('admin', 'sentinelx123')}
              className="btn btn-sm"
              style={{ fontSize: '0.72rem', padding: '0.3rem 0.6rem' }}
            >
              SOC Administrator
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginView;
