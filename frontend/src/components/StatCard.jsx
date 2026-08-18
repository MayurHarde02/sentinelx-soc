import React from 'react';

const StatCard = ({ title, value, subtitle, icon: Icon, color = 'var(--color-primary)', trend }) => {
  return (
    <div className="soc-card" style={{ position: 'relative', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {title}
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.35rem', lineHeight: 1.1 }}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
          {subtitle && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.4rem' }}>
              {subtitle}
            </div>
          )}
        </div>
        {Icon && (
          <div style={{
            background: `rgba(${color.startsWith('#') ? '6, 182, 212, 0.12' : '255, 255, 255, 0.05'})`,
            padding: '0.65rem',
            borderRadius: '8px',
            color: color,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Icon size={22} />
          </div>
        )}
      </div>
      {trend && (
        <div style={{ marginTop: '0.65rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.75rem', color: trend.isGood ? 'var(--color-success)' : 'var(--color-danger)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
          <span>{trend.text}</span>
        </div>
      )}
    </div>
  );
};

export default StatCard;
