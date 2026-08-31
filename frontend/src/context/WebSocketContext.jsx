import React, { createContext, useContext, useEffect, useState, useRef } from 'react';
import { ShieldAlert, AlertTriangle, Info, X } from 'lucide-react';

const WebSocketContext = createContext({
  isConnected: false,
  lastEvent: null,
  lastAlert: null,
  newAlertCount: 0,
  clearNewAlerts: () => {}
});

export const useWebSocket = () => useContext(WebSocketContext);

export const WebSocketProvider = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState(null);
  const [lastAlert, setLastAlert] = useState(null);
  const [newAlertCount, setNewAlertCount] = useState(0);
  const [toasts, setToasts] = useState([]);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  // Play subtle warning audio chime on CRITICAL alerts
  const playAlertSound = (severity) => {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return;
      const ctx = new AudioContext();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (severity === 'CRITICAL') {
        osc.frequency.setValueAtTime(880, ctx.currentTime); // High pitch warning
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.3);
      } else if (severity === 'HIGH') {
        osc.frequency.setValueAtTime(587.33, ctx.currentTime);
        gain.gain.setValueAtTime(0.08, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.2);
      }
    } catch (err) {
      // Audio playback might be blocked by browser autoplay policy
    }
  };

  const addToast = (alert) => {
    const id = Date.now() + Math.random();
    const newToast = { id, alert, timestamp: new Date() };
    setToasts(prev => [newToast, ...prev].slice(0, 5));

    // Auto-dismiss after 4.5s
    setTimeout(() => {
      removeToast(id);
    }, 4500);
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  const connect = () => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host || 'localhost:8000';
      const wsUrl = `${protocol}//${host}/api/ws/telemetry`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (evt) => {
        try {
          const message = JSON.parse(evt.data);
          const { type, data } = message;

          if (type === 'NEW_EVENT') {
            setLastEvent(data);
          } else if (type === 'NEW_ALERT') {
            setLastAlert(data);
            setNewAlertCount(prev => prev + 1);
            addToast(data);
            if (data?.severity === 'CRITICAL' || data?.severity === 'HIGH') {
              playAlertSound(data?.severity);
            }
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message', err);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        // Reconnect after 3 seconds
        reconnectTimeoutRef.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        setIsConnected(false);
        ws.close();
      };
    } catch (e) {
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    }
  };

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, []);

  const clearNewAlerts = () => {
    setNewAlertCount(0);
  };

  return (
    <WebSocketContext.Provider value={{ isConnected, lastEvent, lastAlert, newAlertCount, clearNewAlerts }}>
      {children}

      {/* Floating Real-Time SOC Alert Toasts */}
      <div style={{
        position: 'fixed',
        bottom: '1.5rem',
        right: '1.5rem',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.6rem',
        maxWidth: '380px',
        pointerEvents: 'none'
      }}>
        {toasts.map(toast => {
          const { alert, id } = toast;
          const isCritical = alert.severity === 'CRITICAL';
          const isHigh = alert.severity === 'HIGH';

          const borderColor = isCritical ? 'rgba(220, 38, 38, 0.8)' : isHigh ? 'rgba(245, 158, 11, 0.8)' : 'rgba(6, 182, 212, 0.5)';
          const bgColor = isCritical ? 'rgba(30, 10, 10, 0.95)' : isHigh ? 'rgba(30, 20, 10, 0.95)' : 'rgba(10, 20, 30, 0.95)';
          const Icon = isCritical ? ShieldAlert : AlertTriangle;

          return (
            <div
              key={id}
              style={{
                pointerEvents: 'auto',
                background: bgColor,
                border: `1px solid ${borderColor}`,
                boxShadow: isCritical ? '0 4px 20px rgba(220, 38, 38, 0.3)' : '0 4px 15px rgba(0, 0, 0, 0.5)',
                borderRadius: '8px',
                padding: '0.75rem 1rem',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.75rem',
                backdropFilter: 'blur(8px)',
                animation: 'slideInRight 0.25s ease-out'
              }}
            >
              <Icon size={20} color={isCritical ? '#f87171' : '#fbbf24'} style={{ marginTop: '0.1rem', flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                  <span style={{ fontSize: '0.72rem', fontWeight: 700, color: isCritical ? '#fca5a5' : '#fcd34d', textTransform: 'uppercase' }}>
                    🚨 {alert.severity} • {alert.alert_type}
                  </span>
                  <span className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
                    {new Date(toast.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ fontSize: '0.8rem', color: '#f3f4f6', fontWeight: 500, lineHeight: 1.3 }}>
                  {alert.description}
                </div>
                <div className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--color-primary)', marginTop: '0.3rem' }}>
                  Src: {alert.source_ip}
                </div>
              </div>
              <button
                onClick={() => removeToast(id)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-dim)',
                  cursor: 'pointer',
                  padding: 0,
                  marginLeft: '0.25rem'
                }}
              >
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </WebSocketContext.Provider>
  );
};
