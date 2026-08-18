import React, { useState, useEffect } from 'react';
import { useAuth } from './context/AuthContext';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardOverview from './pages/DashboardOverview';
import LiveLogsView from './pages/LiveLogsView';
import AlertsView from './pages/AlertsView';
import IncidentsView from './pages/IncidentsView';
import IpIntelligenceView from './pages/IpIntelligenceView';
import AttackSimulatorView from './pages/AttackSimulatorView';
import DetectionRulesView from './pages/DetectionRulesView';
import ReportsView from './pages/ReportsView';
import LoginView from './pages/LoginView';
import QuickAlertModal from './components/QuickAlertModal';
import CreateIncidentModal from './components/CreateIncidentModal';
import ManualLogModal from './components/ManualLogModal';
import ChangePasswordModal from './components/ChangePasswordModal';
import api from './api/client';

function App() {
  const { isAuthenticated } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  
  // Modals state
  const [selectedAlertForModal, setSelectedAlertForModal] = useState(null);
  const [alertToEscalate, setAlertToEscalate] = useState(null);
  const [isIncidentModalOpen, setIsIncidentModalOpen] = useState(false);
  const [isManualLogModalOpen, setIsManualLogModalOpen] = useState(false);
  const [isChangePasswordModalOpen, setIsChangePasswordModalOpen] = useState(false);

  // Global telemetry badges
  const [alertStats, setAlertStats] = useState({});
  const [incidentCounts, setIncidentCounts] = useState({ active: 0 });
  const [refreshKey, setRefreshKey] = useState(0);

  const fetchGlobalStats = async () => {
    if (!isAuthenticated) return;
    try {
      const [alRes, incRes] = await Promise.all([
        api.get('/alerts/stats'),
        api.get('/incidents?limit=100')
      ]);
      setAlertStats(alRes.data);
      const active = incRes.data.filter(i => ['Open', 'Investigating'].includes(i.status)).length;
      setIncidentCounts({ active });
    } catch (e) {
      // ignore in background
    }
  };

  useEffect(() => {
    fetchGlobalStats();
    const interval = setInterval(fetchGlobalStats, 5000);
    return () => clearInterval(interval);
  }, [isAuthenticated, refreshKey]);

  const handleRefreshAll = () => {
    setRefreshKey(prev => prev + 1);
    fetchGlobalStats();
  };

  const handleOpenAlert = (alert) => {
    setSelectedAlertForModal(alert);
  };

  const handleUpdateAlertStatus = async (alertId, newStatus) => {
    try {
      await api.patch(`/alerts/${alertId}/status`, { status: newStatus });
      fetchGlobalStats();
      if (selectedAlertForModal && selectedAlertForModal.id === alertId) {
        setSelectedAlertForModal(prev => ({ ...prev, status: newStatus }));
      }
    } catch (e) {
      console.error('Failed to update alert status', e);
    }
  };

  const handleEscalateFromModal = (alert) => {
    setSelectedAlertForModal(null);
    setAlertToEscalate(alert);
    setIsIncidentModalOpen(true);
  };

  const handleEscalateAlert = (alert) => {
    setAlertToEscalate(alert);
    setIsIncidentModalOpen(true);
  };

  if (!isAuthenticated) {
    return <LoginView />;
  }

  return (
    <div className="layout-container">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertCounts={alertStats}
        incidentCounts={incidentCounts}
      />

      {/* Main Content Pane */}
      <div className="main-content">
        <Header
          onOpenManualLog={() => setIsManualLogModalOpen(true)}
          onOpenChangePassword={() => setIsChangePasswordModalOpen(true)}
          onRefreshAll={handleRefreshAll}
        />

        <main style={{ flex: 1, overflowY: 'auto' }}>
          {activeTab === 'overview' && (
            <DashboardOverview
              key={refreshKey}
              onOpenAlert={handleOpenAlert}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'logs' && (
            <LiveLogsView
              key={refreshKey}
              onOpenManualLog={() => setIsManualLogModalOpen(true)}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsView
              key={refreshKey}
              onOpenAlert={handleOpenAlert}
              onEscalateAlert={handleEscalateAlert}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentsView
              key={refreshKey}
              onOpenCreateIncident={() => {
                setAlertToEscalate(null);
                setIsIncidentModalOpen(true);
              }}
            />
          )}

          {activeTab === 'ip_intel' && (
            <IpIntelligenceView key={refreshKey} />
          )}

          {activeTab === 'simulator' && (
            <AttackSimulatorView
              onSimulationTriggered={handleRefreshAll}
            />
          )}

          {activeTab === 'rules' && (
            <DetectionRulesView key={refreshKey} />
          )}

          {activeTab === 'reports' && (
            <ReportsView key={refreshKey} />
          )}
        </main>
      </div>

      {/* Shared Modals */}
      <QuickAlertModal
        alert={selectedAlertForModal}
        isOpen={!!selectedAlertForModal}
        onClose={() => setSelectedAlertForModal(null)}
        onUpdateStatus={handleUpdateAlertStatus}
        onEscalate={handleEscalateFromModal}
      />

      <CreateIncidentModal
        isOpen={isIncidentModalOpen}
        onClose={() => {
          setIsIncidentModalOpen(false);
          setAlertToEscalate(null);
        }}
        alertToEscalate={alertToEscalate}
        onIncidentCreated={() => {
          handleRefreshAll();
          setActiveTab('incidents');
        }}
      />

      <ManualLogModal
        isOpen={isManualLogModalOpen}
        onClose={() => setIsManualLogModalOpen(false)}
        onLogIngested={handleRefreshAll}
      />

      <ChangePasswordModal
        isOpen={isChangePasswordModalOpen}
        onClose={() => setIsChangePasswordModalOpen(false)}
      />
    </div>
  );
}

export default App;
