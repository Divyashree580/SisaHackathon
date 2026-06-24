import React from 'react';
import { Shield, Activity, Database, Network, Server, RefreshCw } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, apiOnline }) {
  const navItems = [
    { id: 'dashboard', name: 'Threat Dashboard', icon: Shield },
    { id: 'graph', name: 'Threat Graph', icon: Network },
    { id: 'history', name: 'Analysis Logs', icon: Database },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <Activity className="brand-icon animate-pulse" />
        <div className="brand-text">
          <h1>SISA Sentinel</h1>
          <span>AI Threat Intelligence</span>
        </div>
      </div>

      <nav className="sidebar-menu">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`sidebar-link ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon size={18} className="link-icon" />
              <span>{item.name}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <div className={`status-dot ${apiOnline ? 'online' : 'offline'}`} />
          <div className="status-info">
            <span className="status-label">API SERVER</span>
            <span className="status-value">{apiOnline ? 'CONNECTED' : 'OFFLINE (LOCAL)'}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
