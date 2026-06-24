import React from 'react';
import { 
  TrendingUp, ShieldAlert, Award, Database, 
  ArrowRight, Activity, Calendar, Zap, AlertCircle
} from 'lucide-react';
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, 
  CartesianGrid, Tooltip, BarChart, Bar, Cell, Legend 
} from 'recharts';

export default function OverviewDashboard({ history = [], onNavigate, onSelectThreat, apiOnline }) {
  
  // Compute Stats
  const totalScans = history.length;
  
  const avgRiskScore = totalScans > 0 
    ? Math.round(history.reduce((acc, h) => acc + (h.risk_score || 0), 0) / totalScans) 
    : 0;
    
  const criticalCount = history.filter(h => h.risk_level?.toLowerCase() === 'critical').length;
  const highCount = history.filter(h => h.risk_level?.toLowerCase() === 'high').length;
  const mediumCount = history.filter(h => h.risk_level?.toLowerCase() === 'medium').length;
  const lowCount = history.filter(h => h.risk_level?.toLowerCase() === 'low').length;
  
  const cachedCount = history.filter(h => h.cached).length;
  const cacheEfficiency = totalScans > 0 
    ? Math.round((cachedCount / totalScans) * 100) 
    : 33; // Default visual state if zero

  // Prepare Trend Data (sorted by timestamp ascending)
  const trendData = [...history]
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .slice(-10) // Last 10 scans
    .map((h, idx) => ({
      index: idx + 1,
      score: h.risk_score || 0,
      name: h.presetName || (h.input_type === 'file' ? 'Artifact File' : 'Text Paste'),
      id: h.analysis_id?.substring(0, 8) || 'Scan'
    }));

  // Prepare Severity Data
  const severityData = [
    { name: 'Critical', count: criticalCount, color: '#ff3e3e' },
    { name: 'High', count: highCount, color: '#ffaa00' },
    { name: 'Medium', count: mediumCount, color: '#00f0ff' },
    { name: 'Low', count: lowCount, color: '#00ff9f' }
  ];

  const getRiskBadgeClass = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'badge badge-critical';
      case 'high': return 'badge badge-high';
      case 'medium': return 'badge badge-medium';
      case 'low': return 'badge badge-low';
      default: return 'badge';
    }
  };

  const formatDate = (isoStr) => {
    try {
      const date = new Date(isoStr);
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return isoStr;
    }
  };

  const handleInspectThreat = (item) => {
    onSelectThreat(item);
    onNavigate('analyzer');
  };

  return (
    <div className="dashboard-overview animate-fade-in">
      {/* Header */}
      <div className="overview-header">
        <div>
          <h1 className="overview-title">Threat Security Center</h1>
          <p className="overview-subtitle">Real-time AI threat intelligence ingestion & analysis monitoring</p>
        </div>
        <button 
          className="btn btn-primary"
          onClick={() => onNavigate('analyzer')}
        >
          <span>New Threat Scan</span>
          <ArrowRight size={16} />
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="metrics-summary-grid">
        {/* KPI 1 */}
        <div className="metric-card card">
          <div className="metric-icon-wrapper bg-cyan">
            <TrendingUp size={20} className="icon-cyan" />
          </div>
          <div className="metric-details">
            <span className="metric-label">Total Ingested Scans</span>
            <h2 className="metric-value font-display">{totalScans}</h2>
            <span className="metric-trend text-cyan">
              <Zap size={12} style={{ display: 'inline', marginRight: '4px' }} />
              Active Pipeline
            </span>
          </div>
        </div>

        {/* KPI 2 */}
        <div className="metric-card card">
          <div className="metric-icon-wrapper bg-red">
            <ShieldAlert size={20} className="icon-red" />
          </div>
          <div className="metric-details">
            <span className="metric-label">Critical Threat Events</span>
            <h2 className="metric-value font-display">{criticalCount}</h2>
            <span className="metric-trend text-red">Requires immediate action</span>
          </div>
        </div>

        {/* KPI 3 */}
        <div className="metric-card card">
          <div className="metric-icon-wrapper bg-orange">
            <Award size={20} className="icon-orange" />
          </div>
          <div className="metric-details">
            <span className="metric-label">Average Risk Index</span>
            <h2 className="metric-value font-display">{avgRiskScore}<span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/100</span></h2>
            <span className="metric-trend text-orange">Aggregated system severity</span>
          </div>
        </div>

        {/* KPI 4 */}
        <div className="metric-card card">
          <div className="metric-icon-wrapper bg-purple">
            <Database size={20} className="icon-purple" />
          </div>
          <div className="metric-details">
            <span className="metric-label">Cache Saving Ratio</span>
            <h2 className="metric-value font-display">{cacheEfficiency}%</h2>
            <span className="metric-trend text-purple">Optimized backend latency</span>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="overview-charts-grid">
        {/* Risk Trend Chart */}
        <div className="chart-card card">
          <div className="card-header">
            <h3>Threat Severity Scoring Trend</h3>
            <span className="card-subtitle">Risk indexing score for the last 10 analyzed threats</span>
          </div>
          <div className="chart-wrapper">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="id" stroke="var(--text-muted)" fontSize={11} />
                  <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-medium)' }} 
                    labelStyle={{ color: 'var(--text-primary)', fontWeight: 'bold' }}
                    itemStyle={{ color: '#00f0ff' }}
                    formatter={(value, name, props) => [`Score: ${value}`, props.payload.name]}
                  />
                  <Area type="monotone" dataKey="score" stroke="#00f0ff" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-chart">
                <AlertCircle size={28} />
                <span>No trend data available. Ingest threat files to populate.</span>
              </div>
            )}
          </div>
        </div>

        {/* Severity Classification */}
        <div className="chart-card card">
          <div className="card-header">
            <h3>Severity Tier Distribution</h3>
            <span className="card-subtitle">Breakdown of vulnerabilities and scans by risk severity level</span>
          </div>
          <div className="chart-wrapper">
            {totalScans > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={11} />
                  <YAxis allowDecimals={false} stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-medium)' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-chart">
                <AlertCircle size={28} />
                <span>No distribution metrics available.</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Grid: Recent Alerts Feed & System Health Quick Glance */}
      <div className="overview-bottom-grid">
        {/* Recent Alerts Feed */}
        <div className="recent-threats-card card">
          <div className="card-header">
            <h3>Recent Threat Incidents</h3>
            <span className="card-subtitle">Latest security intelligence runs in the audit stack</span>
          </div>
          <div className="table-responsive">
            {history.length === 0 ? (
              <div className="empty-state-text">No threat reports logged.</div>
            ) : (
              <table className="overview-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Threat Profile</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {history.slice(0, 5).map((item) => (
                    <tr key={item.analysis_id}>
                      <td className="time-col font-mono text-muted">{formatDate(item.timestamp)}</td>
                      <td className="profile-col">
                        <div className="profile-name">
                          {item.presetName || (item.input_type === 'file' ? 'Artifact Document' : 'Manual Text Ingestion')}
                        </div>
                        <span className="id-col text-muted font-mono">{item.analysis_id?.substring(0, 8)}...</span>
                      </td>
                      <td className="score-col font-mono font-bold">{item.risk_score}</td>
                      <td>
                        <span className={getRiskBadgeClass(item.risk_level)}>
                          {item.risk_level}
                        </span>
                      </td>
                      <td className="action-col">
                        <button 
                          className="btn btn-secondary btn-small"
                          onClick={() => handleInspectThreat(item)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Quick System Info Widget */}
        <div className="quick-sys-card card">
          <div className="card-header">
            <h3>AI Orchestrator Nodes</h3>
            <span className="card-subtitle">Active processors and system gateway checks</span>
          </div>
          <div className="orchestrator-list">
            <div className="orchestrator-item">
              <div className="orch-meta">
                <span className="orch-dot online"></span>
                <strong>Groq AI Engine</strong>
              </div>
              <span className="orch-status text-cyan">Llama3-70B-Sec</span>
            </div>
            
            <div className="orchestrator-item">
              <div className="orch-meta">
                <span className="orch-dot online"></span>
                <strong>NVD CVE Lookup Service</strong>
              </div>
              <span className="orch-status text-muted">2.0 REST API</span>
            </div>

            <div className="orchestrator-item">
              <div className="orch-meta">
                <span className="orch-dot online"></span>
                <strong>Local Heuristics Engine</strong>
              </div>
              <span className="orch-status text-muted">Signature & Regex Matcher</span>
            </div>

            <div className="orchestrator-item">
              <div className="orch-meta">
                <span className={`orch-dot ${apiOnline ? 'online' : 'offline'}`}></span>
                <strong>Sentinel REST API Gateway</strong>
              </div>
              <span className={`orch-status ${apiOnline ? 'text-green' : 'text-orange'}`}>
                {apiOnline ? 'ONLINE (8000)' : 'LOCAL MODE'}
              </span>
            </div>
          </div>
          
          <div className="sys-summary-footer">
            <Activity size={14} className="animate-pulse text-cyan" />
            <span>Continuous telemetry feedback active</span>
          </div>
        </div>
      </div>
    </div>
  );
}
