import React, { useState, useEffect } from 'react';
import { 
  Activity, Database, Cpu, HardDrive, Wifi, WifiOff, 
  Clock, AlertTriangle, CheckCircle2, RotateCw, Server, Zap, Globe
} from 'lucide-react';

export default function SystemHealth() {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [uptimeStr, setUptimeStr] = useState('N/A');

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:8000/health', {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(2000)
      });
      if (response.ok) {
        const data = await response.json();
        setHealthData(data);
        setApiOnline(true);
        calculateUptime(data.uptime_seconds);
      } else {
        throw new Error('API Health response error');
      }
    } catch (e) {
      setApiOnline(false);
      setHealthData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000); // Check every 10s
    return () => clearInterval(interval);
  }, []);

  const calculateUptime = (seconds) => {
    if (!seconds) return;
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    setUptimeStr(`${hrs}h ${mins}m ${secs}s`);
  };

  // Uptime tick logic for active UI
  useEffect(() => {
    if (!healthData || !healthData.uptime_seconds) return;
    let currentUptime = healthData.uptime_seconds;
    const ticker = setInterval(() => {
      currentUptime += 1;
      calculateUptime(currentUptime);
    }, 1000);
    return () => clearInterval(ticker);
  }, [healthData]);

  // Compute local fallback stats if API offline
  const mockHealthData = {
    status: "degraded",
    uptime_seconds: 0,
    version: "1.0.0-local",
    metrics: {
      total_requests: 0,
      total_analyses: 0,
      avg_response_time_ms: 0,
      error_count: 0,
      cache_hit_count: 0,
      cache_miss_count: 0
    },
    dependencies: {
      database: false,
      groq_api: false,
      nvd_api: true
    }
  };

  const activeData = apiOnline && healthData ? healthData : mockHealthData;
  const metrics = activeData.metrics || {};
  const deps = activeData.dependencies || {};

  // Compute cache hit ratio
  const cacheTotal = (metrics.cache_hit_count || 0) + (metrics.cache_miss_count || 0);
  const cacheHitRatio = cacheTotal > 0 
    ? Math.round((metrics.cache_hit_count / cacheTotal) * 100) 
    : 0;

  return (
    <div className="system-health-view animate-fade-in">
      {/* Header */}
      <div className="overview-header">
        <div>
          <h1 className="overview-title">System Observability Hub</h1>
          <p className="overview-subtitle">Real-time gateway connectivity logs and pipeline health analytics</p>
        </div>
        <button 
          onClick={fetchHealth} 
          className={`btn btn-secondary ${loading ? 'disabled' : ''}`}
          disabled={loading}
        >
          <RotateCw size={16} className={loading ? 'animate-spin' : ''} />
          <span>Sync Diagnostics</span>
        </button>
      </div>

      {/* Online/Offline Banner */}
      {!apiOnline ? (
        <div className="health-warning-banner card">
          <WifiOff size={24} className="icon-orange animate-pulse" />
          <div className="banner-details">
            <h4>Local Sandbox Mode Active</h4>
            <p>The FastAPI backend server is currently offline. Sentinel is running fully client-side on local fallback heuristics. Threat intelligence parsing is fully active in your browser, but database persistence and LLM reports are limited.</p>
          </div>
        </div>
      ) : (
        <div className="health-success-banner card">
          <Wifi size={24} className="icon-cyan" />
          <div className="banner-details">
            <h4>Gateway Connected</h4>
            <p>API Endpoint is responding successfully. All advanced features including MongoDB clustering, Groq Llama3 modeling, and NVD real-time CVE searches are operating at full capacity.</p>
          </div>
        </div>
      )}

      {/* Main Grid */}
      <div className="health-grid">
        {/* Left: Dependencies Cards */}
        <div className="health-column-left">
          <div className="card dependency-card">
            <div className="card-header">
              <h3>Service Dependency Map</h3>
              <span className="card-subtitle">Ping statuses of required pipeline systems</span>
            </div>

            <div className="dep-list">
              {/* Database */}
              <div className="dep-item">
                <div className="dep-meta">
                  <Database size={18} className="dep-icon" />
                  <div>
                    <h4>MongoDB Database Node</h4>
                    <p className="text-muted">Storage for threat analyses & cache logs</p>
                  </div>
                </div>
                <div className="dep-status">
                  {deps.database ? (
                    <span className="status-label-online"><CheckCircle2 size={12} /> Connected</span>
                  ) : (
                    <span className="status-label-offline"><AlertTriangle size={12} /> Local Storage</span>
                  )}
                </div>
              </div>

              {/* LLM Engine */}
              <div className="dep-item">
                <div className="dep-meta">
                  <Cpu size={18} className="dep-icon" />
                  <div>
                    <h4>Groq AI Ingress (Llama3)</h4>
                    <p className="text-muted">AI Threat Briefs & ATT&CK Mapping reports</p>
                  </div>
                </div>
                <div className="dep-status">
                  {deps.groq_api ? (
                    <span className="status-label-online"><CheckCircle2 size={12} /> Active</span>
                  ) : (
                    <span className="status-label-offline"><AlertTriangle size={12} /> Heuristics Mode</span>
                  )}
                </div>
              </div>

              {/* NVD Feed */}
              <div className="dep-item">
                <div className="dep-meta">
                  <Globe size={18} className="dep-icon" />
                  <div>
                    <h4>NVD CVE Lookup API</h4>
                    <p className="text-muted">Dynamic CVSS severity database queries</p>
                  </div>
                </div>
                <div className="dep-status">
                  {deps.nvd_api ? (
                    <span className="status-label-online"><CheckCircle2 size={12} /> Operational</span>
                  ) : (
                    <span className="status-label-degraded"><AlertTriangle size={12} /> Local Cache</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* System Telemetry Details */}
          <div className="card telemetry-card">
            <div className="card-header">
              <h3>Runtime Telemetry</h3>
              <span className="card-subtitle">Gateway engine stats and environment logs</span>
            </div>
            
            <div className="telemetry-info-grid">
              <div className="tel-box">
                <span className="tel-label">System Uptime</span>
                <span className="tel-value font-mono">{apiOnline ? uptimeStr : 'N/A (Offline)'}</span>
              </div>
              <div className="tel-box">
                <span className="tel-label">API Gateway Host</span>
                <span className="tel-value font-mono">http://localhost:8000</span>
              </div>
              <div className="tel-box">
                <span className="tel-label">Engine Version</span>
                <span className="tel-value font-mono">v{activeData.version}</span>
              </div>
              <div className="tel-box">
                <span className="tel-label">API Error Rate</span>
                <span className="tel-value font-mono">{metrics.error_count || 0} failed requests</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Observability Metrics */}
        <div className="health-column-right">
          <div className="card metrics-card">
            <div className="card-header">
              <h3>API Gateway Performance</h3>
              <span className="card-subtitle">Orchestrated request latency and pipeline counters</span>
            </div>

            <div className="metrics-performance-grid">
              <div className="perf-item">
                <div className="perf-label-row">
                  <span>Total Pipeline Requests</span>
                  <strong className="font-mono">{metrics.total_requests || 0}</strong>
                </div>
                <div className="progress-bar-container">
                  <div className="progress-bar bg-cyan" style={{ width: metrics.total_requests > 0 ? '100%' : '0%' }}></div>
                </div>
              </div>

              <div className="perf-item">
                <div className="perf-label-row">
                  <span>Average API Latency</span>
                  <strong className="font-mono">{metrics.avg_response_time_ms ? `${metrics.avg_response_time_ms.toFixed(1)}ms` : '0ms'}</strong>
                </div>
                <div className="progress-bar-container">
                  <div className="progress-bar bg-orange" style={{ 
                    width: metrics.avg_response_time_ms ? `${Math.min(100, (metrics.avg_response_time_ms / 2000) * 100)}%` : '0%' 
                  }}></div>
                </div>
                <span className="perf-hint">Optimal baseline is below 800ms</span>
              </div>

              <div className="perf-item">
                <div className="perf-label-row">
                  <span>Cache Efficiency (Hit Ratio)</span>
                  <strong className="font-mono">{cacheHitRatio}%</strong>
                </div>
                <div className="progress-bar-container">
                  <div className="progress-bar bg-purple" style={{ width: `${cacheHitRatio}%` }}></div>
                </div>
                <span className="perf-hint">
                  {metrics.cache_hit_count || 0} hits / {metrics.cache_miss_count || 0} misses
                </span>
              </div>

              <div className="perf-item">
                <div className="perf-label-row">
                  <span>Threat Intelligence Pipelines Run</span>
                  <strong className="font-mono">{metrics.total_analyses || 0}</strong>
                </div>
                <div className="progress-bar-container">
                  <div className="progress-bar bg-red" style={{ width: metrics.total_analyses > 0 ? '100%' : '0%' }}></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
