import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import ThreatInput from './components/ThreatInput';
import RiskScoreGauge from './components/RiskScoreGauge';
import IOCTable from './components/IOCTable';
import MitreMatrix from './components/MitreMatrix';
import AIReportViewer from './components/AIReportViewer';
import DetectionRules from './components/DetectionRules';
import InteractiveGraph from './components/InteractiveGraph';
import HistoryList from './components/HistoryList';
import OverviewDashboard from './components/OverviewDashboard';
import SystemHealth from './components/SystemHealth';
import RuleEngineHub from './components/RuleEngineHub';
import { api, loadHistoryFromStorage } from './services/api';
import { Activity, ShieldAlert, BookOpen, Layers, ShieldCheck } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [activeAnalysis, setActiveAnalysis] = useState(null);
  const [historyList, setHistoryList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [activeSection, setActiveSection] = useState('risk'); // 'risk' | 'summary' | 'iocs' | 'mitre' | 'rules'

  // Check API health and load default history on start
  useEffect(() => {
    const checkApiAndLoadHistory = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/analyses?page=1&pageSize=1', {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          signal: AbortSignal.timeout(1500) // Fast timeout for health check
        });
        setApiOnline(response.ok);
      } catch (e) {
        setApiOnline(false);
      }

      // Load history (seeds loaded automatically if empty)
      const logs = loadHistoryFromStorage();
      setHistoryList(logs);
      if (logs.length > 0) {
        setActiveAnalysis(logs[0]);
      }
    };

    checkApiAndLoadHistory();
  }, []);

  const handleAnalyze = async (payload) => {
    setLoading(true);
    try {
      let result;
      if (payload.inputType === 'file') {
        result = await api.uploadThreatFile(payload.file, {
          selectedPresetId: payload.selectedPresetId
        });
      } else {
        result = await api.analyzeThreat(payload.content, {
          inputType: payload.inputType,
          selectedPresetId: payload.selectedPresetId
        });
      }
      
      // Update state
      setActiveAnalysis(result);
      // Reload history list
      setHistoryList(loadHistoryFromStorage());
      // Switch view to analyzer
      setActiveTab('analyzer');
    } catch (e) {
      console.error("Analysis pipeline execution failed", e);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectHistory = (item) => {
    setActiveAnalysis(item);
    setActiveTab('analyzer');
  };

  const handleClearHistory = () => {
    api.clearHistory();
    setHistoryList([]);
    setActiveAnalysis(null);
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        apiOnline={apiOnline} 
      />

      {/* Main Content Area */}
      <main className="main-content">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <OverviewDashboard 
            history={historyList}
            onNavigate={setActiveTab}
            onSelectThreat={setActiveAnalysis}
            apiOnline={apiOnline}
          />
        )}

        {/* Threat Analyzer Tab */}
        {activeTab === 'analyzer' && (
          <div className="dashboard-grid animate-fade-in">
            
            {/* Left Column: Input Panel */}
            <div className="dashboard-left">
              <ThreatInput onAnalyze={handleAnalyze} loading={loading} />
            </div>

            {/* Right Column: Dynamic Analysis Panels */}
            <div className="dashboard-right">
              {activeAnalysis ? (
                <div className="analysis-results animate-fade-in">
                  
                  {/* Results Panel Switch Tabs */}
                  <div className="results-nav-tabs">
                    <button 
                      className={`res-tab-btn ${activeSection === 'risk' ? 'active' : ''}`}
                      onClick={() => setActiveSection('risk')}
                    >
                      <ShieldCheck size={16} />
                      <span>Risk Engine</span>
                    </button>
                    <button 
                      className={`res-tab-btn ${activeSection === 'summary' ? 'active' : ''}`}
                      onClick={() => setActiveSection('summary')}
                    >
                      <BookOpen size={16} />
                      <span>Threat Brief</span>
                    </button>
                    <button 
                      className={`res-tab-btn ${activeSection === 'iocs' ? 'active' : ''}`}
                      onClick={() => setActiveSection('iocs')}
                    >
                      <ShieldAlert size={16} />
                      <span>IOC Registry ({activeAnalysis.iocs?.length || 0})</span>
                    </button>
                    <button 
                      className={`res-tab-btn ${activeSection === 'mitre' ? 'active' : ''}`}
                      onClick={() => setActiveSection('mitre')}
                    >
                      <Layers size={16} />
                      <span>MITRE Matrix</span>
                    </button>
                    <button 
                      className={`res-tab-btn ${activeSection === 'rules' ? 'active' : ''}`}
                      onClick={() => setActiveSection('rules')}
                    >
                      <Activity size={16} />
                      <span>Detection Rules</span>
                    </button>
                  </div>

                  {/* Tab Renderers */}
                  <div className="results-viewport">
                    {activeSection === 'risk' && (
                      <div className="animate-fade-in">
                        <RiskScoreGauge 
                          score={activeAnalysis.risk_score} 
                          level={activeAnalysis.risk_level} 
                          factors={activeAnalysis.risk_factors} 
                        />
                      </div>
                    )}
                    {activeSection === 'summary' && (
                      <AIReportViewer report={activeAnalysis.ai_report} />
                    )}
                    {activeSection === 'iocs' && (
                      <IOCTable iocs={activeAnalysis.iocs} enrichment={activeAnalysis.enrichment} />
                    )}
                    {activeSection === 'mitre' && (
                      <MitreMatrix mapping={activeAnalysis.mitre_mapping} />
                    )}
                    {activeSection === 'rules' && (
                      <DetectionRules rules={activeAnalysis.detection_rules} />
                    )}
                  </div>

                </div>
              ) : (
                <div className="dashboard-empty-state card">
                  <ShieldAlert size={48} className="shield-placeholder animate-pulse" />
                  <h2>System Idle</h2>
                  <p>Input threat intelligence data or select a preset scenario from the left panel to execute the AI Security pipeline.</p>
                </div>
              )}
            </div>

          </div>
        )}

        {/* Threat Relationship Graph Tab */}
        {activeTab === 'graph' && (
          <div className="graph-tab-view animate-fade-in">
            <InteractiveGraph analysisData={activeAnalysis} />
          </div>
        )}

        {/* Rule Engine Workstation Tab */}
        {activeTab === 'rules' && (
          <RuleEngineHub 
            history={historyList}
            activeAnalysis={activeAnalysis}
            onSelectThreat={setActiveAnalysis}
            onUpdateHistory={setHistoryList}
          />
        )}

        {/* History Audit Logs Tab */}
        {activeTab === 'history' && (
          <div className="history-tab-view animate-fade-in">
            <HistoryList 
              history={historyList} 
              onSelect={handleSelectHistory} 
              onClear={handleClearHistory} 
            />
          </div>
        )}

        {/* System Health Tab */}
        {activeTab === 'health' && (
          <SystemHealth />
        )}
      </main>
    </div>
  );
}
