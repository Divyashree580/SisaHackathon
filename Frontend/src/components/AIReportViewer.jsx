import React, { useState } from 'react';
import { FileText, Eye, AlertTriangle, Play, HelpCircle, ShieldAlert, CheckSquare } from 'lucide-react';

export default function AIReportViewer({ report = {} }) {
  const [activeSection, setActiveSection] = useState('summary');

  const sections = [
    { id: 'summary', title: 'Executive Summary', icon: FileText },
    { id: 'scenario', title: 'Attack Scenario & Flow', icon: Play },
    { id: 'impact', title: 'Business Impact Assessment', icon: AlertTriangle },
    { id: 'remediation', title: 'Remediation & Action Plan', icon: CheckSquare },
  ];

  return (
    <div className="ai-report-card card">
      <div className="card-header">
        <div className="header-badge-row">
          <h2>AI Copilot Threat Report</h2>
          <span className="badge badge-accent">Groq llama-3.3-70b-versatile Generated</span>
        </div>
        <span className="card-subtitle">Automated, context-rich intelligence brief and defense strategy</span>
      </div>

      <div className="ai-report-layout">
        {/* Navigation Tabs */}
        <div className="report-tabs">
          {sections.map(s => {
            const Icon = s.icon;
            return (
              <button
                key={s.id}
                className={`report-tab-btn ${activeSection === s.id ? 'active' : ''}`}
                onClick={() => setActiveSection(s.id)}
              >
                <Icon size={16} />
                <span>{s.title}</span>
              </button>
            );
          })}
        </div>

        {/* Report Content Panels */}
        <div className="report-content-panel font-sans">
          {activeSection === 'summary' && (
            <div className="report-text-section animate-fade-in">
              <h3>Incident Overview</h3>
              <p className="summary-paragraph">{report.summary || 'Generating summary...'}</p>

              <div className="report-callout note-callout">
                <h4><ShieldAlert size={16} /> Analyst Assessment</h4>
                <p>Verify all associated IP addresses are blocked on edge gateways immediately. System logs show signatures matching persistent campaigns targeting similar technical infrastructure.</p>
              </div>
            </div>
          )}

          {activeSection === 'scenario' && (
            <div className="report-text-section animate-fade-in">
              <h3>Attack Path Prediction</h3>
              <p className="scenario-paragraph">{report.attack_scenario || 'Generating attack timeline...'}</p>

              <div className="kill-chain-timeline">
                <div className="timeline-node">
                  <div className="node-marker">1</div>
                  <div className="node-content">
                    <strong>Initial Access</strong>
                    <span>Technique identified in incoming vectors.</span>
                  </div>
                </div>
                <div className="timeline-node">
                  <div className="node-marker">2</div>
                  <div className="node-content">
                    <strong>Local Execution</strong>
                    <span>Process spawned on system host resources.</span>
                  </div>
                </div>
                <div className="timeline-node">
                  <div className="node-marker">3</div>
                  <div className="node-content">
                    <strong>Command and Control</strong>
                    <span>Outbound heartbeat connection established.</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'impact' && (
            <div className="report-text-section animate-fade-in">
              <h3>Business & System Impact</h3>
              <p className="impact-paragraph">{report.business_impact || 'Calculating impact factors...'}</p>

              <div className="impact-matrix">
                <div className="impact-box critical-impact">
                  <strong>Confidentiality</strong>
                  <span>High Risk of Exfiltration</span>
                </div>
                <div className="impact-box high-impact">
                  <strong>Integrity</strong>
                  <span>System Tampering Detected</span>
                </div>
                <div className="impact-box medium-impact">
                  <strong>Availability</strong>
                  <span>Potential Operation Disruption</span>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'remediation' && (
            <div className="report-text-section animate-fade-in">
              <div className="remediation-subsections">
                <div className="remedy-block">
                  <h3>Immediate Incident Response Actions</h3>
                  {report.immediate_actions?.length > 0 ? (
                    <ul className="remediation-list check-list">
                      {report.immediate_actions.map((act, i) => (
                        <li key={i}>{act}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>No actions specified.</p>
                  )}
                </div>

                <div className="remedy-block">
                  <h3>Long-Term Remediation & Hardening</h3>
                  {report.long_term_remediation?.length > 0 ? (
                    <ul className="remediation-list dot-list">
                      {report.long_term_remediation.map((rem, i) => (
                        <li key={i}>{rem}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>No remediation specified.</p>
                  )}
                </div>

                <div className="remedy-block">
                  <h3>Defensive Monitoring Recommendations</h3>
                  {report.monitoring?.length > 0 ? (
                    <ul className="remediation-list search-list">
                      {report.monitoring.map((mon, i) => (
                        <li key={i}>{mon}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>No monitoring recommendations specified.</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
