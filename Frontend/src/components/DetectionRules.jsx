import React, { useState } from 'react';
import { Terminal, Copy, Check, FileCode, Search } from 'lucide-react';

export default function DetectionRules({ rules = {} }) {
  const [activeTab, setActiveTab] = useState('sigma');
  const [copied, setCopied] = useState(false);

  const ruleTabs = [
    { id: 'sigma', name: 'Sigma Rule', icon: FileCode, code: rules.sigma, lang: 'yaml' },
    { id: 'yara', name: 'YARA Rule', icon: Terminal, code: rules.yara, lang: 'c' },
    { id: 'splunk', name: 'Splunk SPL', icon: Search, code: rules.splunk, lang: 'sql' },
    { id: 'kql', name: 'Sentinel KQL', icon: Search, code: rules.kql, lang: 'sql' }
  ];

  const currentRule = ruleTabs.find(t => t.id === activeTab);

  const handleCopy = () => {
    if (currentRule && currentRule.code) {
      navigator.clipboard.writeText(currentRule.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="detection-rules-card card">
      <div className="card-header">
        <div className="header-badge-row">
          <h2>SIEM & EDR Detection Rules</h2>
          <span className="badge badge-accent">Auto-compiled from IOCs</span>
        </div>
        <span className="card-subtitle">Deployable detection rules to locate threat activity in production environments</span>
      </div>

      <div className="rules-layout">
        {/* Rules Navigation */}
        <div className="rules-tabs">
          {ruleTabs.map(t => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                className={`rules-tab-btn ${activeTab === t.id ? 'active' : ''}`}
                onClick={() => { setActiveTab(t.id); setCopied(false); }}
                disabled={!t.code}
              >
                <Icon size={14} />
                <span>{t.name}</span>
              </button>
            );
          })}
        </div>

        {/* Code display block */}
        <div className="rules-code-block">
          <div className="code-header">
            <span className="code-file-label font-mono">
              detection_profile.{activeTab === 'sigma' ? 'yml' : activeTab === 'yara' ? 'yar' : 'spl'}
            </span>
            <button 
              className={`btn btn-secondary btn-small copy-btn ${copied ? 'copied' : ''}`}
              onClick={handleCopy}
              disabled={!currentRule?.code}
            >
              {copied ? (
                <>
                  <Check size={12} />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy size={12} />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>

          <div className="code-container font-mono">
            {currentRule && currentRule.code ? (
              <pre>
                <code>{currentRule.code}</code>
              </pre>
            ) : (
              <div className="code-empty">
                <span>No rule profile generated for this threat configuration.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
