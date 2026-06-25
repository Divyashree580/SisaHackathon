import React, { useState, useEffect } from 'react';
import { 
  Terminal, Clipboard, Download, Edit3, Check, Save, Undo,
  FileCode2, ShieldAlert, BookOpen, AlertCircle
} from 'lucide-react';
import { saveHistoryToStorage, loadHistoryFromStorage } from '../services/api';

export default function RuleEngineHub({ history = [], activeAnalysis, onSelectThreat, onUpdateHistory }) {
  const [selectedId, setSelectedId] = useState('');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [activeFormat, setActiveFormat] = useState('sigma'); // 'sigma' | 'yara' | 'splunk' | 'kql'
  const [copied, setCopied] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editedCode, setEditedCode] = useState('');

  // Sync with activeAnalysis or history selection
  useEffect(() => {
    if (activeAnalysis) {
      setSelectedId(activeAnalysis.analysis_id);
      setSelectedThreat(activeAnalysis);
    } else if (history.length > 0 && !selectedId) {
      setSelectedId(history[0].analysis_id);
      setSelectedThreat(history[0]);
    }
  }, [activeAnalysis, history]);

  // Sync code content when selection or tab changes
  useEffect(() => {
    if (selectedThreat) {
      const code = selectedThreat.detection_rules?.[activeFormat] || '';
      setEditedCode(code);
      setIsEditing(false);
    } else {
      setEditedCode('');
    }
  }, [selectedThreat, activeFormat]);

  const handleThreatChange = (e) => {
    const id = e.target.value;
    setSelectedId(id);
    const threat = history.find(h => h.analysis_id === id);
    setSelectedThreat(threat || null);
    if (threat) {
      onSelectThreat(threat); // Sync parent state
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(editedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!selectedThreat) return;
    
    let extension = 'txt';
    let mimeType = 'text/plain';
    
    if (activeFormat === 'sigma') {
      extension = 'yml';
      mimeType = 'application/x-yaml';
    } else if (activeFormat === 'yara') {
      extension = 'yar';
    } else if (activeFormat === 'kql') {
      extension = 'kql';
    }

    const blob = new Blob([editedCode], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    
    // Construct descriptive filename
    const threatName = (selectedThreat.presetName || 'threat')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_');
    
    link.download = `sentinel_${threatName}_rule.${extension}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleSaveRule = () => {
    if (!selectedThreat) return;
    
    // Update local object
    const updatedThreat = {
      ...selectedThreat,
      detection_rules: {
        ...selectedThreat.detection_rules,
        [activeFormat]: editedCode
      }
    };
    
    setSelectedThreat(updatedThreat);
    
    // Update parent list
    const newHistory = history.map(h => 
      h.analysis_id === updatedThreat.analysis_id ? updatedThreat : h
    );
    
    onUpdateHistory(newHistory);
    saveHistoryToStorage(newHistory);
    setIsEditing(false);
  };

  const handleRevertRule = () => {
    if (selectedThreat) {
      setEditedCode(selectedThreat.detection_rules?.[activeFormat] || '');
      setIsEditing(false);
    }
  };

  const getFormatLabel = (fmt) => {
    switch (fmt) {
      case 'sigma': return 'Sigma (SIEM Generic)';
      case 'yara': return 'YARA (Static Malware)';
      case 'splunk': return 'Splunk search SPL';
      case 'kql': return 'KQL (Defender / Sentinel)';
      default: return fmt.toUpperCase();
    }
  };

  return (
    <div className="rules-hub-view animate-fade-in">
      {/* Header */}
      <div className="overview-header">
        <div>
          <h1 className="overview-title">Detection Rule Workstation</h1>
          <p className="overview-subtitle">Customize, download, and export Sigma, YARA, Splunk, and KQL rules</p>
        </div>
      </div>

      {/* Threat Input Context box */}
      {selectedThreat && (
        <div className="analysis-input-context animate-fade-in" style={{
          marginBottom: '20px',
          padding: '12px 16px',
          backgroundColor: 'var(--bg-secondary)',
          borderLeft: '4px solid var(--color-medium)',
          borderRadius: 'var(--radius-sm)',
          fontSize: '0.85rem',
          color: 'var(--text-secondary)',
          lineHeight: '1.4',
          border: '1px solid var(--border-light)',
          borderLeftWidth: '4px'
        }}>
          <span style={{ 
            display: 'block', 
            fontSize: '0.75rem', 
            fontWeight: '700', 
            color: 'var(--color-medium)',
            textTransform: 'uppercase', 
            letterSpacing: '0.05em', 
            marginBottom: '4px' 
          }}>
            Threat Input Rule Context:
          </span>
          "{selectedThreat.raw_input || 'N/A'}"
        </div>
      )}

      <div className="rules-hub-layout">
        {/* Left Options Controller */}
        <div className="rules-controller card">
          <div className="card-header">
            <h3>Incident Target Selection</h3>
            <span className="card-subtitle">Choose a threat context to extract rule parameters</span>
          </div>

          <div className="form-group">
            <label htmlFor="rule-threat-select">Target Threat Report</label>
            <select
              id="rule-threat-select"
              value={selectedId}
              onChange={handleThreatChange}
              className="select-input"
            >
              {history.length === 0 && <option value="">-- No reports analyzed yet --</option>}
              {history.map(h => (
                <option key={h.analysis_id} value={h.analysis_id}>
                  {h.presetName || (h.input_type === 'file' ? 'Artifact Document' : 'Manual Paste')} ({h.risk_level})
                </option>
              ))}
            </select>
          </div>

          {selectedThreat && (
            <div className="rules-threat-metadata font-sans">
              <div className="meta-box">
                <span className="meta-label">Selected Threat</span>
                <span className="meta-value text-cyan font-mono" style={{ fontSize: '0.85rem' }}>{selectedThreat.analysis_id}</span>
              </div>
              
              <div className="meta-box">
                <span className="meta-label">Risk Profile</span>
                <span className="meta-value" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                  <span className={`badge ${selectedThreat.risk_level?.toLowerCase() === 'critical' ? 'badge-critical' : selectedThreat.risk_level?.toLowerCase() === 'high' ? 'badge-high' : 'badge-medium'}`}>
                    {selectedThreat.risk_level} ({selectedThreat.risk_score})
                  </span>
                </span>
              </div>

              {selectedThreat.iocs?.length > 0 && (
                <div className="meta-box">
                  <span className="meta-label">Extracted Network/File Indicators</span>
                  <div className="rules-ioc-list font-mono">
                    {selectedThreat.iocs.slice(0, 4).map((ioc, idx) => (
                      <span key={idx} className="rules-ioc-pill" title={ioc.value}>
                        {ioc.type}: {ioc.value.length > 20 ? ioc.value.substring(0, 17) + '...' : ioc.value}
                      </span>
                    ))}
                    {selectedThreat.iocs.length > 4 && (
                      <span className="rules-ioc-pill text-muted">+{selectedThreat.iocs.length - 4} more</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Editor Screen */}
        <div className="rules-editor-panel card">
          {selectedThreat ? (
            <>
              {/* Code Editor Header & Controls */}
              <div className="editor-nav-header">
                <div className="rules-tabs">
                  {['sigma', 'yara', 'splunk', 'kql'].map((fmt) => (
                    <button
                      key={fmt}
                      className={`rules-tab-btn ${activeFormat === fmt ? 'active' : ''}`}
                      onClick={() => {
                        setActiveFormat(fmt);
                      }}
                    >
                      <FileCode2 size={14} />
                      <span>{fmt.toUpperCase()}</span>
                    </button>
                  ))}
                </div>

                <div className="editor-action-buttons">
                  {isEditing ? (
                    <>
                      <button 
                        onClick={handleSaveRule} 
                        className="btn btn-secondary btn-small text-green"
                        style={{ borderColor: 'rgba(0, 255, 159, 0.2)' }}
                      >
                        <Save size={14} />
                        <span>Save Change</span>
                      </button>
                      <button 
                        onClick={handleRevertRule} 
                        className="btn btn-secondary btn-small"
                      >
                        <Undo size={14} />
                        <span>Discard</span>
                      </button>
                    </>
                  ) : (
                    <button 
                      onClick={() => setIsEditing(true)} 
                      className="btn btn-secondary btn-small"
                    >
                      <Edit3 size={14} />
                      <span>Edit Rule</span>
                    </button>
                  )}

                  <button 
                    onClick={handleCopy} 
                    className="btn btn-secondary btn-small"
                    title="Copy rule to clipboard"
                    disabled={!editedCode}
                  >
                    {copied ? <Check size={14} className="text-green" /> : <Clipboard size={14} />}
                    <span>{copied ? 'Copied!' : 'Copy'}</span>
                  </button>

                  <button 
                    onClick={handleDownload} 
                    className="btn btn-secondary btn-small"
                    title="Download rule file"
                    disabled={!editedCode}
                  >
                    <Download size={14} />
                    <span>Download</span>
                  </button>
                </div>
              </div>

              {/* Code Container */}
              <div className="editor-workspace">
                <div className="editor-filename font-mono text-muted">
                  {activeFormat === 'sigma' ? 'lockbit_rules.yml' : activeFormat === 'yara' ? 'malware_rule.yar' : 'splunk_query.spl'}
                </div>
                
                {isEditing ? (
                  <textarea
                    value={editedCode}
                    onChange={(e) => setEditedCode(e.target.value)}
                    className="code-textarea font-mono"
                    spellCheck="false"
                  />
                ) : editedCode ? (
                  <div className="code-container font-mono">
                    <pre><code>{editedCode}</code></pre>
                  </div>
                ) : (
                  <div className="code-empty">
                    <AlertCircle size={28} />
                    <p>No rule generated for this format.</p>
                  </div>
                )}
              </div>

              <div className="editor-footer-status">
                <Terminal size={12} className="text-cyan animate-pulse" />
                <span>Format: {getFormatLabel(activeFormat)}</span>
              </div>
            </>
          ) : (
            <div className="editor-empty-state">
              <ShieldAlert size={48} className="text-muted animate-pulse" />
              <h3>Workstation Locked</h3>
              <p>Please select an analyzed threat scenario or run a text/file scan to activate the rule editor interface.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
