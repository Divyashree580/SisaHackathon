import React, { useState } from 'react';
import { Search, Trash2, Calendar, FileText, Upload, AlertCircle } from 'lucide-react';

export default function HistoryList({ history = [], onSelect, onClear }) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredHistory = history.filter(item => {
    const term = searchTerm.toLowerCase();
    const typeMatch = item.input_type?.toLowerCase().includes(term);
    const idMatch = item.analysis_id?.toLowerCase().includes(term);
    const levelMatch = item.risk_level?.toLowerCase().includes(term);
    const summaryMatch = item.ai_report?.summary?.toLowerCase().includes(term);
    const nameMatch = item.presetName?.toLowerCase().includes(term);
    return typeMatch || idMatch || levelMatch || summaryMatch || nameMatch;
  });

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
      return date.toLocaleString();
    } catch (e) {
      return isoStr;
    }
  };

  return (
    <div className="history-card card">
      <div className="card-header history-header-row">
        <div>
          <h2>Analysis Audit Logs</h2>
          <span className="card-subtitle">Historical records of ingested threat intelligence and outputs</span>
        </div>
        <button 
          onClick={onClear} 
          className="btn btn-secondary btn-icon-only" 
          title="Clear History Audit Log"
          disabled={history.length === 0}
        >
          <Trash2 size={16} />
          <span>Reset History</span>
        </button>
      </div>

      <div className="history-search-bar">
        <Search size={16} className="search-icon" />
        <input
          type="text"
          placeholder="Search logs by risk level, IOC value, summary keywords..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
      </div>

      <div className="history-list-wrapper">
        {filteredHistory.length === 0 ? (
          <div className="empty-state">
            <AlertCircle size={36} />
            <p>{history.length === 0 ? "Audit logs are empty. Run a threat analysis to start logging." : "No records match search queries."}</p>
          </div>
        ) : (
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Analysis ID</th>
                  <th>Input Source</th>
                  <th>Risk Score</th>
                  <th>Threat Tier</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map((item) => (
                  <tr key={item.analysis_id} className="history-row">
                    <td>
                      <div className="timestamp-cell">
                        <Calendar size={12} className="meta-icon" />
                        <span>{formatDate(item.timestamp)}</span>
                      </div>
                    </td>
                    <td className="font-mono">{item.analysis_id}</td>
                    <td>
                      <div className="source-cell">
                        {item.input_type === 'file' ? <Upload size={12} /> : <FileText size={12} />}
                        <span className="source-text">{item.presetName || (item.input_type === 'file' ? 'Artifact File' : 'Text Paste')}</span>
                      </div>
                    </td>
                    <td className="font-mono font-bold">{item.risk_score}</td>
                    <td>
                      <span className={getRiskBadgeClass(item.risk_level)}>
                        {item.risk_level}
                      </span>
                    </td>
                    <td>
                      <button 
                        onClick={() => onSelect(item)} 
                        className="btn btn-secondary btn-small"
                      >
                        Load Record
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
