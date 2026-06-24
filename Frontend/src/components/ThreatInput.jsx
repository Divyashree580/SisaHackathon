import React, { useState } from 'react';
import { Upload, FileText, Play, Check, AlertTriangle } from 'lucide-react';
import { SEED_SCENARIOS } from '../services/api';

export default function ThreatInput({ onAnalyze, loading }) {
  const [inputType, setInputType] = useState('text'); // 'text' | 'file'
  const [content, setContent] = useState('');
  const [file, setFile] = useState(null);
  const [selectedPreset, setSelectedPreset] = useState('');
  const [options, setOptions] = useState({
    mitre_mapping: true,
    generate_rules: true,
    risk_scoring: true
  });

  const handlePresetChange = (e) => {
    const val = e.target.value;
    setSelectedPreset(val);
    if (val) {
      const preset = SEED_SCENARIOS.find(s => s.id === val);
      if (preset) {
        setInputType(preset.inputType);
        setContent(preset.content);
        if (preset.inputType === 'file') {
          setFile({ name: 'invoice_v9.2.exe', size: 1450000 });
        } else {
          setFile(null);
        }
      }
    } else {
      setContent('');
      setFile(null);
    }
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      setSelectedPreset('');
      
      // Load file content as text
      const reader = new FileReader();
      reader.onload = (evt) => {
        setContent(evt.target.result);
      };
      reader.readAsText(selectedFile);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (inputType === 'text' && !content.trim()) return;
    if (inputType === 'file' && !file) return;

    onAnalyze({
      content,
      file,
      inputType,
      selectedPresetId: selectedPreset || null,
      options
    });
  };

  const handleOptionToggle = (key) => {
    setOptions(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="threat-input-card card">
      <div className="card-header">
        <h2>Threat Assessment Hub</h2>
        <span className="card-subtitle">Ingest security data, documents, or CVEs for analysis</span>
      </div>

      <form onSubmit={handleSubmit} className="input-form">
        {/* Preset Selector */}
        <div className="form-group">
          <label htmlFor="preset-select">Select Demo Preset Scenario</label>
          <select 
            id="preset-select" 
            value={selectedPreset} 
            onChange={handlePresetChange}
            className="select-input"
          >
            <option value="">-- Start Custom Analysis or Select Preset --</option>
            {SEED_SCENARIOS.map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </div>

        {/* Input Type Toggles */}
        <div className="input-tabs">
          <button 
            type="button" 
            className={`input-tab ${inputType === 'text' ? 'active' : ''}`}
            onClick={() => { setInputType('text'); setSelectedPreset(''); }}
          >
            <FileText size={16} />
            <span>Raw Report / CVE ID</span>
          </button>
          <button 
            type="button" 
            className={`input-tab ${inputType === 'file' ? 'active' : ''}`}
            onClick={() => { setInputType('file'); setSelectedPreset(''); }}
          >
            <Upload size={16} />
            <span>Upload Artifact</span>
          </button>
        </div>

        {/* Dynamic Input Fields */}
        {inputType === 'text' ? (
          <div className="form-group">
            <textarea
              value={content}
              onChange={(e) => { setContent(e.target.value); setSelectedPreset(''); }}
              placeholder="Paste raw threat intelligence report, CVE reference (e.g. CVE-2023-4966), network logs, or list of suspicious IPs/domains..."
              rows={8}
              className="textarea-input"
              required
            />
          </div>
        ) : (
          <div className="file-dropzone">
            <input 
              type="file" 
              id="file-upload" 
              accept=".pdf,.doc,.docx,.txt,.csv,.json,.exe" 
              onChange={handleFileChange}
              style={{ display: 'none' }}
            />
            <label htmlFor="file-upload" className="dropzone-label">
              <Upload size={32} className="dropzone-icon" />
              {file ? (
                <div className="file-details">
                  <span className="file-name">{file.name}</span>
                  <span className="file-size">({(file.size / 1024).toFixed(1)} KB)</span>
                </div>
              ) : (
                <div className="dropzone-text">
                  <strong>Click to upload</strong> or drag and drop
                  <span className="file-hint">PDF, DOCX, TXT, CSV, JSON, EXE (max 10MB)</span>
                </div>
              )}
            </label>
          </div>
        )}

        {/* Pipeline Options Toggle */}
        <div className="analysis-options">
          <label className="checkbox-container">
            <input 
              type="checkbox" 
              checked={options.risk_scoring} 
              onChange={() => handleOptionToggle('risk_scoring')}
            />
            <span className="checkmark" />
            <span className="checkbox-label">Calculate Risk Score</span>
          </label>
          <label className="checkbox-container">
            <input 
              type="checkbox" 
              checked={options.mitre_mapping} 
              onChange={() => handleOptionToggle('mitre_mapping')}
            />
            <span className="checkmark" />
            <span className="checkbox-label">Map to MITRE ATT&CK</span>
          </label>
          <label className="checkbox-container">
            <input 
              type="checkbox" 
              checked={options.generate_rules} 
              onChange={() => handleOptionToggle('generate_rules')}
            />
            <span className="checkmark" />
            <span className="checkbox-label">Generate Detection Rules</span>
          </label>
        </div>

        {/* Action Button */}
        <button 
          type="submit" 
          disabled={loading || (inputType === 'text' && !content) || (inputType === 'file' && !file)}
          className="btn btn-primary"
        >
          {loading ? (
            <>
              <div className="spinner" />
              <span>Analyzing Threat Pipeline...</span>
            </>
          ) : (
            <>
              <Play size={16} />
              <span>Run Intelligence Engine</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
}
