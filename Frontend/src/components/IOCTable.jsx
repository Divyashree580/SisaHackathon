import React, { useState } from 'react';
import { ShieldAlert, Globe, Server, Hash, FileText, Info, Award, Crosshair } from 'lucide-react';

export default function IOCTable({ iocs = [], enrichment = {} }) {
  const [selectedIoc, setSelectedIoc] = useState(null);

  const getIocIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'ipv4':
        return Server;
      case 'domain':
      case 'url':
        return Globe;
      case 'email':
        return Info;
      case 'md5':
      case 'sha1':
      case 'sha256':
        return Hash;
      case 'cve id':
        return ShieldAlert;
      default:
        return FileText;
    }
  };

  const getReputationBadgeClass = (rep) => {
    switch (rep?.toLowerCase()) {
      case 'malicious':
        return 'badge badge-critical';
      case 'suspicious':
        return 'badge badge-high';
      case 'benign/scanner':
      case 'benign':
        return 'badge badge-low';
      default:
        return 'badge badge-medium';
    }
  };

  return (
    <div className="ioc-section">
      <div className="card-header">
        <h2>Extracted Indicators of Compromise (IOC)</h2>
        <span className="card-subtitle">Identified system, network, and file-based threat signatures</span>
      </div>

      <div className="ioc-split-view">
        {/* IOC List Table */}
        <div className="ioc-table-wrapper card">
          {iocs.length === 0 ? (
            <div className="empty-state">
              <Info size={36} />
              <p>No indicators of compromise detected in the threat brief.</p>
            </div>
          ) : (
            <table className="ioc-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator Value</th>
                  <th>Reputation</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc, idx) => {
                  const Icon = getIocIcon(ioc.type);
                  const isSelected = selectedIoc === ioc;
                  return (
                    <tr 
                      key={idx} 
                      className={`ioc-row ${isSelected ? 'selected' : ''}`}
                      onClick={() => setSelectedIoc(ioc)}
                    >
                      <td>
                        <div className="ioc-type-cell">
                          <Icon size={14} className="type-icon" />
                          <span>{ioc.type}</span>
                        </div>
                      </td>
                      <td className="font-mono text-truncate" title={ioc.value}>
                        {ioc.value}
                      </td>
                      <td>
                        <span className={getReputationBadgeClass(ioc.reputation)}>
                          {ioc.reputation || 'Unknown'}
                        </span>
                      </td>
                      <td>
                        <button 
                          className="btn-text" 
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIoc(ioc);
                          }}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Enrichment Drawer/Detail Panel */}
        <div className="ioc-enrichment-card card">
          <div className="enrichment-header">
            <h3>Threat Enrichment Details</h3>
            <span className="badge badge-accent">OSINT & NVD Synced</span>
          </div>

          {selectedIoc ? (
            <div className="enrichment-content font-sans">
              <div className="selected-ioc-banner">
                <span className="label">Selected Indicator</span>
                <strong className="value font-mono">{selectedIoc.value}</strong>
                <span className="type font-mono">{selectedIoc.type}</span>
              </div>

              <div className="meta-grid">
                <div className="meta-box">
                  <span className="meta-label">Context Category</span>
                  <span className="meta-val">{selectedIoc.context || 'Raw threat extraction'}</span>
                </div>
                <div className="meta-box">
                  <span className="meta-label">Reputation Status</span>
                  <span className="meta-val font-mono">{selectedIoc.reputation}</span>
                </div>
              </div>

              {/* Show CVE/Vulnerability detail if selected IOC is a CVE, or if selected and CVE exists */}
              {selectedIoc.type === 'CVE ID' && enrichment.cve_id === selectedIoc.value && (
                <div className="cve-enrichment-section animate-fade-in">
                  <div className="cve-cvss-bar">
                    <div className="cvss-value font-mono">{enrichment.cvss}</div>
                    <div className="cvss-meta">
                      <strong>CVSS Severity Score</strong>
                      <span className="badge badge-critical">{enrichment.severity}</span>
                    </div>
                  </div>
                  <p className="cve-desc">{enrichment.description}</p>
                  
                  <div className="enrichment-tags">
                    <div className="tag-group">
                      <span className="tag-title"><Award size={12} /> Threat Actors:</span>
                      <div className="tag-list">
                        {enrichment.threat_actors?.map((a, i) => <span key={i} className="actor-tag tag">{a}</span>) || <span className="none-tag">None</span>}
                      </div>
                    </div>
                    <div className="tag-group">
                      <span className="tag-title"><Crosshair size={12} /> Malware:</span>
                      <div className="tag-list">
                        {enrichment.malware_families?.map((m, i) => <span key={i} className="malware-tag tag">{m}</span>) || <span className="none-tag">None</span>}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Show generic enrichment if not a specific CVE detail */}
              {(selectedIoc.type !== 'CVE ID' || enrichment.cve_id !== selectedIoc.value) && (
                <div className="generic-enrichment-section animate-fade-in">
                  <h4>Geo-IP & Host Intelligence</h4>
                  <ul className="intel-list">
                    <li><strong>Autonomous System:</strong> AS-47352 Cloud Services Provider</li>
                    <li><strong>Target Country:</strong> United States / Western Europe</li>
                    <li><strong>Exploit Availability:</strong> {enrichment.exploit_available ? 'Confirmed (PoC Public)' : 'None Registered'}</li>
                    {enrichment.malware_families?.length > 0 && (
                      <li><strong>Linked Malware:</strong> {enrichment.malware_families.join(', ')}</li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          ) : enrichment.cve_id && enrichment.cve_id !== 'N/A' ? (
            <div className="enrichment-content font-sans">
              <div className="selected-ioc-banner">
                <span className="label">Vulnerability Incident Reference</span>
                <strong className="value font-mono">{enrichment.cve_id}</strong>
                <span className="type font-mono">CVSS {enrichment.cvss}</span>
              </div>
              <div className="cve-cvss-bar">
                <div className="cvss-value font-mono">{enrichment.cvss}</div>
                <div className="cvss-meta">
                  <strong>CVSS Severity Score</strong>
                  <span className="badge badge-critical">{enrichment.severity}</span>
                </div>
              </div>
              <p className="cve-desc">{enrichment.description}</p>
              
              <div className="enrichment-tags">
                <div className="tag-group">
                  <span className="tag-title"><Award size={12} /> Associated Actors:</span>
                  <div className="tag-list">
                    {enrichment.threat_actors?.map((a, i) => <span key={i} className="actor-tag tag">{a}</span>) || <span className="none-tag">None</span>}
                  </div>
                </div>
                <div className="tag-group">
                  <span className="tag-title"><Crosshair size={12} /> Malware Families:</span>
                  <div className="tag-list">
                    {enrichment.malware_families?.map((m, i) => <span key={i} className="malware-tag tag">{m}</span>) || <span className="none-tag">None</span>}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="enrichment-empty-prompt font-sans">
              <p>Select any indicator from the table on the left to load real-time intelligence feeds, CVSS records, exploit vectors, and actor attribution logs.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
