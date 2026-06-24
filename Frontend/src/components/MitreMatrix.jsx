import React from 'react';
import { Target, ShieldAlert, Award } from 'lucide-react';

const MITRE_TACTICS_CATALOG = [
  {
    name: 'Reconnaissance',
    techniques: [
      { id: 'T1595', name: 'Active Scanning' },
      { id: 'T1589', name: 'Gather Victim Identity Info' },
      { id: 'T1592', name: 'Gather Victim Host Info' }
    ]
  },
  {
    name: 'Initial Access',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application' },
      { id: 'T1566', name: 'Phishing' },
      { id: 'T1566.001', name: 'Spearphishing Attachment' },
      { id: 'T1195.002', name: 'Software Dependency Compromise' }
    ]
  },
  {
    name: 'Execution',
    techniques: [
      { id: 'T1204', name: 'User Execution' },
      { id: 'T1204.002', name: 'Malicious File Execution' },
      { id: 'T1059', name: 'Command & Scripting Interpreter' },
      { id: 'T1203', name: 'Exploitation for Client Execution' }
    ]
  },
  {
    name: 'Defense Evasion',
    techniques: [
      { id: 'T1574.002', name: 'DLL Side-Loading' },
      { id: 'T1027', name: 'Obfuscated Files or Information' },
      { id: 'T1562', name: 'Impair Defenses' }
    ]
  },
  {
    name: 'Credential Access',
    techniques: [
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1110', name: 'Brute Force' }
    ]
  },
  {
    name: 'Command & Control',
    techniques: [
      { id: 'T1071', name: 'Application Layer Protocol' },
      { id: 'T1102', name: 'Web Service' },
      { id: 'T1573', name: 'Encrypted Channel' }
    ]
  },
  {
    name: 'Exfiltration',
    techniques: [
      { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
      { id: 'T1020', name: 'Automated Exfiltration' }
    ]
  },
  {
    name: 'Impact',
    techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact' },
      { id: 'T1485', name: 'Data Destruction' },
      { id: 'T1490', name: 'Inhibit System Recovery' }
    ]
  }
];

export default function MitreMatrix({ mapping = [] }) {
  // Check if a specific technique ID is mapped in the threat output
  const getMappedTechnique = (techId) => {
    return mapping.find(
      m => m.technique_id === techId || 
           techId.startsWith(m.technique_id) || 
           m.technique_id.startsWith(techId)
    );
  };

  const getConfidenceBadge = (confidence) => {
    switch (confidence?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'confidence-high';
      case 'medium':
        return 'confidence-medium';
      default:
        return 'confidence-low';
    }
  };

  return (
    <div className="mitre-card card">
      <div className="card-header">
        <h2>MITRE ATT&CK Mapping Matrix</h2>
        <span className="card-subtitle">AI-assisted correlation against standard adversarial tactics and techniques</span>
      </div>

      {/* MITRE ATT&CK Matrix Layout */}
      <div className="mitre-matrix-grid">
        {MITRE_TACTICS_CATALOG.map((tactic, tIdx) => {
          // Check if this tactic column has any active techniques
          const hasActiveInTactic = tactic.techniques.some(tech => getMappedTechnique(tech.id));
          return (
            <div key={tIdx} className={`tactic-column ${hasActiveInTactic ? 'tactic-active' : ''}`}>
              <div className="tactic-header">
                <h3>{tactic.name}</h3>
              </div>
              <div className="technique-list">
                {tactic.techniques.map((tech, techIdx) => {
                  const mapped = getMappedTechnique(tech.id);
                  return (
                    <div 
                      key={techIdx} 
                      className={`technique-box ${mapped ? 'active-technique' : ''}`}
                    >
                      <div className="tech-meta">
                        <span className="tech-id font-mono">{tech.id}</span>
                        {mapped && (
                          <span className={`confidence-dot ${getConfidenceBadge(mapped.confidence)}`} title={`Confidence: ${mapped.confidence || 'Medium'}`} />
                        )}
                      </div>
                      <span className="tech-name">{tech.name}</span>
                      {mapped && (
                        <div className="tech-popover">
                          <strong>Tactic:</strong> {mapped.tactic} <br />
                          <strong>Confidence:</strong> {mapped.confidence || 'High'}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      <div className="mitre-matrix-legend font-sans">
        <span className="legend-title">Mapping Confidence Legend:</span>
        <div className="legend-items">
          <span className="legend-item"><span className="confidence-dot confidence-high" /> High/Critical Confidence</span>
          <span className="legend-item"><span className="confidence-dot confidence-medium" /> Medium Confidence</span>
          <span className="legend-item"><span className="confidence-dot confidence-low" /> Active Adversary Path</span>
        </div>
      </div>
    </div>
  );
}
