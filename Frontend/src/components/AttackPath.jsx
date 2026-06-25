import React, { useEffect, useState } from 'react';
import { Crosshair, ChevronRight, Zap, Send, RotateCw } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

// Icons for different attack phases
const PHASE_ICONS = {
  'Reconnaissance': '🔍',
  'Weaponization': '⚔️',
  'Delivery': '📧',
  'Credential Harvest': '🔑',
  'VPN Access': '🌐',
  'Lateral Movement': '🔀',
  'Privilege Escalation': '⬆️',
  'Ransomware Deploy': '💀',
  'Exploitation': '🎯',
  'Exfiltration': '📤',
  'Persistence': '🔗',
  'Command and Control': '📡',
};

const PHASE_COLORS = [
  '#00f0ff',
  '#00ff9f',
  '#448AFF',
  '#ffaa00',
  '#ff6b35',
  '#ff3e3e',
  '#f000ff',
  '#cc0000',
];

function getPhaseIcon(phase) {
  for (const [key, icon] of Object.entries(PHASE_ICONS)) {
    if (phase.toLowerCase().includes(key.toLowerCase())) return icon;
  }
  return '🔹';
}

export default function AttackPath() {
  const [attackPath, setAttackPath] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [threatText, setThreatText] = useState('');
  const [isCustom, setIsCustom] = useState(false);

  const fetchDefaultPath = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/attack-path`);
      if (response.ok) {
        const data = await response.json();
        setAttackPath(data);
      } else {
        throw new Error(`API error: ${response.status}`);
      }
    } catch (e) {
      console.warn('Attack path API unavailable:', e);
      setError('Unable to load attack path. Make sure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const fetchCustomPath = async () => {
    if (!threatText.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/attack-path`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_text: threatText }),
      });
      if (response.ok) {
        const data = await response.json();
        setAttackPath(data);
      } else {
        throw new Error(`API error: ${response.status}`);
      }
    } catch (e) {
      console.warn('Attack path generation failed:', e);
      setError('Failed to generate attack path. Check your API key and try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDefaultPath();
  }, []);

  return (
    <div className="attack-path-container animate-fade-in">
      {/* Header */}
      <div className="card attack-path-header-card">
        <div className="card-header">
          <div className="attack-path-title-row">
            <Crosshair size={22} style={{ color: 'var(--color-critical)' }} />
            <div>
              <h2 className="card-title">Attack Path Prediction</h2>
              <p className="card-subtitle">AI-generated kill chain showing the full attack progression</p>
            </div>
          </div>
        </div>

        {/* Custom threat input */}
        <div className="attack-path-input-section">
          <button
            className={`btn btn-small ${isCustom ? 'btn-secondary' : 'btn-primary'}`}
            onClick={() => setIsCustom(!isCustom)}
            style={{ width: 'auto', marginBottom: isCustom ? 12 : 0 }}
          >
            {isCustom ? 'Hide Custom Input' : '✨ Generate Custom Path'}
          </button>

          {isCustom && (
            <div className="attack-path-input-group animate-fade-in">
              <textarea
                className="textarea-input"
                placeholder="Describe a threat scenario to generate a custom kill chain…"
                value={threatText}
                onChange={(e) => setThreatText(e.target.value)}
                rows={3}
              />
              <div className="attack-path-input-actions">
                <button
                  className="btn btn-primary"
                  style={{ width: 'auto' }}
                  onClick={fetchCustomPath}
                  disabled={loading || !threatText.trim()}
                >
                  {loading ? <div className="spinner" /> : <Send size={14} />}
                  <span>Generate Path</span>
                </button>
                <button
                  className="btn btn-secondary"
                  style={{ width: 'auto' }}
                  onClick={() => { setIsCustom(false); fetchDefaultPath(); }}
                >
                  <RotateCw size={14} />
                  <span>Reset to Default</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="card attack-path-loading">
          <div className="siem-loading-spinner">
            <div className="spinner" />
            <span>AI is generating the attack path…</span>
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="card error-card">
          <p>{error}</p>
          <button className="btn btn-small btn-secondary" onClick={fetchDefaultPath} style={{ marginTop: 12, width: 'auto' }}>
            <RotateCw size={14} /> Retry
          </button>
        </div>
      )}

      {/* Attack Path Timeline */}
      {!loading && attackPath && (
        <div className="attack-path-timeline-card card">
          <div className="attack-path-meta">
            <h3>{attackPath.title}</h3>
            <p>{attackPath.summary}</p>
          </div>

          <div className="attack-path-timeline">
            {attackPath.steps.map((step, index) => {
              const color = PHASE_COLORS[index % PHASE_COLORS.length];
              const icon = getPhaseIcon(step.phase);
              return (
                <div
                  key={step.step}
                  className="attack-step"
                  style={{
                    '--step-color': color,
                    animationDelay: `${index * 0.1}s`,
                  }}
                >
                  <div className="attack-step-connector">
                    <div className="step-dot" style={{ borderColor: color, boxShadow: `0 0 12px ${color}40` }}>
                      <span className="step-icon">{icon}</span>
                    </div>
                    {index < attackPath.steps.length - 1 && (
                      <div className="step-line" style={{ background: `linear-gradient(to bottom, ${color}60, ${PHASE_COLORS[(index + 1) % PHASE_COLORS.length]}60)` }} />
                    )}
                  </div>

                  <div className="attack-step-content">
                    <div className="step-header">
                      <span className="step-number" style={{ color }}>STEP {step.step}</span>
                      <span className="step-phase" style={{ color }}>{step.phase}</span>
                      {step.technique_id && (
                        <span className="step-technique-badge">{step.technique_id}</span>
                      )}
                    </div>
                    <p className="step-description">{step.description}</p>
                  </div>

                  {index < attackPath.steps.length - 1 && (
                    <div className="step-arrow">
                      <ChevronRight size={16} style={{ color: `${color}80` }} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
