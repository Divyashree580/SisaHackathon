import React from 'react';
import { 
  AlertOctagon, Flame, AlertTriangle, ShieldCheck, 
  Zap, User, Globe, HelpCircle, Activity 
} from 'lucide-react';

export default function RiskScoreGauge({ score, level, factors = [] }) {
  // SVG gauge constants
  const radius = 60;
  const strokeWidth = 8;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  // Determine colors and icons based on threat level
  const getLevelConfig = (lvl) => {
    switch (lvl?.toLowerCase()) {
      case 'critical':
        return {
          color: 'var(--color-critical)',
          glow: 'glow-critical',
          icon: Flame,
          label: 'CRITICAL THREAT'
        };
      case 'high':
        return {
          color: 'var(--color-high)',
          glow: 'glow-high',
          icon: AlertOctagon,
          label: 'HIGH RISK'
        };
      case 'medium':
        return {
          color: 'var(--color-medium)',
          glow: 'glow-medium',
          icon: AlertTriangle,
          label: 'MEDIUM RISK'
        };
      case 'low':
      default:
        return {
          color: 'var(--color-low)',
          glow: 'glow-low',
          icon: ShieldCheck,
          label: 'LOW RISK'
        };
    }
  };

  const config = getLevelConfig(level);
  const LevelIcon = config.icon;

  // Generate ticks around the dial for visual structure
  const ticks = [];
  const totalTicks = 32;
  for (let i = 0; i < totalTicks; i++) {
    const angle = (i / totalTicks) * 2 * Math.PI - Math.PI / 2;
    const innerRadius = radius - 8;
    const outerRadius = radius - 2;
    
    const x1 = 80 + innerRadius * Math.cos(angle);
    const y1 = 80 + innerRadius * Math.sin(angle);
    const x2 = 80 + outerRadius * Math.cos(angle);
    const y2 = 80 + outerRadius * Math.sin(angle);
    
    const isActive = (i / totalTicks) * 100 <= score;
    ticks.push({ x1, y1, x2, y2, isActive });
  }

  // Factor details mapper for visual richness
  const getFactorDetails = (name) => {
    const lowercaseName = name.toLowerCase();
    
    if (lowercaseName.includes('cvss') || lowercaseName.includes('severity')) {
      return {
        icon: AlertOctagon,
        desc: 'Vulnerability CVE base severity score matches critical index.',
        color: 'var(--color-critical)'
      };
    }
    if (lowercaseName.includes('exploit') || lowercaseName.includes('poc')) {
      return {
        icon: Flame,
        desc: 'Active proof-of-concept exploit codes are publicly published.',
        color: 'var(--color-high)'
      };
    }
    if (lowercaseName.includes('malware') || lowercaseName.includes('ransomware')) {
      return {
        icon: Zap,
        desc: 'Payload signatures match known automated malware/RAT strains.',
        color: 'var(--color-accent)'
      };
    }
    if (lowercaseName.includes('actor') || lowercaseName.includes('group')) {
      return {
        icon: User,
        desc: 'Adversarial behavior maps to attributed APT organization.',
        color: 'var(--color-medium)'
      };
    }
    if (lowercaseName.includes('ioc') || lowercaseName.includes('reputation') || lowercaseName.includes('tor')) {
      return {
        icon: Globe,
        desc: 'IP/DNS queries hit active blacklists or darknet nodes.',
        color: 'var(--color-medium)'
      };
    }
    return {
      icon: HelpCircle,
      desc: 'System event log matches heuristic threat correlation rules.',
      color: 'var(--color-low)'
    };
  };

  return (
    <div className="risk-score-card card full-width-card animate-fade-in" style={{ padding: '24px' }}>
      <div className="card-header">
        <h2>Risk Assessment Engine</h2>
        <span className="card-subtitle">Weighted and explainable scoring formula analysis</span>
      </div>

      <div className="risk-split-container">
        {/* Left Side: Visual Gauge & Status */}
        <div className="risk-gauge-panel">
          <div className="gauge-wrapper">
            <svg className="gauge-svg" width="160" height="160">
              <defs>
                <filter id="gauge-blur" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="5" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Base Background Track */}
              <circle
                className="gauge-bg"
                cx="80"
                cy="80"
                r={radius}
                strokeWidth={strokeWidth}
              />

              {/* Glowing active progress overlay */}
              <circle
                className="gauge-progress"
                cx="80"
                cy="80"
                r={radius}
                strokeWidth={strokeWidth}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                stroke={config.color}
                filter="url(#gauge-blur)"
                transform="rotate(-90 80 80)"
                style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
              />

              {/* Internal Dial Tick Marks */}
              {ticks.map((tick, idx) => (
                <line
                  key={idx}
                  x1={tick.x1}
                  y1={tick.y1}
                  x2={tick.x2}
                  y2={tick.y2}
                  stroke={tick.isActive ? config.color : 'var(--border-light)'}
                  strokeWidth={1.5}
                  strokeOpacity={tick.isActive ? 0.9 : 0.3}
                  style={{ transition: 'stroke 0.5s ease-in-out' }}
                />
              ))}
            </svg>
            <div className="gauge-content">
              <span className="gauge-score">{score}</span>
              <span className="gauge-total">/ 100</span>
            </div>
          </div>

          {/* Level Banner */}
          <div className="risk-level-banner" style={{ borderColor: config.color, background: `rgba(from ${config.color} r g b / 0.08)`, width: '100%', justifyContent: 'center' }}>
            <LevelIcon size={18} style={{ color: config.color }} />
            <span className="level-text" style={{ color: config.color }}>{config.label}</span>
          </div>

          <div className="risk-summary-text font-sans">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: 'var(--text-primary)' }}>
              <Activity size={14} className="text-cyan animate-pulse" />
              <strong style={{ fontSize: '0.85rem' }}>Pipeline Diagnostics</strong>
            </div>
            <p>Calculated index based on correlation of active network IOCs, CVE severity indicators, and threat intelligence attribution models.</p>
          </div>
        </div>

        {/* Right Side: Contributing Factors Grid */}
        <div className="risk-factors-panel font-sans">
          <h3>Weighted Contributing Factors</h3>
          {factors.length === 0 ? (
            <div className="no-factors card" style={{ textAlign: 'center', padding: '40px 10px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <ShieldCheck size={28} className="text-muted" style={{ margin: '0 auto' }} />
              <p style={{ color: 'var(--text-muted)' }}>No significant risk factors registered. System is operating normally.</p>
            </div>
          ) : (
            <div className="factors-grid">
              {factors.map((factor, index) => {
                const details = getFactorDetails(factor.name);
                const FactorIcon = details.icon;
                return (
                  <div key={index} className="factor-grid-card">
                    <div className="factor-header-row">
                      <div className="factor-title-meta">
                        <FactorIcon size={16} style={{ color: details.color }} />
                        <span className="factor-name-text" title={factor.name}>{factor.name}</span>
                      </div>
                      <span className="factor-points-badge font-mono" style={{ backgroundColor: `rgba(from ${config.color} r g b / 0.08)`, color: config.color }}>
                        +{factor.points} pts
                      </span>
                    </div>
                    
                    <p className="factor-desc-text">{details.desc}</p>
                    
                    <div className="progress-bar-container" style={{ height: '3px', background: 'var(--bg-primary)', border: 'none', borderRadius: '2px', marginTop: '4px' }}>
                      <div 
                        className="progress-bar" 
                        style={{ 
                          width: `${Math.min(100, (factor.points / 30) * 100)}%`, 
                          backgroundColor: details.color,
                          height: '100%',
                          borderRadius: '2px'
                        }}
                      ></div>
                    </div>
                  </div>
                );
              })}
              
              <div className="total-score-summary" style={{ borderLeft: `3px solid ${config.color}`, background: `rgba(from ${config.color} r g b / 0.03)` }}>
                <span className="total-label">AGGREGATED SCORE (MAX CAPPED):</span>
                <strong className="total-val font-mono" style={{ color: config.color }}>{score} / 100</strong>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
