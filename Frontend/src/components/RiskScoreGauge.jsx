import React from 'react';
import { AlertOctagon, Flame, AlertTriangle, ShieldCheck } from 'lucide-react';

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
  const totalTicks = 24;
  for (let i = 0; i < totalTicks; i++) {
    // 270 degrees total dial arc or 360 degree full ring
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

  return (
    <div className="risk-score-card card">
      <div className="card-header">
        <h2>Risk Assessment Engine</h2>
        <span className="card-subtitle">Weighted and explainable scoring formula analysis</span>
      </div>

      <div className="risk-display-container">
        {/* SVG Circular Gauge */}
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
        <div className="risk-level-banner" style={{ borderColor: config.color, background: `rgba(from ${config.color} r g b / 0.08)` }}>
          <LevelIcon size={18} style={{ color: config.color }} />
          <span className="level-text" style={{ color: config.color }}>{config.label}</span>
        </div>
      </div>

      {/* Itemized Factors */}
      <div className="risk-factors-section">
        <h3>Contributing Risk Factors</h3>
        {factors.length === 0 ? (
          <p className="no-factors">No significant risk factors detected.</p>
        ) : (
          <ul className="factors-list" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {factors.map((factor, index) => (
              <li key={index} className="factor-item" style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                  <span className="factor-name" style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{factor.name}</span>
                  <span className="factor-points font-mono" style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>+{factor.points} pts</span>
                </div>
                <div className="progress-bar-container" style={{ height: '3px', background: 'var(--bg-primary)', border: 'none', borderRadius: '2px' }}>
                  <div 
                    className="progress-bar" 
                    style={{ 
                      width: `${Math.min(100, (factor.points / 30) * 100)}%`, 
                      backgroundColor: config.color,
                      height: '100%',
                      borderRadius: '2px'
                    }}
                  ></div>
                </div>
              </li>
            ))}
            <li className="factor-item total-item" style={{ borderTop: '1px dashed var(--border-light)', paddingTop: '10px', marginTop: '4px', display: 'flex', justifyContent: 'space-between' }}>
              <strong>Total Aggregated Score</strong>
              <strong className="font-mono" style={{ color: config.color }}>{score} / 100</strong>
            </li>
          </ul>
        )}
      </div>
    </div>
  );
}
