import React from 'react';
import { AlertOctagon, Flame, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function RiskScoreGauge({ score, level, factors = [] }) {
  // SVG gauge constants
  const radius = 60;
  const strokeWidth = 10;
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
            <circle
              className="gauge-bg"
              cx="80"
              cy="80"
              r={radius}
              strokeWidth={strokeWidth}
            />
            <circle
              className={`gauge-progress ${config.glow}`}
              cx="80"
              cy="80"
              r={radius}
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              stroke={config.color}
              transform="rotate(-90 80 80)"
            />
          </svg>
          <div className="gauge-content">
            <span className="gauge-score">{score}</span>
            <span className="gauge-total">/ 100</span>
          </div>
        </div>

        {/* Level Banner */}
        <div className="risk-level-banner" style={{ borderColor: config.color, background: `rgba(from ${config.color} r g b / 0.1)` }}>
          <LevelIcon size={20} style={{ color: config.color }} />
          <span className="level-text" style={{ color: config.color }}>{config.label}</span>
        </div>
      </div>

      {/* Itemized Factors */}
      <div className="risk-factors-section">
        <h3>Contributing Risk Factors</h3>
        {factors.length === 0 ? (
          <p className="no-factors">No significant risk factors detected.</p>
        ) : (
          <ul className="factors-list">
            {factors.map((factor, index) => (
              <li key={index} className="factor-item">
                <span className="factor-name">{factor.name}</span>
                <span className="factor-points font-mono">+{factor.points} pts</span>
              </li>
            ))}
            <li className="factor-item total-item">
              <strong>Total Score (Capped)</strong>
              <strong className="font-mono" style={{ color: config.color }}>{score} / 100</strong>
            </li>
          </ul>
        )}
      </div>
    </div>
  );
}
