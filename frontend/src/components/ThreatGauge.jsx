/**
 * Animated SVG Threat Gauge
 */

import { useEffect, useState } from 'react';

export default function ThreatGauge({ score = 0, size = 180, strokeWidth = 12 }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const duration = 1500;
    const startTime = Date.now();

    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(score * eased));

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [score]);

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (animatedScore / 100) * circumference;

  const getColor = (s) => {
    if (s >= 75) return '#dc2626';
    if (s >= 55) return '#ea580c';
    if (s >= 35) return '#d97706';
    if (s >= 15) return '#2563eb';
    return '#059669';
  };

  const getLabel = (s) => {
    if (s >= 75) return 'Dangerous';
    if (s >= 55) return 'Risky';
    if (s >= 35) return 'Caution';
    if (s >= 15) return 'Low Risk';
    return 'Safe';
  };

  const color = getColor(animatedScore);
  const center = size / 2;

  return (
    <div className="threat-gauge-container">
      <svg className="threat-gauge" width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Background circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="rgba(0, 0, 0, 0.06)"
          strokeWidth={strokeWidth}
        />

        {/* Glow effect */}
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Score arc */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform={`rotate(-90 ${center} ${center})`}
          filter="url(#glow)"
          style={{ transition: 'stroke-dashoffset 0.1s ease' }}
        />

        {/* Score text */}
        <text
          x={center}
          y={center - 8}
          textAnchor="middle"
          fill={color}
          fontSize="2.5rem"
          fontWeight="800"
          fontFamily="Inter, sans-serif"
        >
          {animatedScore}
        </text>

        {/* Label */}
        <text
          x={center}
          y={center + 20}
          textAnchor="middle"
          fill="rgba(0, 0, 0, 0.35)"
          fontSize="0.65rem"
          fontWeight="600"
          letterSpacing="0.1em"
          fontFamily="Inter, sans-serif"
        >
          {getLabel(animatedScore)}
        </text>
      </svg>
      <div className="threat-gauge-label">Risk Score</div>
    </div>
  );
}
