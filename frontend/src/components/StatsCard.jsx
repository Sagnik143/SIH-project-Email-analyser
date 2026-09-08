/**
 * Stats Card Component
 */

export default function StatsCard({ icon, value, label, trend, trendDir, color = 'blue' }) {
  return (
    <div className="glass-card stat-card animate-fade-in">
      <div className={`stat-icon ${color}`}>
        {icon}
      </div>
      <div className="stat-info">
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
        {trend && (
          <div className={`stat-trend ${trendDir || 'up'}`}>
            {trendDir === 'up' ? '↑' : '↓'} {trend}
          </div>
        )}
      </div>
    </div>
  );
}
