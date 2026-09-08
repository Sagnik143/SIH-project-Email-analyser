/**
 * Dashboard Page
 * Overview with stats, charts, recent alerts, and threat map.
 */

import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Chart, registerables } from 'chart.js';
import { useEmail } from '../context/EmailContext';
import StatsCard from '../components/StatsCard';
import AlertCard from '../components/AlertCard';
import WorldMap from '../components/WorldMap';

Chart.register(...registerables);

export default function Dashboard() {
  const { analyzedEmails } = useEmail();
  const navigate = useNavigate();
  const timelineChartRef = useRef(null);
  const doughnutChartRef = useRef(null);
  const barChartRef = useRef(null);
  const timelineInstance = useRef(null);
  const doughnutInstance = useRef(null);
  const barInstance = useRef(null);

  const totalEmails = analyzedEmails.length;
  const threats = analyzedEmails.filter(e => e.threatAssessment?.threatScore >= 35);
  const criticalThreats = analyzedEmails.filter(e => e.threatAssessment?.threatScore >= 75);
  const avgScore = totalEmails > 0
    ? Math.round(analyzedEmails.reduce((sum, e) => sum + (e.threatAssessment?.threatScore || 0), 0) / totalEmails)
    : 0;

  // Collect all IPs from all analyses for the map
  const allIPs = analyzedEmails.flatMap(e => e.ipResults || []);

  // Category distribution
  const categories = {};
  analyzedEmails.forEach(e => {
    const cat = e.threatAssessment?.classification || 'unknown';
    categories[cat] = (categories[cat] || 0) + 1;
  });

  useEffect(() => {
    // Timeline Chart
    if (timelineChartRef.current) {
      if (timelineInstance.current) timelineInstance.current.destroy();

      const last7Days = Array.from({ length: 7 }, (_, i) => {
        const d = new Date();
        d.setDate(d.getDate() - (6 - i));
        return d.toLocaleDateString('en', { weekday: 'short' });
      });

      // Simulated data (with real data overlay if available)
      const baseData = [3, 5, 2, 8, 4, 6, totalEmails || 1];
      const threatData = [1, 2, 0, 4, 1, 3, threats.length || 0];

      timelineInstance.current = new Chart(timelineChartRef.current, {
        type: 'line',
        data: {
          labels: last7Days,
          datasets: [
            {
              label: 'Emails Analyzed',
              data: baseData,
              borderColor: '#2563eb',
              backgroundColor: 'rgba(37, 99, 235, 0.08)',
              fill: true,
              tension: 0.4,
              borderWidth: 2,
              pointRadius: 4,
              pointBackgroundColor: '#2563eb',
              pointBorderColor: '#ffffff',
              pointBorderWidth: 2,
            },
            {
              label: 'Threats Detected',
              data: threatData,
              borderColor: '#dc2626',
              backgroundColor: 'rgba(220, 38, 38, 0.06)',
              fill: true,
              tension: 0.4,
              borderWidth: 2,
              pointRadius: 4,
              pointBackgroundColor: '#dc2626',
              pointBorderColor: '#ffffff',
              pointBorderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'top',
              labels: { color: '#4a5568', font: { family: 'Inter', size: 11 }, usePointStyle: true, pointStyle: 'circle' },
            },
          },
          scales: {
            x: { grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { color: '#718096', font: { size: 11 } } },
            y: { grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { color: '#718096', font: { size: 11 } }, beginAtZero: true },
          },
        },
      });
    }

    // Doughnut Chart
    if (doughnutChartRef.current) {
      if (doughnutInstance.current) doughnutInstance.current.destroy();

      const catLabels = Object.keys(categories).length > 0
        ? Object.keys(categories)
        : ['Phishing', 'Spoofing', 'BEC', 'Legitimate', 'Suspicious'];
      const catData = Object.keys(categories).length > 0
        ? Object.values(categories)
        : [4, 2, 1, 8, 3];
      const catColors = catLabels.map(l => getCategoryColor(l));

      doughnutInstance.current = new Chart(doughnutChartRef.current, {
        type: 'doughnut',
        data: {
          labels: catLabels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
          datasets: [{
            data: catData,
            backgroundColor: catColors,
            borderColor: '#ffffff',
            borderWidth: 3,
            hoverOffset: 8,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#4a5568', font: { family: 'Inter', size: 11 }, usePointStyle: true, pointStyle: 'circle', padding: 12 },
            },
          },
        },
      });
    }

    // Bar Chart - Top Threat Domains
    if (barChartRef.current) {
      if (barInstance.current) barInstance.current.destroy();

      const domains = {};
      analyzedEmails.forEach(e => {
        const domain = e.parsed?.from?.email?.split('@')[1];
        if (domain && e.threatAssessment?.threatScore >= 30) {
          domains[domain] = (domains[domain] || 0) + 1;
        }
      });

      const topDomains = Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 6);
      const domainLabels = topDomains.length > 0
        ? topDomains.map(d => d[0])
        : ['secure-verify.xyz', 'microsft-login.com', 'invoice-services.top', 'ng-ministry.org', 'fake-bank.site'];
      const domainData = topDomains.length > 0
        ? topDomains.map(d => d[1])
        : [12, 8, 6, 4, 3];

      barInstance.current = new Chart(barChartRef.current, {
        type: 'bar',
        data: {
          labels: domainLabels,
          datasets: [{
            label: 'Threat Count',
            data: domainData,
            backgroundColor: 'rgba(220, 38, 38, 0.6)',
            borderColor: '#dc2626',
            borderWidth: 1,
            borderRadius: 6,
            barPercentage: 0.6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: { display: false },
          },
          scales: {
            x: { grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { color: '#718096', font: { size: 11 } }, beginAtZero: true },
            y: { grid: { display: false }, ticks: { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 } } },
          },
        },
      });
    }

    return () => {
      if (timelineInstance.current) timelineInstance.current.destroy();
      if (doughnutInstance.current) doughnutInstance.current.destroy();
      if (barInstance.current) barInstance.current.destroy();
    };
  }, [analyzedEmails]);

  return (
    <div>
      <div className="page-header">
        <h1>Dashboard</h1>
        <p>Your email security overview at a glance</p>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid section-gap stagger">
        <StatsCard
          icon="📧"
          value={totalEmails || '—'}
          label="Emails Scanned"
          trend={totalEmails > 0 ? `${totalEmails} total` : null}
          color="blue"
        />
        <StatsCard
          icon="🚨"
          value={threats.length || '—'}
          label="Threats Found"
          trend={threats.length > 0 ? `${Math.round(threats.length / Math.max(totalEmails, 1) * 100)}% rate` : null}
          trendDir="up"
          color="danger"
        />
        <StatsCard
          icon="⚡"
          value={criticalThreats.length || '—'}
          label="Urgent Alerts"
          color="warning"
        />
        <StatsCard
          icon="📊"
          value={avgScore || '—'}
          label="Risk Level"
          color={avgScore >= 50 ? 'danger' : avgScore >= 25 ? 'warning' : 'green'}
        />
      </div>

      {/* Charts Row */}
      <div className="grid-2 section-gap">
        <div className="glass-card chart-container no-hover">
          <h3>📈 Activity This Week</h3>
          <div className="chart-wrapper">
            <canvas ref={timelineChartRef}></canvas>
          </div>
        </div>

        <div className="glass-card chart-container no-hover">
          <h3>📊 Threat Types</h3>
          <div className="chart-wrapper">
            <canvas ref={doughnutChartRef}></canvas>
          </div>
        </div>
      </div>

      {/* Map + Alerts Row */}
      <div className="grid-2 section-gap">
        <div className="glass-card no-hover" style={{ padding: 'var(--space-lg)' }}>
          <h3 style={{ marginBottom: 'var(--space-md)', fontSize: '0.95rem', color: 'var(--text-secondary)', fontWeight: '600' }}>
            🌍 Where Threats Come From
          </h3>
          <WorldMap ipResults={allIPs} height="320px" showTrace={false} />
        </div>

        <div className="glass-card no-hover" style={{ padding: 'var(--space-lg)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-md)' }}>
            <h3 style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', fontWeight: '600' }}>
              🔔 Recent Scans
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/analyze')}>
              + Analyze New
            </button>
          </div>
          <div className="alert-list">
            {analyzedEmails.length > 0 ? (
              analyzedEmails.slice(0, 5).map(email => (
                <AlertCard key={email.id} analysis={email} />
              ))
            ) : (
              <div className="empty-state">
                <div className="empty-icon">🔍</div>
                <div className="empty-title">No emails scanned yet</div>
                <div className="empty-desc">
                  Start by scanning an email to see results here.
                </div>
                <button
                  className="btn btn-primary"
                  style={{ marginTop: '16px' }}
                  onClick={() => navigate('/analyze')}
                >
                  🔍 Scan First Email
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Threat Domains */}
      <div className="glass-card chart-container no-hover section-gap">
        <h3>🏴 Suspicious Domains</h3>
        <div className="chart-wrapper" style={{ height: '220px' }}>
          <canvas ref={barChartRef}></canvas>
        </div>
      </div>
    </div>
  );
}

function getCategoryColor(category) {
  const colors = {
    legitimate: '#059669',
    suspicious: '#d97706',
    phishing: '#dc2626',
    fraud: '#be185d',
    impersonation: '#7c3aed',
    malware: '#b91c1c',
    unknown: '#718096',
  };
  return colors[category?.toLowerCase()] || '#718096';
}
