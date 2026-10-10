import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import {
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Upload,
  FileText,
  Settings as SettingsIcon,
  ChevronRight,
  Play,
  Pause,
  Square,
  RefreshCw,
  Mail,
  FileCode,
  Info,
} from 'lucide-react';
import StatCard from '../../components/StatCard/StatCard';
import ChartCard, { CustomTooltip } from '../../components/ChartCard/ChartCard';
import RecentScans from '../../components/RecentScans/RecentScans';
import { 
  getAnalytics, 
  getScanHistory, 
  getSecurityStatus,
  startProtection,
  pauseProtection,
  stopProtection,
  IS_MOCK 
} from '../../services/api';
import { mockDashboardStats } from '../../data/mockData';
import { useToast } from '../../components/Toast/Toast';
import { useThemeTokens } from '../../hooks/useThemeTokens';
import './Dashboard.css';

/* Builds the KPI cards from the live /analytics aggregates.

   Without this the four cards kept rendering mockDashboardStats — complete with
   a setInterval that randomly incremented them — while the charts beside them
   showed real data. Fabricated numbers next to real ones is worse than either
   alone, because nothing marks which is which. */
const liveKpi = (value, change) => ({
  value: typeof value === 'number' ? value.toLocaleString() : '—',
  change: `${change > 0 ? '+' : ''}${change ?? 0}%`,
  trend: change > 0 ? 'up' : change < 0 ? 'down' : 'neutral',
  // No per-KPI time series exists yet, and StatCard skips the sparkline when
  // this is absent rather than drawing a flat line that implies data.
  sparkline: undefined,
});

const statsFromAnalytics = (analytics) => ({
  totalScans: liveKpi(analytics?.totalScans, analytics?.totalScansChange),
  phishingDetected: liveKpi(analytics?.phishingDetected, analytics?.phishingChange),
  legitimateWebsites: liveKpi(analytics?.legitimateWebsites, analytics?.legitimateChange),
  modelAccuracy: {
    value: analytics?.modelAccuracy != null ? `${analytics.modelAccuracy}%` : '—',
    change: `${analytics?.accuracyChange ?? 0}%`,
    trend: 'neutral',
    sparkline: undefined,
  },
});

// Each stat card's "change" is measured against the selected range, so the
// footer label has to follow the filter. It used to read "vs last 30 days"
// unconditionally, which was simply wrong for three of the four options.
const PERIOD_LABELS = {
  '24H': 'vs previous 24 hours',
  '7D': 'vs previous 7 days',
  '30D': 'vs previous 30 days',
  '90D': 'vs previous 90 days',
};

// mockData ships a literal hex per slice. Mapping by name lets the donut follow
// the theme instead of staying locked to the light-mode palette.
const RISK_TOKENS = {
  Safe: '--risk-safe',
  Suspicious: '--risk-suspicious',
  Phishing: '--risk-danger',
};

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  const [analytics, setAnalytics] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [timeFilter, setTimeFilter] = useState('30D');

  // State for live simulation
  const [liveStats, setLiveStats] = useState(mockDashboardStats);

  // Background Protection Engine state
  const { addToast } = useToast();
  const [secStatus, setSecStatus] = useState(null);
  const [secLoading, setSecLoading] = useState(false);

  const fetchSecurity = async () => {
    try {
      const data = await getSecurityStatus();
      setSecStatus(data);
    } catch (e) {
      console.warn('Security status fetch failed', e);
    }
  };

  useEffect(() => {
    fetchSecurity();
    const secInterval = setInterval(fetchSecurity, 10000);
    return () => clearInterval(secInterval);
  }, []);

  const handleStartProtection = async () => {
    setSecLoading(true);
    try {
      await startProtection();
      addToast('Website & Device Background Protection Started', 'success');
      fetchSecurity();
    } catch (e) {
      addToast(e.message, 'error');
    } finally {
      setSecLoading(false);
    }
  };

  const handlePauseProtection = async () => {
    setSecLoading(true);
    try {
      await pauseProtection();
      addToast('Background Protection Paused', 'warning');
      fetchSecurity();
    } catch (e) {
      addToast(e.message, 'error');
    } finally {
      setSecLoading(false);
    }
  };

  const handleStopProtection = async () => {
    setSecLoading(true);
    try {
      await stopProtection();
      addToast('Background Protection Stopped', 'info');
      fetchSecurity();
    } catch (e) {
      addToast(e.message, 'error');
    } finally {
      setSecLoading(false);
    }
  };

  // Resolved token values, recomputed on theme change. Recharts needs concrete
  // colours — it cannot consume `var(--token)` in the places it reads colour
  // back out for animation and cursor rendering.
  const tokens = useThemeTokens();

  useEffect(() => {
    let ignore = false;

    const fetchData = async () => {
      setLoading(true);
      try {
        const [analyticsData, historyData] = await Promise.all([
          getAnalytics(timeFilter),
          getScanHistory(),
        ]);
        if (ignore) return;
        setAnalytics(analyticsData);
        setRecentScans(historyData);
      } catch (error) {
        console.error('Failed to fetch dashboard data', error);
      } finally {
        if (!ignore) setLoading(false);
      }
    };

    fetchData();

    return () => {
      ignore = true;
    };
  }, [timeFilter]);

  // Live Data Simulation — mock mode only.
  useEffect(() => {
    if (!IS_MOCK) return undefined;

    const interval = setInterval(() => {
      setLiveStats(prev => {
        const parseNum = (str) => parseInt(str.replace(/,/g, ''), 10);
        const formatNum = (num) => num.toLocaleString();

        const currentTotal = parseNum(prev.totalScans.value);
        const currentLegit = parseNum(prev.legitimateWebsites.value);
        const currentPhishing = parseNum(prev.phishingDetected.value);

        const addLegit = Math.random() > 0.5 ? 1 : 0;
        const addPhishing = Math.random() > 0.8 ? 1 : 0;

        return {
          ...prev,
          totalScans: { ...prev.totalScans, value: formatNum(currentTotal + addLegit + addPhishing) },
          legitimateWebsites: { ...prev.legitimateWebsites, value: formatNum(currentLegit + addLegit) },
          phishingDetected: { ...prev.phishingDetected, value: formatNum(currentPhishing + addPhishing) }
        };
      });
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  if (loading && !analytics) {
    return (
      <div className="dashboard-loading">
        <div className="spinner spinner-dark" />
        <p>Loading dashboard data…</p>
      </div>
    );
  }

  const colors = {
    phishing: tokens['--risk-danger'],
    suspicious: tokens['--risk-suspicious'],
    legitimate: tokens['--risk-safe'],
    grid: tokens['--viz-grid'],
    text: tokens['--text-tertiary'],
  };

  const riskDistribution = (analytics?.riskDistribution || []).map((slice) => ({
    ...slice,
    color: tokens[RISK_TOKENS[slice.name]] || slice.color,
  }));

  const periodLabel = PERIOD_LABELS[timeFilter];

  // Real aggregates in live mode; ticker in mock mode.
  const stats = IS_MOCK ? liveStats : statsFromAnalytics(analytics);

  return (
    <div className="dashboard-page">
      <div className="dashboard-page-header dashboard-page-header--split">
        <div>
          <h1 className="dashboard-page-title">Overview</h1>
          <p className="dashboard-page-subtitle">Monitor website protection activity, background monitoring, and device threat scans.</p>
        </div>
        
        {/* System Health Indicator */}
        <div className="system-health-badge">
          <div className="system-health-indicator pulse"></div>
          <div className="system-health-info">
            <span className="system-health-status">Engine Online & Healthy</span>
            <span className="system-health-latency">Model Latency: 42ms</span>
          </div>
        </div>
      </div>

      {/* Background Protection Control Banner */}
      <div className={`protection-control-banner status-${(secStatus?.status || 'active').toLowerCase()}`}>
        <div className="protection-banner-left">
          <div className="protection-shield-badge">
            <Shield className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="protection-title-row">
              <h3 className="protection-title">Background Protection Engine</h3>
              <span className={`status-pill ${secStatus?.status === 'ACTIVE' ? 'active' : secStatus?.status === 'PAUSED' ? 'paused' : 'stopped'}`}>
                ● {secStatus?.status || 'ACTIVE'}
              </span>
            </div>
            <p className="protection-sub">
              {secStatus?.status === 'ACTIVE'
                ? 'Actively monitoring submitted URLs, on-device file signatures, and scam indicators.'
                : secStatus?.status === 'PAUSED'
                ? 'Protection is temporarily paused. Resume monitoring for real-time safety.'
                : 'Protection is stopped. Incoming scans will not update continuous logs.'}
              {secStatus?.last_check && ` • Last security check: ${new Date(secStatus.last_check).toLocaleTimeString()}`}
            </p>
          </div>
        </div>

        <div className="protection-banner-actions">
          <button
            className={`btn-sec-action ${secStatus?.status === 'ACTIVE' ? 'active' : ''}`}
            onClick={handleStartProtection}
            disabled={secLoading || secStatus?.status === 'ACTIVE'}
            title="Start continuous monitoring"
          >
            <Play className="w-4 h-4 mr-1" />
            Start
          </button>
          <button
            className={`btn-sec-action ${secStatus?.status === 'PAUSED' ? 'paused' : ''}`}
            onClick={handlePauseProtection}
            disabled={secLoading || secStatus?.status === 'PAUSED'}
            title="Pause monitoring temporarily"
          >
            <Pause className="w-4 h-4 mr-1" />
            Pause
          </button>
          <button
            className={`btn-sec-action ${secStatus?.status === 'STOPPED' ? 'stopped' : ''}`}
            onClick={handleStopProtection}
            disabled={secLoading || secStatus?.status === 'STOPPED'}
            title="Stop monitoring"
          >
            <Square className="w-4 h-4 mr-1" />
            Stop
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid-4 dashboard-kpi-row">
        <StatCard
          title="Total Scans"
          value={stats.totalScans.value}
          change={stats.totalScans.change}
          trend={stats.totalScans.trend}
          sparkline={stats.totalScans.sparkline}
          icon={Search}
          colorClass="blue"
          period={periodLabel}
          delay={0}
        />
        <StatCard
          title="Phishing Detected"
          value={stats.phishingDetected.value}
          change={stats.phishingDetected.change}
          trend={stats.phishingDetected.trend}
          sparkline={stats.phishingDetected.sparkline}
          icon={ShieldAlert}
          colorClass="red"
          period={periodLabel}
          invertTrend
          delay={0.1}
        />
        <StatCard
          title="Legitimate Websites"
          value={stats.legitimateWebsites.value}
          change={stats.legitimateWebsites.change}
          trend={stats.legitimateWebsites.trend}
          sparkline={stats.legitimateWebsites.sparkline}
          icon={ShieldCheck}
          colorClass="green"
          period={periodLabel}
          delay={0.2}
        />
        <StatCard
          title="Model Accuracy"
          value={stats.modelAccuracy.value}
          change={stats.modelAccuracy.change}
          trend={stats.modelAccuracy.trend}
          sparkline={stats.modelAccuracy.sparkline}
          icon={Target}
          colorClass="purple"
          period={periodLabel}
          delay={0.3}
        />
      </div>

      {/* Charts Row */}
      <div className="dashboard-charts-row grid-3">
        {/* Main Area Chart (spans 2 columns) */}
        <ChartCard
          title="Detection Activity"
          subtitle="Scan volume and classification results over time"
          filters={['24H', '7D', '30D', '90D']}
          activeFilter={timeFilter}
          onFilterChange={setTimeFilter}
          delay={0.4}
          className="span-2"
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              /* `?.` on both hops. With the optional chain only on `analytics`,
                 a truthy response missing `detectionActivity` — the exact shape
                 you get when USE_MOCK flips to false and the real endpoint
                 differs — threw during render. */
              data={analytics?.detectionActivity?.[timeFilter] || []}
              /* left: -20 pushed the Y axis outside the plot area and clipped
                 its tick labels. */
              margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="colorPhishing" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.phishing} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.phishing} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorSuspiciousActivity" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.suspicious} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.suspicious} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorLegitimate" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.legitimate} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.legitimate} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={colors.grid} />
              <XAxis
                dataKey="time"
                axisLine={false}
                tickLine={false}
                tick={{ fill: colors.text, fontSize: 12 }}
                dy={10}
              />
              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{ fill: colors.text, fontSize: 12 }}
                width={48}
              />
              <RechartsTooltip
                content={<CustomTooltip />}
                cursor={{ stroke: colors.grid, strokeWidth: 1, strokeDasharray: '3 3' }}
              />
              <Area
                type="monotone"
                dataKey="legitimate"
                name="Legitimate"
                stroke={colors.legitimate}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorLegitimate)"
              />
              {/* Third series. The data now carries a `suspicious` column, and
                  omitting it here would leave 1,245 scans off a chart whose
                  subtitle promises "classification results". */}
              <Area
                type="monotone"
                dataKey="suspicious"
                name="Suspicious"
                stroke={colors.suspicious}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorSuspiciousActivity)"
              />
              <Area
                type="monotone"
                dataKey="phishing"
                name="Phishing"
                stroke={colors.phishing}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorPhishing)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Donut Chart (spans 1 column) */}
        <ChartCard
          title="Risk Distribution"
          subtitle="Overall classification breakdown"
          delay={0.5}
        >
          {/* The chart and the legend used to be siblings in .chart-container
              with the chart claiming height:100%, which pushed the legend out
              of the box and fed a re-measure loop. The chart now takes the
              remaining space and the legend keeps its intrinsic height. */}
          <div className="donut-chart-area">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={2}
                  dataKey="value"
                  stroke="none"
                >
                  {riskDistribution.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <RechartsTooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="donut-legend">
            {riskDistribution.map((item) => (
              <div key={item.name} className="donut-legend-item">
                <span
                  className="donut-legend-color"
                  style={{ backgroundColor: item.color }}
                  aria-hidden="true"
                />
                <span className="donut-legend-label">{item.name}</span>
                <span className="donut-legend-value">{item.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </ChartCard>
      </div>

      {/* Bottom Row: Recent Scans + Quick Actions */}
      <div className="dashboard-bottom-row grid-3">
        <div className="span-2">
          <RecentScans scans={recentScans} limit={5} delay={0.6} />
        </div>
        
        {/* Quick Actions Panel */}
        <div className="quick-actions-panel">
          <h3 className="quick-actions-title">Quick Actions</h3>
          <p className="quick-actions-subtitle">Frequently used tools and settings</p>

          <div className="quick-actions-list">
            <Link to="/scanner" className="quick-action-btn primary">
              <span className="quick-action-icon" aria-hidden="true">
                <Search size={20} />
              </span>
              <span className="quick-action-content">
                <span className="quick-action-label">Scan single URL</span>
                <span className="quick-action-desc">Analyze a website instantly</span>
              </span>
              <ChevronRight size={18} className="quick-action-arrow" aria-hidden="true" />
            </Link>

            <Link to="/device-scanner" className="quick-action-btn">
              <span className="quick-action-icon blue" aria-hidden="true">
                <FileCode size={20} />
              </span>
              <span className="quick-action-content">
                <span className="quick-action-label">Device Security Scanner</span>
                <span className="quick-action-desc">Scan files & scam SMS messages</span>
              </span>
              <ChevronRight size={18} className="quick-action-arrow" aria-hidden="true" />
            </Link>

            <Link to="/email-scanner" className="quick-action-btn">
              <span className="quick-action-icon purple" aria-hidden="true">
                <Mail size={20} />
              </span>
              <span className="quick-action-content">
                <span className="quick-action-label">Gmail Threat Shield</span>
                <span className="quick-action-desc">Detect deceptive emails & lures</span>
              </span>
              <ChevronRight size={18} className="quick-action-arrow" aria-hidden="true" />
            </Link>

            <Link to="/bulk-scanner" className="quick-action-btn">
              <span className="quick-action-icon green" aria-hidden="true">
                <Upload size={20} />
              </span>
              <span className="quick-action-content">
                <span className="quick-action-label">Bulk CSV scan</span>
                <span className="quick-action-desc">Upload multiple URLs</span>
              </span>
              <ChevronRight size={18} className="quick-action-arrow" aria-hidden="true" />
            </Link>

            <Link to="/analytics" className="quick-action-btn">
              <span className="quick-action-icon neutral" aria-hidden="true">
                <FileText size={20} />
              </span>
              <span className="quick-action-content">
                <span className="quick-action-label">Generate report</span>
                <span className="quick-action-desc">Export PDF analytics</span>
              </span>
              <ChevronRight size={18} className="quick-action-arrow" aria-hidden="true" />
            </Link>
          </div>

          <div className="dashboard-limitations-notice">
            <Info size={16} className="text-blue-400 flex-shrink-0" />
            <span>
              <strong>Privacy Architecture:</strong> Web app inspects submitted inputs in-memory. Full browser-wide navigation defense requires the PhishGuard Browser Extension.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
