import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Palette,
  Bell,
  BrainCircuit,
  Server,
  Save,
  CheckCircle2,
  Moon,
  Sun,
  Monitor,
  ShieldCheck,
  Lock,
  Trash2,
  EyeOff,
  RefreshCw,
  KeyRound,
  ShieldAlert,
} from 'lucide-react';
import { useToast } from '../../components/Toast/Toast';
import { useTheme } from '../../context/ThemeContext';
import { useIsMounted } from '../../hooks/useIsMounted';
import { getPrivacyStatus, togglePrivacyMode, clearAllHistory } from '../../services/api';
import './Settings.css';

const TABS = [
  { id: 'privacy', label: 'Security & Privacy', icon: ShieldCheck },
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'model', label: 'ML Model', icon: BrainCircuit },
  { id: 'backend', label: 'Backend API', icon: Server },
  { id: 'notifications', label: 'Notifications', icon: Bell },
];

const THEME_OPTIONS = [
  { id: 'light', label: 'Light', icon: Sun },
  { id: 'dark', label: 'Dark', icon: Moon },
  { id: 'system', label: 'System', icon: Monitor },
];

const Settings = () => {
  const toast = useToast();
  const { preference, setPreference } = useTheme();
  const [activeTab, setActiveTab] = useState('privacy');
  const [isSaving, setIsSaving] = useState(false);
  const [privacyMode, setPrivacyMode] = useState(false);
  const [privacyLoading, setPrivacyLoading] = useState(false);
  const [purging, setPurging] = useState(false);
  const isMounted = useIsMounted();

  useEffect(() => {
    getPrivacyStatus()
      .then((st) => {
        if (isMounted()) setPrivacyMode(Boolean(st.privacy_mode));
      })
      .catch(() => {});
  }, [isMounted]);

  const handleTogglePrivacy = async (val) => {
    setPrivacyLoading(true);
    try {
      const res = await togglePrivacyMode(val);
      if (isMounted()) setPrivacyMode(res.privacy_mode);
      toast.success(
        res.privacy_mode
          ? 'Zero-Trace Privacy Mode activated: Scans will NOT be retained in history.'
          : 'Standard Mode: Scans recorded in temporary volatile history.',
        'Privacy Updated'
      );
    } catch (e) {
      toast.error(e.message || 'Failed to toggle privacy mode');
    } finally {
      if (isMounted()) setPrivacyLoading(false);
    }
  };

  const handlePurgeHistory = async () => {
    if (!window.confirm('Permanently purge all server and client session scan histories?')) return;
    setPurging(true);
    try {
      await clearAllHistory();
      toast.success('All scan histories, uploaded traces, and audit logs permanently purged.', 'Data Wiped');
    } catch (e) {
      toast.error(e.message || 'Could not purge history');
    } finally {
      if (isMounted()) setPurging(false);
    }
  };

  const [settings, setSettings] = useState({
    notifications: {
      scanComplete: true,
      threatDetection: true,
    },
    model: {
      current: 'random_forest',
      confidenceThreshold: 75,
    },
    backend: {
      apiUrl: import.meta.env.VITE_API_URL || 'http://localhost:5000',
      timeout: 30,
    },
  });

  const handleSave = async () => {
    setIsSaving(true);
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 800));
    // Leaving Settings within 800ms of clicking Save would otherwise pop
    // "Settings updated" on the next page.
    if (!isMounted()) return;
    setIsSaving(false);
    // Says what it actually did. Theme is persisted immediately by the provider;
    // the rest is not yet wired to a backend, so the copy no longer claims it is.
    toast.success('Preferences applied for this session.', 'Settings updated');
  };

  return (
    <div className="settings-page">
      <div className="dashboard-page-header">
        <h1 className="dashboard-page-title">Settings</h1>
        <p className="dashboard-page-subtitle">
          Configure system appearance, model parameters, and API connections.
        </p>
      </div>

      <div className="settings-container">
        {/* Tab navigation */}
        <div className="settings-sidebar" role="tablist" aria-label="Settings sections">
          {TABS.map((tab) => (
            <button
              type="button"
              key={tab.id}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`settings-panel-${tab.id}`}
              id={`settings-tab-${tab.id}`}
              className={`settings-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <tab.icon size={18} aria-hidden="true" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content Area */}
        <div className="settings-content">
          <motion.div
            key={activeTab}
            id={`settings-panel-${activeTab}`}
            role="tabpanel"
            aria-labelledby={`settings-tab-${activeTab}`}
            initial={{ opacity: 0, x: 10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            {activeTab === 'privacy' && (
              <section className="settings-section">
                <h2 className="settings-section-title">Security & Privacy Controls</h2>
                <p className="settings-section-desc">
                  Manage data protection policies, zero-trace scanning modes, and in-memory trace purging.
                </p>

                {/* Zero-Trace Incognito Mode */}
                <div className="settings-toggle-group">
                  <div className="settings-toggle-info">
                    <h3 className="settings-toggle-title">
                      Zero-Trace Incognito Mode
                    </h3>
                    <p className="settings-toggle-desc">
                      When active, scanned URLs, uploaded file names, scam messages, and emails are never recorded to server memory or history logs.
                    </p>
                  </div>
                  <label className="toggle-switch">
                    <span className="sr-only">Toggle zero trace privacy mode</span>
                    <input
                      type="checkbox"
                      checked={privacyMode}
                      disabled={privacyLoading}
                      onChange={(e) => handleTogglePrivacy(e.target.checked)}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>

                {/* Hardened Architecture Badges */}
                <div className="privacy-audit-card">
                  <h3 className="privacy-card-title">
                    <Lock size={16} /> Hardened Architecture Guarantees
                  </h3>
                  <div className="privacy-grid">
                    <div className="privacy-item">
                      <CheckCircle2 size={18} className="text-success" />
                      <div>
                        <strong>Strict Content Security Policy (CSP)</strong>
                        <p>Enforced HTTP response headers protect against cross-site scripting (XSS) and unauthorized script execution.</p>
                      </div>
                    </div>
                    <div className="privacy-item">
                      <CheckCircle2 size={18} className="text-success" />
                      <div>
                        <strong>Zero-Disk Storage Policy</strong>
                        <p>Uploaded files are inspected purely in volatile RAM buffers and instantly purged after analysis.</p>
                      </div>
                    </div>
                    <div className="privacy-item">
                      <CheckCircle2 size={18} className="text-success" />
                      <div>
                        <strong>SSRF & Loopback Isolation</strong>
                        <p>Active network gateway blocks requests targeting localhost, internal RFC1918 subnets, and cloud metadata (169.254.169.254).</p>
                      </div>
                    </div>
                    <div className="privacy-item">
                      <CheckCircle2 size={18} className="text-success" />
                      <div>
                        <strong>Anti-Clickjacking Framing Guard</strong>
                        <p>Enforces <code>X-Frame-Options: SAMEORIGIN</code> to prevent iframe hijacking and credential scraping.</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* One-Click History Purge */}
                <div className="purge-box">
                  <div className="purge-info">
                    <h3 className="purge-title">
                      <Trash2 size={16} className="text-danger" /> Permanent History Purge
                    </h3>
                    <p className="purge-desc">
                      Immediately wipe all URL scans, uploaded file records, message analyses, and email history from server memory and client cache.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="btn btn-outline-danger"
                    onClick={handlePurgeHistory}
                    disabled={purging}
                  >
                    {purging ? (
                      <>
                        <RefreshCw size={15} className="spinner" /> Purging…
                      </>
                    ) : (
                      <>
                        <Trash2 size={15} /> Purge All Session Data
                      </>
                    )}
                  </button>
                </div>
              </section>
            )}

            {activeTab === 'appearance' && (
              <section className="settings-section">
                <h2 className="settings-section-title">Appearance</h2>
                <p className="settings-section-desc">Customize the interface theme.</p>

                <div className="settings-group">
                  <p className="settings-label" id="theme-preference-label">
                    Theme preference
                  </p>
                  <div
                    className="theme-options"
                    role="radiogroup"
                    aria-labelledby="theme-preference-label"
                  >
                    {THEME_OPTIONS.map((option) => (
                      <button
                        type="button"
                        key={option.id}
                        role="radio"
                        aria-checked={preference === option.id}
                        className={`theme-option-card ${preference === option.id ? 'active' : ''}`}
                        onClick={() => setPreference(option.id)}
                      >
                        <option.icon size={24} className="theme-option-icon" aria-hidden="true" />
                        <span>{option.label}</span>
                      </button>
                    ))}
                  </div>
                  <p className="settings-hint">
                    System follows your operating system setting and updates when it changes.
                  </p>
                </div>
              </section>
            )}

            {activeTab === 'model' && (
              <section className="settings-section">
                <h2 className="settings-section-title">Machine Learning Model</h2>
                <p className="settings-section-desc">
                  Configure the active prediction model and thresholds.
                </p>

                <div className="settings-group">
                  <label className="settings-label" htmlFor="active-model">
                    Active model
                  </label>
                  {/* .select-field supplies the chevron that `appearance: none`
                      strips; .settings-input alone left a bare box. */}
                  <select
                    id="active-model"
                    className="select-field settings-input"
                    value={settings.model.current}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        model: { ...settings.model, current: e.target.value },
                      })
                    }
                  >
                    <option value="random_forest">Random Forest (Recommended)</option>
                    <option value="decision_tree">Decision Tree</option>
                    <option value="logistic_regression">Logistic Regression</option>
                  </select>
                </div>

                <div className="settings-group">
                  {/* Was an inline-styled flex div with a magic 8px margin. */}
                  <div className="settings-label-row">
                    <label className="settings-label" htmlFor="confidence-threshold">
                      Confidence threshold
                    </label>
                    {/* aria-live="off" because <output> carries an implicit
                        role="status". Without it, dragging the slider queues an
                        announcement for every integer between 50 and 99 — and
                        the range input already announces its own value. */}
                    <output
                      className="settings-value"
                      htmlFor="confidence-threshold"
                      aria-live="off"
                    >
                      {settings.model.confidenceThreshold}%
                    </output>
                  </div>
                  <input
                    id="confidence-threshold"
                    type="range"
                    min="50"
                    max="99"
                    className="settings-range"
                    value={settings.model.confidenceThreshold}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        model: {
                          ...settings.model,
                          // Number(), not the raw string. The field was seeded
                          // as 75 and then overwritten with "75", so any
                          // arithmetic on it would concatenate.
                          confidenceThreshold: Number(e.target.value),
                        },
                      })
                    }
                  />
                  <p className="settings-hint">
                    Predictions below this confidence level will be marked as Suspicious rather
                    than Legitimate or Phishing.
                  </p>
                </div>
              </section>
            )}

            {activeTab === 'backend' && (
              <section className="settings-section">
                <h2 className="settings-section-title">Backend API</h2>
                <p className="settings-section-desc">
                  Configure connection settings for the Machine Learning inference API.
                </p>

                <div className="api-status-card connected">
                  <span className="api-status-icon" aria-hidden="true">
                    <CheckCircle2 size={24} />
                  </span>
                  <div>
                    <h3 className="api-status-title">API connected</h3>
                    <p className="api-status-desc">
                      Currently using mock data for frontend demonstration.
                    </p>
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-label" htmlFor="api-url">
                    API endpoint URL
                  </label>
                  <input
                    id="api-url"
                    type="url"
                    className="settings-input"
                    value={settings.backend.apiUrl}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        backend: { ...settings.backend, apiUrl: e.target.value },
                      })
                    }
                  />
                </div>

                <div className="settings-group">
                  <label className="settings-label" htmlFor="api-timeout">
                    Request timeout (seconds)
                  </label>
                  <input
                    id="api-timeout"
                    type="number"
                    min="1"
                    max="300"
                    className="settings-input"
                    value={settings.backend.timeout}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        backend: { ...settings.backend, timeout: Number(e.target.value) },
                      })
                    }
                  />
                </div>
              </section>
            )}

            {activeTab === 'notifications' && (
              <section className="settings-section">
                <h2 className="settings-section-title">Notifications</h2>
                <p className="settings-section-desc">
                  Manage system alerts and toast notifications.
                </p>

                <div className="settings-toggle-group">
                  <div className="settings-toggle-info">
                    <h3 className="settings-toggle-title">Scan complete</h3>
                    <p className="settings-toggle-desc">
                      Show a notification when a URL scan finishes successfully.
                    </p>
                  </div>
                  <label className="toggle-switch">
                    <span className="sr-only">Notify when a scan completes</span>
                    <input
                      type="checkbox"
                      checked={settings.notifications.scanComplete}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          notifications: {
                            ...settings.notifications,
                            scanComplete: e.target.checked,
                          },
                        })
                      }
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>

                <div className="settings-toggle-group">
                  <div className="settings-toggle-info">
                    <h3 className="settings-toggle-title">High risk threats</h3>
                    <p className="settings-toggle-desc">
                      Alert immediately if a high-risk phishing site is detected during bulk scans.
                    </p>
                  </div>
                  <label className="toggle-switch">
                    <span className="sr-only">Alert on high risk threats</span>
                    <input
                      type="checkbox"
                      checked={settings.notifications.threatDetection}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          notifications: {
                            ...settings.notifications,
                            threatDetection: e.target.checked,
                          },
                        })
                      }
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </section>
            )}

            <div className="settings-actions">
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleSave}
                disabled={isSaving}
              >
                {isSaving ? (
                  <>
                    <span className="spinner" aria-hidden="true" /> Saving…
                  </>
                ) : (
                  <>
                    <Save size={18} aria-hidden="true" /> Save settings
                  </>
                )}
              </button>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
