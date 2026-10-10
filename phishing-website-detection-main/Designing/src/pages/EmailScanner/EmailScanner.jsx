import { useState, useEffect, useRef } from 'react';
import {
  Mail,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  RefreshCw,
  Search,
  CheckCircle2,
  Lock,
  ChevronRight,
  Info,
  Filter,
  Inbox,
  FileText,
  Key,
  Flame,
  ArrowRight,
  Lightbulb
} from 'lucide-react';
import { scanEmail, getEmailPresets, syncGmail } from '../../services/api';
import { useToast } from '../../components/Toast/Toast';
import './EmailScanner.css';

export default function EmailScanner() {
  const toast = useToast();
  const detailRef = useRef(null);
  const [activeTab, setActiveTab] = useState('gmail-inbox'); // 'gmail-inbox' | 'manual-inspect'
  const [loading, setLoading] = useState(false);
  const [syncingInbox, setSyncingInbox] = useState(false);
  
  // Gmail sync & inbox state
  const [inboxEmails, setInboxEmails] = useState([]);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [inboxFilter, setInboxFilter] = useState('all'); // 'all' | 'phishing' | 'suspicious' | 'safe'
  const [searchQuery, setSearchQuery] = useState('');
  const [showOauthModal, setShowOauthModal] = useState(false);
  const [connectedAccount, setConnectedAccount] = useState('');

  // Modal Connection form state
  const [connectTab, setConnectTab] = useState('imap'); // 'imap' | 'demo' | 'oauth'
  const [gmailEmail, setGmailEmail] = useState('');
  const [appPassword, setAppPassword] = useState('');
  const [oauthToken, setOauthToken] = useState('');
  const [connectError, setConnectError] = useState('');

  // Manual Inspector state
  const [presets, setPresets] = useState([]);
  const [senderInput, setSenderInput] = useState('');
  const [subjectInput, setSubjectInput] = useState('');
  const [bodyInput, setBodyInput] = useState('');
  const [inspectionResult, setInspectionResult] = useState(null);

  // Load presets on mount
  useEffect(() => {
    loadPresets();
    // Auto-run sandbox sync initially so user immediately sees Gmail protection in action
    handleSyncDemo();
  }, []);

  const loadPresets = async () => {
    try {
      const data = await getEmailPresets();
      setPresets(data);
    } catch (err) {
      console.warn('Could not load presets:', err);
    }
  };

  const handleSelectPreset = (preset) => {
    setSenderInput(preset.sender);
    setSubjectInput(preset.subject);
    setBodyInput(preset.body);
    toast.info(`Loaded preset: "${preset.title}"`);
  };

  const handleSyncDemo = async () => {
    setSyncingInbox(true);
    try {
      const res = await syncGmail({});
      setInboxEmails(res.results || []);
      if (res.results && res.results.length > 0) {
        setSelectedEmail(res.results[0]);
      }
    } catch (err) {
      console.warn('Demo sync error:', err);
    } finally {
      setSyncingInbox(false);
    }
  };

  // Re-sync inbox using whatever credentials are currently stored, or fall back to demo
  const handleSyncGmail = async () => {
    setSyncingInbox(true);
    try {
      let payload = {};
      if (gmailEmail && appPassword) {
        payload = { email: gmailEmail.trim(), app_password: appPassword.trim() };
      } else if (oauthToken) {
        payload = { access_token: oauthToken.trim() };
      }
      const res = await syncGmail(payload);
      setInboxEmails(res.results || []);
      if (res.results && res.results.length > 0) {
        setSelectedEmail(res.results[0]);
      }
      toast.success(`Inbox refreshed — ${res.total_scanned} emails scanned.`);
    } catch (err) {
      toast.error(err.message || 'Sync failed');
    } finally {
      setSyncingInbox(false);
    }
  };

  const handleConnectSubmit = async (e) => {
    e?.preventDefault();
    setSyncingInbox(true);
    setConnectError('');

    try {
      let payload = {};
      let accountLabel = '';

      if (connectTab === 'imap') {
        if (!gmailEmail.trim()) {
          toast.warning('Please enter your Gmail address.');
          setSyncingInbox(false);
          return;
        }
        if (!appPassword.trim()) {
          toast.warning('Please enter your 16-character Google App Password.');
          setSyncingInbox(false);
          return;
        }
        payload = { email: gmailEmail.trim(), app_password: appPassword.trim() };
        accountLabel = gmailEmail.trim();
      } else if (connectTab === 'oauth') {
        if (!oauthToken.trim()) {
          toast.warning('Please enter your Google OAuth Access Token.');
          setSyncingInbox(false);
          return;
        }
        payload = { access_token: oauthToken.trim() };
        accountLabel = 'Google OAuth Account';
      } else {
        // Demo Sandbox
        payload = {};
        accountLabel = 'Protected Demo Mailbox';
      }

      const res = await syncGmail(payload);
      setInboxEmails(res.results || []);
      if (res.results && res.results.length > 0) {
        setSelectedEmail(res.results[0]);
      }
      setConnectedAccount(accountLabel);
      if (connectTab === 'imap') {
        toast.success(`Successfully connected & scanned ${res.total_scanned} live emails from ${accountLabel}!`);
      } else {
        toast.success(`Loaded ${res.total_scanned} analyzed emails!`);
      }
      setShowOauthModal(false);
    } catch (err) {
      const msg = err.message || 'Gmail connection failed';
      setConnectError(msg);
      toast.error(msg);
    } finally {
      setSyncingInbox(false);
    }
  };

  const handleManualScan = async (e) => {
    e?.preventDefault();
    if (!bodyInput.trim() && !subjectInput.trim()) {
      toast.warning('Please enter an email subject or message body to analyze.');
      return;
    }

    setLoading(true);
    setInspectionResult(null);
    try {
      const report = await scanEmail({
        sender: senderInput,
        subject: subjectInput,
        body: bodyInput,
      });
      setInspectionResult(report);
      if (report.theme === 'danger') {
        toast.warning(`Threat detected: ${report.verdict}`);
      } else {
        toast.success(`Analysis complete: ${report.verdict}`);
      }
    } catch (err) {
      toast.error(err.message || 'Email scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      const rawContent = evt.target.result;
      setLoading(true);
      try {
        const report = await scanEmail({ raw_content: rawContent });
        setInspectionResult(report);
        setSenderInput(report.sender || '');
        setSubjectInput(report.subject || '');
        setBodyInput(rawContent);
        toast.success('Parsed & inspected .eml file successfully!');
      } catch (err) {
        toast.error(err.message || 'Could not parse email file');
      } finally {
        setLoading(false);
      }
    };
    reader.readAsText(file);
  };

  // Filter inbox list
  const filteredInbox = inboxEmails.filter((mail) => {
    const matchesFilter =
      inboxFilter === 'all' ||
      (inboxFilter === 'phishing' && mail.theme === 'danger') ||
      (inboxFilter === 'suspicious' && mail.theme === 'warning') ||
      (inboxFilter === 'safe' && mail.theme === 'safe');

    const matchesSearch =
      !searchQuery ||
      mail.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      mail.sender?.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesFilter && matchesSearch;
  });

  const getVerdictBadge = (theme, verdict, riskScore) => {
    if (theme === 'danger') {
      return (
        <span className="threat-pill threat-pill--danger">
          <ShieldAlert size={14} /> {verdict} ({riskScore}%)
        </span>
      );
    }
    if (theme === 'warning') {
      return (
        <span className="threat-pill threat-pill--warning">
          <AlertTriangle size={14} /> {verdict} ({riskScore}%)
        </span>
      );
    }
    return (
      <span className="threat-pill threat-pill--safe">
        <ShieldCheck size={14} /> {verdict} ({riskScore}%)
      </span>
    );
  };

  return (
    <div className="email-scanner-container">
      {/* Top Banner / Privacy Guarantee */}
      <div className="email-scanner-hero">
        <div className="email-scanner-hero-content">
          <div className="privacy-badge">
            <Lock size={14} />
            <span>100% On-Device & Privacy-Preserving Email Security</span>
          </div>
          <h1 className="email-scanner-title">
            <Mail className="title-icon" size={32} />
            Gmail Shield & Misleading Email Detector
          </h1>
          <p className="email-scanner-subtitle">
            Autonomous multi-signal email protection. Inspects sender brand spoofing, psychological
            coercion, credential-harvesting NLP cues, and deeply validates all embedded hyperlinks with our 111-feature ML model.
          </p>
        </div>

        {/* Quick Stats Pill */}
        <div className="email-scanner-stats">
          <div className="stat-card">
            <span className="stat-label">Inbox Status</span>
            <span className="stat-value stat-value--secure">Protected</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Model Engine</span>
            <span className="stat-value">Random Forest + NLP</span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="scanner-tabs-bar">
        <button
          className={`scanner-tab-btn ${activeTab === 'gmail-inbox' ? 'active' : ''}`}
          onClick={() => setActiveTab('gmail-inbox')}
        >
          <Inbox size={18} />
          <span>Gmail Inbox Shield</span>
          {inboxEmails.length > 0 && <span className="tab-counter">{inboxEmails.length}</span>}
        </button>
        <button
          className={`scanner-tab-btn ${activeTab === 'manual-inspect' ? 'active' : ''}`}
          onClick={() => setActiveTab('manual-inspect')}
        >
          <FileText size={18} />
          <span>Email & Message Inspector</span>
        </button>
      </div>

      {/* ========================================================== */}
      {/* TAB 1: GMAIL INBOX SHIELD */}
      {/* ========================================================== */}
      {activeTab === 'gmail-inbox' && (
        <div className="inbox-shield-view">
          {/* Controls Bar */}
          <div className="inbox-toolbar">
            <div className="inbox-search-box">
              <Search size={16} className="search-icon" />
              <input
                type="text"
                placeholder="Search subject or sender..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div className="inbox-filter-group">
              <Filter size={16} />
              <button
                className={`filter-btn ${inboxFilter === 'all' ? 'active' : ''}`}
                onClick={() => setInboxFilter('all')}
              >
                All ({inboxEmails.length})
              </button>
              <button
                className={`filter-btn filter-btn--danger ${inboxFilter === 'phishing' ? 'active' : ''}`}
                onClick={() => setInboxFilter('phishing')}
              >
                Threats ({inboxEmails.filter((m) => m.theme === 'danger').length})
              </button>
              <button
                className={`filter-btn filter-btn--warning ${inboxFilter === 'suspicious' ? 'active' : ''}`}
                onClick={() => setInboxFilter('suspicious')}
              >
                Suspicious ({inboxEmails.filter((m) => m.theme === 'warning').length})
              </button>
              <button
                className={`filter-btn filter-btn--safe ${inboxFilter === 'safe' ? 'active' : ''}`}
                onClick={() => setInboxFilter('safe')}
              >
                Safe ({inboxEmails.filter((m) => m.theme === 'safe').length})
              </button>
            </div>

            <div className="inbox-action-buttons">
              <button
                className="btn-sync"
                disabled={syncingInbox}
                onClick={() => handleSyncGmail(false)}
                title="Refresh Protected Inbox"
              >
                <RefreshCw size={16} className={syncingInbox ? 'spin' : ''} />
                <span>Sync Inbox</span>
              </button>
              <button
                className="btn-connect-gmail"
                onClick={() => setShowOauthModal(true)}
              >
                <Key size={16} />
                <span>Connect Live Gmail</span>
              </button>
            </div>
          </div>

          {/* Master-Detail Layout */}
          <div className="inbox-master-detail">
            {/* Left Email List */}
            <div className="inbox-email-list">
              {filteredInbox.length === 0 ? (
                <div className="empty-inbox-state">
                  <ShieldCheck size={36} />
                  <p>No emails match current filter.</p>
                </div>
              ) : (
                filteredInbox.map((mail, idx) => {
                  const isSelected = selectedEmail?.scan_id === mail.scan_id;
                  return (
                    <div
                      key={mail.scan_id || `mail-${idx}`}
                      className={`email-row-card ${isSelected ? 'is-selected' : ''} theme--${mail.theme}`}
                      onClick={() => setSelectedEmail(mail)}
                    >
                      <div className="email-row-risk-bar">
                        <div className={`risk-score-circle risk-score--${mail.theme}`}>
                          <span className="risk-score-num">{mail.risk_score}</span>
                        </div>
                        <div className="email-row-content">
                          <div className="email-row-header">
                            <span className="email-sender-name" title={mail.sender}>
                              {mail.sender_analysis?.display_name || mail.sender || 'Unknown Sender'}
                            </span>
                            {getVerdictBadge(mail.theme, mail.verdict, mail.risk_score)}
                          </div>
                          <div className="email-row-subject">{mail.subject || '(No Subject)'}</div>
                          {mail.snippet && (
                            <div className="email-row-snippet">{mail.snippet.slice(0, 100)}{mail.snippet.length > 100 ? '…' : ''}</div>
                          )}
                          <div className="email-row-footer">
                            <span className="email-domain-tag">
                              {mail.sender_analysis?.domain || 'unverified'}
                            </span>
                            {mail.evidence?.length > 0 && (
                              <span className="evidence-count-tag">
                                {mail.evidence.length} red flag{mail.evidence.length > 1 ? 's' : ''}
                              </span>
                            )}
                          </div>
                        </div>
                        {isSelected && (
                          <ChevronRight size={18} className="email-row-chevron" />
                        )}
                      </div>
                    </div>
                  );
                })

              )}
            </div>

            {/* Right Detailed Email Inspection Panel */}
            <div className="inbox-email-detail">
              {selectedEmail ? (
                <EmailDetailReport report={selectedEmail} />
              ) : (
                <div className="detail-placeholder">
                  <Mail size={48} />
                  <h3>Select an email to view complete threat intelligence</h3>
                  <p>Inspect header spoofing, manipulative NLP signals, and URL safety ratings.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================== */}
      {/* TAB 2: MANUAL EMAIL & MESSAGE INSPECTOR */}
      {/* ========================================================== */}
      {activeTab === 'manual-inspect' && (
        <div className="manual-inspector-view">
          {/* Preset Attack Scenarios */}
          <div className="preset-selector-card">
            <div className="preset-header">
              <Flame size={18} className="preset-icon" />
              <span>Hackathon Live Attack Presets:</span>
            </div>
            <div className="preset-chips">
              {presets.map((preset) => (
                <button
                  key={preset.id}
                  className="preset-chip"
                  onClick={() => handleSelectPreset(preset)}
                >
                  <span className="preset-chip-title">{preset.title}</span>
                  <span className="preset-chip-cat">{preset.category}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="inspector-columns">
            {/* Input Form */}
            <div className="inspector-form-card">
              <div className="form-card-header">
                <h3>Scan Raw Email or Scam Message</h3>
                <label className="file-upload-btn">
                  <span>Upload .EML</span>
                  <input type="file" accept=".eml,.txt" onChange={handleFileUpload} />
                </label>
              </div>

              <form onSubmit={handleManualScan}>
                <div className="form-group">
                  <label>Sender / From Header</label>
                  <input
                    type="text"
                    placeholder='"Netflix Security" <billing-alert@fake-domain.com>'
                    value={senderInput}
                    onChange={(e) => setSenderInput(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label>Subject Line</label>
                  <input
                    type="text"
                    placeholder="e.g. Urgent: Account suspended within 24 hours"
                    value={subjectInput}
                    onChange={(e) => setSubjectInput(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label>Email Body / Message Content</label>
                  <textarea
                    rows={8}
                    placeholder="Paste the full email text, SMS message, or notification here. Include any links (e.g. https://...)..."
                    value={bodyInput}
                    onChange={(e) => setBodyInput(e.target.value)}
                  />
                </div>

                <div className="form-actions">
                  <button type="submit" className="btn-run-scan" disabled={loading}>
                    {loading ? (
                      <>
                        <RefreshCw size={18} className="spin" />
                        <span>Analyzing Message Signals...</span>
                      </>
                    ) : (
                      <>
                        <Shield size={18} />
                        <span>Inspect Email Threat</span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>

            {/* Live Result View */}
            <div className="inspector-results-card">
              {inspectionResult ? (
                <EmailDetailReport report={inspectionResult} />
              ) : (
                <div className="empty-inspector-state">
                  <ShieldCheck size={56} className="shield-ghost-icon" />
                  <h3>Ready to Inspect</h3>
                  <p>
                    Select an attack preset above or paste suspicious emails to analyze deceptive
                    headers, psychological urgency patterns, and malicious URLs.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================== */}
      {/* GMAIL CONNECTION MODAL (APP PASSWORD / DEMO / OAUTH) */}
      {/* ========================================================== */}
      {showOauthModal && (
        <div className="modal-backdrop" onClick={() => setShowOauthModal(false)}>
          <div className="modal-dialog modal-dialog--wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-title">
                <Mail className="modal-gmail-icon" size={24} />
                <h3>Connect Gmail Account</h3>
              </div>
              <button className="modal-close-btn" onClick={() => setShowOauthModal(false)}>
                &times;
              </button>
            </div>

            {/* Modal Connection Tabs */}
            <div className="modal-tabs">
              <button
                type="button"
                className={`modal-tab ${connectTab === 'imap' ? 'active' : ''}`}
                onClick={() => setConnectTab('imap')}
              >
                <span>Gmail App Password</span>
                <span className="tab-pill">Recommended</span>
              </button>
              <button
                type="button"
                className={`modal-tab ${connectTab === 'demo' ? 'active' : ''}`}
                onClick={() => setConnectTab('demo')}
              >
                <span>Instant Demo Inbox</span>
                <span className="tab-pill tab-pill--demo">No Password</span>
              </button>
              <button
                type="button"
                className={`modal-tab ${connectTab === 'oauth' ? 'active' : ''}`}
                onClick={() => setConnectTab('oauth')}
              >
                <span>Google OAuth Token</span>
              </button>
            </div>

            <div className="modal-body">
              {connectTab === 'imap' && (
                <form onSubmit={handleConnectSubmit} className="modal-form">
                  <p className="modal-desc">
                    Connect directly to Gmail via secure IMAP. Scans your real inbox messages safely on-device without requiring Google Cloud approval.
                  </p>

                  <div className="form-group">
                    <label>Your Gmail Address</label>
                    <input
                      type="email"
                      placeholder="e.g. yourname@gmail.com"
                      value={gmailEmail}
                      onChange={(e) => setGmailEmail(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label>16-Character Google App Password</label>
                    <input
                      type="password"
                      placeholder="abcd efgh ijkl mnop"
                      value={appPassword}
                      onChange={(e) => setAppPassword(e.target.value)}
                      required
                    />
                  </div>

                  <div className="app-password-guide">
                    <div className="guide-title">
                      <Info size={16} />
                      <strong>How to get your App Password in 30 seconds:</strong>
                    </div>
                    <ol className="guide-steps">
                      <li>
                        Go to{' '}
                        <a
                          href="https://myaccount.google.com/apppasswords"
                          target="_blank"
                          rel="noreferrer"
                        >
                          myaccount.google.com/apppasswords
                        </a>
                      </li>
                      <li>Ensure <strong>2-Step Verification</strong> is ON in your Google Account.</li>
                      <li>Under "App name", type <strong>PhishGuard</strong> and click <strong>Create</strong>.</li>
                      <li>Copy the 16-character password and paste it above!</li>
                    </ol>
                  </div>

                  {connectError && connectTab === 'imap' && (
                    <div className="connect-error-box">
                      <AlertTriangle size={16} />
                      <div>
                        <strong>Connection Failed</strong>
                        <p>{connectError}</p>
                      </div>
                    </div>
                  )}

                  <div className="modal-footer">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => setShowOauthModal(false)}
                    >
                      Cancel
                    </button>
                    <button type="submit" className="btn-primary" disabled={syncingInbox}>
                      {syncingInbox ? (
                        <>
                          <RefreshCw size={16} className="spin" />
                          <span>Connecting & Scanning...</span>
                        </>
                      ) : (
                        <span>Connect & Scan Live Gmail</span>
                      )}
                    </button>
                  </div>
                </form>
              )}

              {connectTab === 'demo' && (
                <div className="demo-modal-content">
                  <p className="modal-desc">
                    Want to test the Gmail scanner right now without entering any passwords?
                  </p>
                  <div className="demo-features-list">
                    <div className="demo-feat-item">
                      <ShieldAlert size={18} className="color-danger" />
                      <span>Simulates incoming high-risk phishing attacks (Netflix suspension, Chase KYC fraud)</span>
                    </div>
                    <div className="demo-feat-item">
                      <AlertTriangle size={18} className="color-warning" />
                      <span>Simulates Executive BEC wire fraud and cryptocurrency giveaway lures</span>
                    </div>
                    <div className="demo-feat-item">
                      <ShieldCheck size={18} className="color-success" />
                      <span>Simulates legitimate verified merchant order receipts</span>
                    </div>
                  </div>

                  <div className="modal-footer">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => setShowOauthModal(false)}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="btn-primary"
                      onClick={handleConnectSubmit}
                      disabled={syncingInbox}
                    >
                      {syncingInbox ? 'Loading...' : 'Load Protected Demo Inbox'}
                    </button>
                  </div>
                </div>
              )}

              {connectTab === 'oauth' && (
                <form onSubmit={handleConnectSubmit} className="modal-form">
                  <p className="modal-desc">
                    Provide a Google OAuth2 Access Token with <code>gmail.readonly</code> scope to pull and scan messages via Google REST API.
                  </p>

                  <div className="form-group">
                    <label>Google OAuth Access Token</label>
                    <input
                      type="password"
                      placeholder="ya29.a0AfH6SM..."
                      value={oauthToken}
                      onChange={(e) => setOauthToken(e.target.value)}
                    />
                  </div>

                  <div className="modal-footer">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => setShowOauthModal(false)}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={!oauthToken.trim() || syncingInbox}
                    >
                      {syncingInbox ? 'Authorizing...' : 'Authorize & Scan'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Sub-component: Comprehensive Email Security Breakdown Report
function EmailDetailReport({ report }) {
  if (!report) return null;

  const {
    subject,
    sender,
    verdict,
    threat_level,
    risk_score,
    theme,
    sender_analysis,
    content_analysis,
    links,
    evidence,
    recommendations,
    simple_explanation,
  } = report;

  return (
    <div className={`email-report-container theme--${theme}`}>
      {/* Main Verdict Header Card */}
      <div className="report-header-banner">
        <div className="verdict-main">
          <div className="verdict-icon-bubble">
            {theme === 'danger' && <ShieldAlert size={36} />}
            {theme === 'warning' && <AlertTriangle size={36} />}
            {theme === 'safe' && <ShieldCheck size={36} />}
          </div>
          <div>
            <div className="verdict-label">{threat_level}</div>
            <h2 className="verdict-title">{verdict}</h2>
            <div className="verdict-meta">
              <strong>From:</strong> {sender || 'N/A'}
            </div>
            <div className="verdict-meta">
              <strong>Subject:</strong> {subject || 'N/A'}
            </div>
          </div>
        </div>

        <div className="score-meter-box">
          <div className="score-number">{risk_score}</div>
          <div className="score-subtext">Composite Threat Score / 100</div>
        </div>
      </div>

      {/* Highlighted Plain English / Simple Language Explanation */}
      <div className={`simple-explain-container theme--${theme}`}>
        <div className="simple-explain-header">
          <div className="simple-explain-tag">
            <Lightbulb size={18} className="simple-bulb-icon" />
            <span>Plain English Security Breakdown</span>
          </div>
          <span className="simple-explain-badge">
            {theme === 'danger' ? '🚨 High Risk Alert' : theme === 'warning' ? '⚠️ Caution Required' : '✅ Verified Safe'}
          </span>
        </div>

        <div className="simple-explain-summary">
          {simple_explanation?.summary ||
            (risk_score >= 70
              ? 'This email is a dangerous phishing scam. It pretends to be a trusted service to panic you into clicking fake links and revealing your private login or payment information.'
              : risk_score >= 35
              ? 'This email exhibits suspicious traits. Proceed with caution and do not click unfamiliar links or share passwords.'
              : 'This email appears authentic and safe. No deceptive social engineering or malicious links were detected.')}
        </div>

        {((simple_explanation?.reasons && simple_explanation.reasons.length > 0) || (evidence && evidence.length > 0)) && (
          <div className="simple-reasons-box">
            <div className="simple-reasons-label">Why this was flagged in simple terms:</div>
            <ul className="simple-reasons-list">
              {simple_explanation?.reasons?.length > 0
                ? simple_explanation.reasons.map((reason, idx) => (
                    <li key={idx}>
                      <span className="reason-bullet">⚡</span>
                      <span>{reason}</span>
                    </li>
                  ))
                : evidence.slice(0, 3).map((ev, idx) => (
                    <li key={idx}>
                      <span className="reason-bullet">⚡</span>
                      <span><strong>{ev.title}:</strong> {ev.description}</span>
                    </li>
                  ))}
            </ul>
          </div>
        )}

        <div className="simple-actions-box">
          <div className="simple-actions-label">🛡️ Recommended Next Steps:</div>
          <ul className="simple-actions-list">
            {(simple_explanation?.actions || recommendations || [
              'Do NOT click any links, open attachments, or reply to this message.',
              'Never enter payment, banking, or password details on linked sites.',
              'Report this email as Phishing / Fraud and delete it.'
            ]).map((act, idx) => (
              <li key={idx}>
                <CheckCircle2 size={16} className="action-check-icon" />
                <span>{act}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* 3-Pillar Threat Breakdown */}
      <div className="pillars-grid">
        {/* Pillar 1: Sender Spoofing */}
        <div className="pillar-card">
          <div className="pillar-title">
            <Key size={16} />
            <span>Sender Authenticity</span>
            <span className="pillar-score">{sender_analysis?.risk_score || 0}%</span>
          </div>
          <div className="pillar-body">
            <div className="prop-row">
              <span className="prop-name">Display Name:</span>
              <span className="prop-value">{sender_analysis?.display_name || 'N/A'}</span>
            </div>
            <div className="prop-row">
              <span className="prop-name">Origin Domain:</span>
              <span className="prop-value font-mono">{sender_analysis?.domain || 'N/A'}</span>
            </div>
            {sender_analysis?.impersonated_brand && (
              <div className="impersonation-warning">
                Impersonating Brand: <strong>{sender_analysis.impersonated_brand}</strong>
              </div>
            )}
          </div>
        </div>

        {/* Pillar 2: Social Engineering NLP */}
        <div className="pillar-card">
          <div className="pillar-title">
            <Flame size={16} />
            <span>Psychological Cues</span>
            <span className="pillar-score">{content_analysis?.risk_score || 0}%</span>
          </div>
          <div className="pillar-body">
            {content_analysis?.categories?.length > 0 ? (
              <div className="tag-cloud">
                {content_analysis.categories.map((c, i) => (
                  <span key={i} className="cue-tag">
                    {c.category} ({c.count})
                  </span>
                ))}
              </div>
            ) : (
              <p className="clean-signal">No coercive urgency or scam lures detected.</p>
            )}
          </div>
        </div>

        {/* Pillar 3: Hyperlinks Found */}
        <div className="pillar-card">
          <div className="pillar-title">
            <ExternalLink size={16} />
            <span>Link Security</span>
            <span className="pillar-score">{links?.length || 0} URL{links?.length !== 1 ? 's' : ''}</span>
          </div>
          <div className="pillar-body">
            {links?.length > 0 ? (
              <div className="mini-link-list">
                {links.map((link, idx) => (
                  <div key={idx} className="mini-link-item">
                    <span className="link-target font-mono" title={link.url}>
                      {link.target_domain}
                    </span>
                    <span
                      className={`link-risk-badge risk-${
                        link.phishing_probability >= 0.5 ? 'high' : 'low'
                      }`}
                    >
                      {link.prediction} ({Math.round((link.phishing_probability || 0) * 100)}%)
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="clean-signal">No external hyperlinks present in message.</p>
            )}
          </div>
        </div>
      </div>

      {/* Red Flags & Evidence Log */}
      {evidence && evidence.length > 0 && (
        <div className="report-section evidence-section">
          <h3>
            <AlertTriangle size={18} />
            Detected Red Flags ({evidence.length})
          </h3>
          <div className="evidence-list">
            {evidence.map((ev, i) => (
              <div key={i} className={`evidence-card sev-${ev.severity}`}>
                <div className="evidence-header">
                  <span className={`sev-badge sev-${ev.severity}`}>{ev.severity.toUpperCase()}</span>
                  <span className="evidence-source">{ev.source}</span>
                  <span className="evidence-title">{ev.title}</span>
                </div>
                <div className="evidence-desc">{ev.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Embedded Link Deep-Dive */}
      {links && links.length > 0 && (
        <div className="report-section links-section">
          <h3>
            <ExternalLink size={18} />
            Embedded Link Analysis (Verified by PhishGuard ML)
          </h3>
          <div className="links-table">
            {links.map((lnk, i) => (
              <div key={i} className="link-detail-row">
                <div className="link-info">
                  <div className="link-url-line">
                    <span className="link-url">{lnk.url}</span>
                    {lnk.is_mismatched && (
                      <span className="mismatch-tag">DECEPTIVE ANCHOR MISMATCH</span>
                    )}
                  </div>
                  {lnk.deception_warning && (
                    <div className="deception-text">{lnk.deception_warning}</div>
                  )}
                </div>
                <div className="link-score-badge">
                  <span className="badge-model-pred">{lnk.prediction}</span>
                  <span className="badge-prob">
                    Risk: {Math.round((lnk.phishing_probability || 0) * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Countermeasures */}
      {recommendations && recommendations.length > 0 && (
        <div className="report-section recommendations-section">
          <h3>
            <CheckCircle2 size={18} />
            Recommended Countermeasures
          </h3>
          <ul className="rec-list">
            {recommendations.map((rec, i) => (
              <li key={i}>
                <ArrowRight size={16} />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
