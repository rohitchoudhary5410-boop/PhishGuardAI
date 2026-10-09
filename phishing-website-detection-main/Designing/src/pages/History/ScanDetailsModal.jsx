import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  X,
  ExternalLink,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  RotateCcw,
  Download,
  AlertTriangle,
  Info,
  Calendar,
  Cpu,
  Layers,
  Globe,
  Loader2,
  CheckCircle2,
} from 'lucide-react';
import { scanUrl } from '../../services/api';
import {
  formatProbability,
  getRiskLevel,
  getImpactLevel,
  formatRelativeTime,
} from '../../utils/helpers';
import { useToast } from '../../components/Toast/Toast';
import './ScanDetailsModal.css';

const VERDICT_DETAILS = {
  Phishing: {
    icon: ShieldAlert,
    badgeClass: 'badge-danger',
    cardClass: 'verdict-phishing',
    title: 'Phishing Threat Detected',
    advisory:
      'High risk of deception or credential harvesting. Do not submit credentials, personal data, or payment information on this domain.',
    severity: 'Critical Threat',
  },
  Suspicious: {
    icon: ShieldQuestion,
    badgeClass: 'badge-caution',
    cardClass: 'verdict-suspicious',
    title: 'Suspicious Website Patterns',
    advisory:
      'The domain exhibits anomalous characteristics such as short registration lifespan or atypical URL structuring. Exercise elevated caution.',
    severity: 'Moderate Risk',
  },
  Legitimate: {
    icon: ShieldCheck,
    badgeClass: 'badge-safe',
    cardClass: 'verdict-legitimate',
    title: 'Legitimate Website',
    advisory:
      'URL structure and security metrics conform to established legitimate web patterns. No prominent phishing indicators detected.',
    severity: 'Verified Safe',
  },
};

const getRiskBand = (score) => {
  if (score <= 25) return 'safe';
  if (score <= 60) return 'suspicious';
  return 'danger';
};

const riskColorFor = (score) => {
  if (score <= 25) return 'var(--risk-safe, #10b981)';
  if (score <= 60) return 'var(--risk-suspicious, #f59e0b)';
  return 'var(--risk-danger, #ef4444)';
};

export default function ScanDetailsModal({ scan, onClose, onUpdateScan }) {
  const navigate = useNavigate();
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);
  const [loadingFeatures, setLoadingFeatures] = useState(false);
  const [currentScan, setCurrentScan] = useState(scan);

  useEffect(() => {
    setCurrentScan(scan);
  }, [scan]);

  // Handle ESC key to close
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!currentScan) return null;

  const verdictMeta = VERDICT_DETAILS[currentScan.prediction] || VERDICT_DETAILS.Legitimate;
  const VerdictIcon = verdictMeta.icon;
  const riskInfo = getRiskLevel(currentScan.risk_score);
  const band = getRiskBand(currentScan.risk_score);

  // SVG Gauge calculations
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeOffset = circumference - (currentScan.risk_score / 100) * circumference;

  const handleCopyUrl = async () => {
    try {
      await navigator.clipboard.writeText(currentScan.url);
      setCopied(true);
      toast.success('Website URL copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Failed to copy URL');
    }
  };

  const handleCopyReport = async () => {
    const reportText = `=== PHISHGUARD SECURITY SCAN REPORT ===
Website: ${currentScan.url}
Verdict: ${currentScan.prediction}
Confidence: ${formatProbability(currentScan.probability)}
Risk Score: ${currentScan.risk_score}/100 (${riskInfo.label})
Model: ${currentScan.model || 'Random Forest'}
Scan Date: ${currentScan.scan_time}
Scan ID: ${currentScan.id || currentScan.scan_id || 'N/A'}
Recommendation: ${verdictMeta.advisory}
`;
    try {
      await navigator.clipboard.writeText(reportText);
      setCopiedReport(true);
      toast.success('Summary report copied to clipboard');
      setTimeout(() => setCopiedReport(false), 2000);
    } catch {
      toast.error('Failed to copy report');
    }
  };

  const handleExportJson = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentScan, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `scan_report_${currentScan.id || 'record'}_${new Date().toISOString().slice(0, 10)}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    toast.success('Scan report downloaded as JSON');
  };

  const handleRescan = () => {
    onClose();
    navigate(`/scanner?url=${encodeURIComponent(currentScan.url)}`);
  };

  // If this history item lacked features, allow user to trigger in-depth inspection
  const handleLoadFeatures = async () => {
    setLoadingFeatures(true);
    try {
      const liveResult = await scanUrl(currentScan.url);
      const updated = {
        ...currentScan,
        ...liveResult,
        id: currentScan.id || liveResult.scan_id,
      };
      setCurrentScan(updated);
      if (onUpdateScan) {
        onUpdateScan(updated);
      }
      toast.success('In-depth feature breakdown retrieved');
    } catch (err) {
      toast.error(err.message || 'Could not retrieve feature breakdown');
    } finally {
      setLoadingFeatures(false);
    }
  };

  const formattedDate = currentScan.scan_time
    ? new Date(currentScan.scan_time).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short',
      })
    : 'Recently';

  return (
    <AnimatePresence>
      <div className="scan-modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
        <motion.div
          className="scan-modal-dialog"
          onClick={(e) => e.stopPropagation()}
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
        >
          {/* Header */}
          <div className="scan-modal-header">
            <div className="scan-modal-header-left">
              <span className={`scan-modal-badge ${verdictMeta.cardClass}`}>
                <VerdictIcon size={18} aria-hidden="true" />
                <span>{currentScan.prediction}</span>
              </span>
              <div className="scan-modal-title-wrap">
                <h2 className="scan-modal-title">Security Inspection Report</h2>
                <span className="scan-modal-id">ID: {currentScan.id || currentScan.scan_id || 'Scan'}</span>
              </div>
            </div>
            <button
              type="button"
              className="scan-modal-close"
              onClick={onClose}
              aria-label="Close details modal"
            >
              <X size={20} />
            </button>
          </div>

          <div className="scan-modal-body">
            {/* Target URL Card */}
            <div className="scan-url-box">
              <div className="scan-url-content">
                <Globe size={18} className="scan-url-icon" aria-hidden="true" />
                <span className="scan-url-text" title={currentScan.url}>
                  {currentScan.url}
                </span>
              </div>
              <div className="scan-url-actions">
                <button
                  type="button"
                  className="btn-pill"
                  onClick={handleCopyUrl}
                  title="Copy URL"
                >
                  {copied ? <Check size={14} className="text-safe" /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <a
                  href={currentScan.url.startsWith('http') ? currentScan.url : `https://${currentScan.url}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-pill"
                  title="Open website in new tab"
                >
                  <ExternalLink size={14} />
                  <span>Visit</span>
                </a>
              </div>
            </div>

            {/* Quick Metrics Bar */}
            <div className="scan-metrics-grid">
              {/* Verdict KPI */}
              <div className="scan-metric-card">
                <span className="scan-metric-label">Prediction</span>
                <div className="scan-metric-val-wrap">
                  <span className={`scan-metric-verdict text-${band}`}>
                    {currentScan.prediction}
                  </span>
                </div>
                <span className={`badge ${riskInfo.className}`}>
                  {verdictMeta.severity}
                </span>
              </div>

              {/* Confidence KPI */}
              <div className="scan-metric-card">
                <span className="scan-metric-label">Model Confidence</span>
                <span className="scan-metric-val">
                  {formatProbability(currentScan.probability)}
                </span>
                <div className="scan-metric-bar-bg">
                  <div
                    className={`scan-metric-bar-fill fill-${band}`}
                    style={{ width: `${(currentScan.probability || 0.9) * 100}%` }}
                  />
                </div>
              </div>

              {/* Risk Score Gauge */}
              <div className="scan-metric-card scan-gauge-card">
                <span className="scan-metric-label">Threat Score</span>
                <div className="scan-gauge-compact">
                  <svg className="scan-gauge-svg" width="60" height="60" viewBox="0 0 100 100">
                    <circle className="scan-gauge-track" cx="50" cy="50" r={radius} />
                    <circle
                      className="scan-gauge-value-circle"
                      cx="50"
                      cy="50"
                      r={radius}
                      stroke={riskColorFor(currentScan.risk_score)}
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeOffset}
                    />
                  </svg>
                  <div className="scan-gauge-number text-${band}">
                    {currentScan.risk_score}
                  </div>
                </div>
                <span className="scan-metric-subtext">0 = Safe · 100 = Phishing</span>
              </div>

              {/* Detection Model */}
              <div className="scan-metric-card">
                <span className="scan-metric-label">Classifier Engine</span>
                <span className="scan-metric-val font-sm">
                  {currentScan.model || 'Random Forest'}
                </span>
                <div className="scan-engine-meta">
                  <Cpu size={13} />
                  <span>111 Feature Vectors</span>
                </div>
              </div>
            </div>

            {/* Advisory Alert */}
            <div className={`scan-advisory-box ${verdictMeta.cardClass}`}>
              <div className="scan-advisory-icon">
                {currentScan.prediction === 'Phishing' ? (
                  <AlertTriangle size={20} />
                ) : (
                  <Info size={20} />
                )}
              </div>
              <div className="scan-advisory-body">
                <h4 className="scan-advisory-title">{verdictMeta.title}</h4>
                <p className="scan-advisory-text">{verdictMeta.advisory}</p>
              </div>
            </div>

            {/* Feature Impact Section */}
            <div className="scan-features-section">
              <div className="scan-section-heading">
                <div className="scan-heading-text">
                  <Layers size={17} className="text-primary" />
                  <h3 className="scan-section-title">Feature Vector Analysis</h3>
                </div>
                {(!currentScan.features || Object.keys(currentScan.features).length === 0) && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={handleLoadFeatures}
                    disabled={loadingFeatures}
                  >
                    {loadingFeatures ? (
                      <>
                        <Loader2 size={14} className="spin" />
                        <span>Analyzing features…</span>
                      </>
                    ) : (
                      <>
                        <RotateCcw size={14} />
                        <span>Extract ML Features</span>
                      </>
                    )}
                  </button>
                )}
              </div>

              {currentScan.features && Object.keys(currentScan.features).length > 0 ? (
                <div className="scan-features-grid">
                  {Object.entries(currentScan.features).map(([key, feat]) => {
                    const impact = getImpactLevel(feat.impact);
                    return (
                      <div key={key} className="scan-feature-item">
                        <div className="scan-feature-header">
                          <span className="scan-feature-label">
                            {feat.label || key.replace(/_/g, ' ')}
                          </span>
                          <span className={`feature-impact-badge ${feat.risk}`}>
                            {impact.label}
                          </span>
                        </div>
                        <div className="scan-feature-details">
                          <span className="scan-feature-value">
                            Value: <strong>{String(feat.value)}</strong>
                          </span>
                        </div>
                        <div className="scan-feature-track">
                          <div
                            className={`scan-feature-fill ${feat.risk}`}
                            style={{ width: `${Math.max(12, (feat.impact || 0.2) * 100)}%` }}
                          />
                        </div>
                        {feat.description && (
                          <p className="scan-feature-description">{feat.description}</p>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="scan-features-empty">
                  <p className="scan-features-empty-note">
                    Standard extraction features are available for this record. Click below to inspect deep URL attributes or perform a live re-evaluation.
                  </p>
                  <div className="scan-quick-attributes">
                    <div className="attribute-pill">
                      <span>URL Length</span>
                      <strong>{currentScan.url.length} chars</strong>
                    </div>
                    <div className="attribute-pill">
                      <span>Protocol</span>
                      <strong>{currentScan.url.startsWith('https') ? 'HTTPS' : 'HTTP/Standard'}</strong>
                    </div>
                    <div className="attribute-pill">
                      <span>Risk Classification</span>
                      <strong>{riskInfo.label}</strong>
                    </div>
                    <div className="attribute-pill">
                      <span>Evaluated Model</span>
                      <strong>{currentScan.model || 'Random Forest'}</strong>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Diagnostic Information */}
            <div className="scan-diagnostics-box">
              <div className="scan-diagnostic-item">
                <Calendar size={14} />
                <span>Timestamp: <strong>{formattedDate}</strong> ({formatRelativeTime(currentScan.scan_time)})</span>
              </div>
              <div className="scan-diagnostic-item">
                <CheckCircle2 size={14} />
                <span>Status: <strong>Analyzed & Scored</strong></span>
              </div>
            </div>
          </div>

          {/* Footer Actions */}
          <div className="scan-modal-footer">
            <div className="scan-footer-left">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleCopyReport}
              >
                {copiedReport ? <Check size={14} className="text-safe" /> : <Copy size={14} />}
                <span>{copiedReport ? 'Report Copied' : 'Copy Report'}</span>
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleExportJson}
              >
                <Download size={14} />
                <span>Export JSON</span>
              </button>
            </div>
            <div className="scan-footer-right">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onClose}
              >
                Close
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleRescan}
              >
                <RotateCcw size={15} />
                <span>Open in Live Scanner</span>
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
