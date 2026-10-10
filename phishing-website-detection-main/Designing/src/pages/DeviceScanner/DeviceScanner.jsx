import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  FileCode,
  FileCheck,
  Upload,
  AlertTriangle,
  Lock,
  MessageSquare,
  FileText,
  Copy,
  CheckCircle2,
  Trash2,
  RefreshCw,
  ExternalLink,
  Info
} from 'lucide-react';
import { scanFile, scanMessage, reportFalsePositive } from '../../services/api';
import { useToast } from '../../components/Toast/Toast';
import './DeviceScanner.css';

const SAMPLE_SCAM_MESSAGES = [
  {
    title: 'Bank KYC Suspension Alert',
    text: 'URGENT: Your HDFC Bank account will be suspended within 24 hours due to pending KYC verification. Click here immediately to verify PAN card and restore access: http://hdfc-kyc-update99.xyz/portal'
  },
  {
    title: 'UPI PIN / OTP Scam',
    text: 'Congratulations! You have received a cash reward of $450 from GooglePay. To claim instant transfer, enter your 6-digit UPI PIN and share the confirmation OTP.'
  },
  {
    title: 'Crypto Airdrop Lure',
    text: 'Anniversary Giveaway: 500 USDT has been credited to your wallet! Connect your crypto wallet to claim now: https://binance-airdrop-reward.work/claim 100% guaranteed return.'
  },
  {
    title: 'Urgent Power Disconnection Threat',
    text: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because previous bill was not updated. Immediately call electricity officer at +1-800-492-1920.'
  }
];

const DeviceScanner = () => {
  const [activeTab, setActiveTab] = useState('file'); // 'file' or 'message'
  const { addToast } = useToast();

  // File Scanner State
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileScanning, setFileScanning] = useState(false);
  const [fileResult, setFileResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  // Message Scanner State
  const [messageInput, setMessageInput] = useState('');
  const [messageScanning, setMessageScanning] = useState(false);
  const [messageResult, setMessageResult] = useState(null);

  // False Positive reporting modal
  const [fpModal, setFpModal] = useState({ open: false, scanId: '' });
  const [fpReason, setFpReason] = useState('');

  // Handle file scan (can be called automatically or manually)
  const handleScanFile = async (fileToScan) => {
    const file = fileToScan || selectedFile;
    if (!file) {
      addToast('Please select a file to scan.', 'warning');
      return;
    }
    setFileScanning(true);
    setFileResult(null);
    try {
      const res = await scanFile(file);
      setFileResult(res);
      if (res.verdict === 'Malicious') {
        addToast(`Threat detected: ${res.threat_category}`, 'error');
      } else if (res.verdict === 'Suspicious') {
        addToast(`Attention: ${res.threat_category}`, 'warning');
      } else {
        addToast(`File scanned clean: ${res.threat_category || 'No threats detected'}`, 'success');
      }
    } catch (err) {
      addToast(err.message || 'File inspection failed.', 'error');
    } finally {
      setFileScanning(false);
    }
  };

  // Handle file select — automatically scans immediately after file upload
  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      handleScanFile(file);
    }
  };

  // Handle file drop — automatically scans immediately upon drop
  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
      handleScanFile(file);
    }
  };

  // Handle message scan
  const handleScanMessage = async () => {
    if (!messageInput.trim()) {
      addToast('Please enter message text to analyze.', 'warning');
      return;
    }
    setMessageScanning(true);
    setMessageResult(null);
    try {
      const res = await scanMessage(messageInput);
      setMessageResult(res);
      if (res.risk_score >= 65) {
        addToast('High risk scam indicators detected!', 'error');
      } else if (res.risk_score >= 35) {
        addToast('Suspicious patterns found.', 'warning');
      } else {
        addToast('Message appears clean.', 'success');
      }
    } catch (err) {
      addToast(err.message || 'Message scan failed.', 'error');
    } finally {
      setMessageScanning(false);
    }
  };

  const handleReportFp = async () => {
    try {
      await reportFalsePositive(fpModal.scanId, fpReason);
      addToast('Feedback submitted! Thank you for improving detection accuracy.', 'success');
      setFpModal({ open: false, scanId: '' });
      setFpReason('');
    } catch (err) {
      addToast(err.message || 'Could not submit report.', 'error');
    }
  };

  return (
    <div className="device-scanner-page">
      <header className="page-header">
        <div className="header-pill">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span>Device & Threat Security Engine</span>
        </div>
        <h1 className="page-title">Device Security Scanner</h1>
        <p className="page-subtitle">
          On-demand security analysis for user-authorized files, SMS fraud alerts, and payment lures.
        </p>
      </header>

      {/* Tabs */}
      <div className="scanner-tabs">
        <button
          className={`scanner-tab-btn ${activeTab === 'file' ? 'active' : ''}`}
          onClick={() => setActiveTab('file')}
        >
          <FileCode className="w-5 h-5 mr-2" />
          On-Device File Scanner
        </button>
        <button
          className={`scanner-tab-btn ${activeTab === 'message' ? 'active' : ''}`}
          onClick={() => setActiveTab('message')}
        >
          <MessageSquare className="w-5 h-5 mr-2" />
          Scam Message & Payment Analyzer
        </button>
      </div>

      {/* Tab 1: File Scanner */}
      {activeTab === 'file' && (
        <div className="tab-content">
          <div className="card file-upload-card">
            <div
              className={`dropzone ${dragOver ? 'drag-over' : ''} ${selectedFile ? 'has-file' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                className="hidden-file-input"
              />
              <div className="dropzone-icon">
                {selectedFile ? <FileCheck className="w-10 h-10 text-emerald-400" /> : <Upload className="w-10 h-10 text-blue-400" />}
              </div>
              {selectedFile ? (
                <div className="selected-file-meta">
                  <h3>{selectedFile.name}</h3>
                  <p>{(selectedFile.size / 1024).toFixed(1)} KB • Click or drop new file to replace</p>
                </div>
              ) : (
                <div className="dropzone-prompt">
                  <h3>Choose a file or drag & drop it here</h3>
                  <p>Supports documents, archives (.zip), images, and binaries up to 25 MB</p>
                </div>
              )}
            </div>

            {/* Active Scanning Animation */}
            {fileScanning && (
              <div className="file-scanning-banner">
                <div className="scanning-banner-content">
                  <RefreshCw className="w-5 h-5 text-blue-400 animate-spin flex-shrink-0" />
                  <div className="scanning-text-wrap">
                    <span className="scanning-title">Analyzing File: Computing Cryptographic Hashes & Parsing Signatures...</span>
                    <span className="scanning-sub">Validating headers, section tables, and threat database matching in memory</span>
                  </div>
                </div>
                <div className="scanning-progress-bar">
                  <div className="scanning-progress-fill" />
                </div>
              </div>
            )}

            <div className="scanner-action-bar">
              <button
                className="btn btn-primary"
                onClick={() => handleScanFile(selectedFile)}
                disabled={!selectedFile || fileScanning}
              >
                {fileScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin mr-2" />
                    Analyzing Signatures & Hashes...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4 mr-2" />
                    {selectedFile && fileResult ? 'Re-scan File' : 'Scan File for Threats'}
                  </>
                )}
              </button>
              {selectedFile && (
                <button
                  className="btn btn-secondary"
                  onClick={() => { setSelectedFile(null); setFileResult(null); }}
                  disabled={fileScanning}
                >
                  <Trash2 className="w-4 h-4 mr-1" />
                  Clear
                </button>
              )}
            </div>

            {/* Privacy Guarantee Banner */}
            <div className="privacy-callout">
              <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>
                <strong>Privacy & Safety Guarantee:</strong> Files are analyzed in-memory without OS execution.
                Buffers are purged immediately after header and signature extraction.
              </span>
            </div>
          </div>

          {/* File Result Display */}
          <AnimatePresence>
            {fileResult && (
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                className={`card result-card verdict-${fileResult.verdict.toLowerCase()}`}
              >
                <div className="result-header">
                  <div className="verdict-badge">
                    {fileResult.verdict === 'Clean' ? (
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    ) : fileResult.verdict === 'Suspicious' ? (
                      <ShieldQuestion className="w-6 h-6 text-amber-400" />
                    ) : (
                      <ShieldAlert className="w-6 h-6 text-rose-500" />
                    )}
                    <div>
                      <span className="verdict-label">Verdict: {fileResult.verdict}</span>
                      <span className="category-label">{fileResult.threat_category}</span>
                    </div>
                  </div>
                  <div className="risk-meter">
                    <span className="risk-num">{fileResult.risk_score}</span>
                    <span className="risk-sub">/ 100 Risk</span>
                  </div>
                </div>

                <div className="result-grid">
                  <div className="result-prop">
                    <span className="prop-key">Detected Header Signature:</span>
                    <span className="prop-val">{fileResult.detected_type}</span>
                  </div>
                  <div className="result-prop">
                    <span className="prop-key">SHA-256 Hash:</span>
                    <span className="prop-val font-mono text-xs">{fileResult.sha256}</span>
                  </div>
                  <div className="result-prop">
                    <span className="prop-key">File Size:</span>
                    <span className="prop-val">{fileResult.formatted_size}</span>
                  </div>
                  <div className="result-prop">
                    <span className="prop-key">Antivirus Engine:</span>
                    <span className="prop-val">{fileResult.antivirus_adapter}</span>
                  </div>
                </div>

                {fileResult.reasons?.length > 0 && (
                  <div className="evidence-section">
                    <h4>Inspection Evidence & Findings:</h4>
                    <ul>
                      {fileResult.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {fileResult.pe_details && (
                  <div className="pe-details-section">
                    <h4>Windows PE Architecture & Section Headers:</h4>
                    <p className="pe-meta-sub">
                      Architecture: <strong>{fileResult.pe_details.architecture}</strong> • Total Sections: <strong>{fileResult.pe_details.section_count}</strong>
                    </p>
                    {fileResult.pe_details.sections?.length > 0 && (
                      <div className="file-list-preview">
                        {fileResult.pe_details.sections.map((sec, idx) => (
                          <span key={idx} className="archive-tag">{sec}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {fileResult.archive_details && (
                  <div className="archive-section">
                    <h4>Safe Archive Inspection (Zip Entries):</h4>
                    <p>Entries: {fileResult.archive_details.entry_count} files ({fileResult.archive_details.executable_entries?.length || 0} executables)</p>
                    <div className="file-list-preview">
                      {fileResult.archive_details.contained_files.map((cf, idx) => (
                        <span key={idx} className="archive-tag">{cf}</span>
                      ))}
                    </div>
                  </div>
                )}

                {fileResult.recommendations?.length > 0 && (
                  <div className="actions-section">
                    <h4>Recommended Actions:</h4>
                    <ul>
                      {fileResult.recommendations.map((rec, i) => (
                        <li key={i}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="card-footer-actions">
                  <button
                    className="btn btn-outline text-xs"
                    onClick={() => setFpModal({ open: true, scanId: fileResult.scan_id })}
                  >
                    Report Incorrect Verdict (False Positive)
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Tab 2: Scam Message Analyzer */}
      {activeTab === 'message' && (
        <div className="tab-content">
          <div className="card message-scanner-card">
            <h3>Analyze Suspicious Message, SMS or Payment Alert</h3>
            <p className="hint-text">
              Paste suspicious messages, WhatsApp forwards, banking alerts, or lottery notifications.
            </p>

            <textarea
              className="message-textarea"
              rows={5}
              placeholder="Paste suspicious SMS text, banking alerts, lottery notice, or payment requests here..."
              value={messageInput}
              onChange={(e) => setMessageInput(e.target.value)}
            />

            <div className="sample-chips">
              <span className="chips-label">Quick Samples:</span>
              {SAMPLE_SCAM_MESSAGES.map((samp, idx) => (
                <button
                  key={idx}
                  className="sample-chip"
                  onClick={() => setMessageInput(samp.text)}
                >
                  {samp.title}
                </button>
              ))}
            </div>

            <div className="scanner-action-bar">
              <button
                className="btn btn-primary"
                onClick={handleScanMessage}
                disabled={!messageInput.trim() || messageScanning}
              >
                {messageScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin mr-2" />
                    Analyzing Social Engineering Signals...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4 mr-2" />
                    Analyze Message
                  </>
                )}
              </button>
              {messageInput && (
                <button
                  className="btn btn-secondary"
                  onClick={() => { setMessageInput(''); setMessageResult(null); }}
                  disabled={messageScanning}
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Message Result Display */}
          <AnimatePresence>
            {messageResult && (
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                className={`card result-card verdict-${messageResult.risk_score >= 65 ? 'malicious' : messageResult.risk_score >= 35 ? 'suspicious' : 'clean'}`}
              >
                <div className="result-header">
                  <div className="verdict-badge">
                    {messageResult.risk_score >= 65 ? (
                      <AlertTriangle className="w-6 h-6 text-rose-500" />
                    ) : messageResult.risk_score >= 35 ? (
                      <ShieldQuestion className="w-6 h-6 text-amber-400" />
                    ) : (
                      <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    )}
                    <div>
                      <span className="verdict-label">Verdict: {messageResult.verdict}</span>
                      <span className="category-label">{messageResult.threat_category}</span>
                    </div>
                  </div>
                  <div className="risk-meter">
                    <span className="risk-num">{messageResult.risk_score}</span>
                    <span className="risk-sub">/ 100 Risk</span>
                  </div>
                </div>

                {messageResult.reasons?.length > 0 && (
                  <div className="evidence-section">
                    <h4>Identified Fraud Indicators:</h4>
                    <ul>
                      {messageResult.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {messageResult.extracted_links?.length > 0 && (
                  <div className="archive-section">
                    <h4>Embedded Link Analysis:</h4>
                    {messageResult.extracted_links.map((link, idx) => (
                      <div key={idx} className="link-item-row">
                        <span className="link-url">{link.url}</span>
                        <span className={`link-verdict-tag ${link.risk_score >= 70 ? 'danger' : 'safe'}`}>
                          {link.verdict} ({link.risk_score}% risk)
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {messageResult.safe_actions?.length > 0 && (
                  <div className="actions-section">
                    <h4>Safety & Protective Next Steps:</h4>
                    <ul>
                      {messageResult.safe_actions.map((act, i) => (
                        <li key={i}>{act}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="card-footer-actions">
                  <button
                    className="btn btn-outline text-xs"
                    onClick={() => setFpModal({ open: true, scanId: messageResult.scan_id })}
                  >
                    Report False Positive
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* False Positive Modal */}
      {fpModal.open && (
        <div className="modal-backdrop" onClick={() => setFpModal({ open: false, scanId: '' })}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Report False Positive</h3>
            <p>Help us calibrate our AI models and heuristic detection rules.</p>
            <textarea
              className="fp-textarea"
              rows={3}
              placeholder="Describe why you believe this verdict was incorrect..."
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
            />
            <div className="modal-actions">
              <button
                className="btn btn-secondary"
                onClick={() => setFpModal({ open: false, scanId: '' })}
              >
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleReportFp}>
                Submit Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DeviceScanner;
