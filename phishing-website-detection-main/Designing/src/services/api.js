import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

/* ONE switch for mock vs live.
   This used to be a `const USE_MOCK = true` declared separately inside each of
   the five API functions, so turning the backend on meant five edits and any one
   of them could be missed silently. Mock stays the default so the app still runs
   with no backend; set VITE_USE_MOCK=false in Designing/.env to go live. */
export const IS_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  // Live scans do DNS, WHOIS, TLS and HTTP lookups per URL, so 30s is not
  // generous for a bulk run — bulk gets its own longer timeout below.
  timeout: 45000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/* Maps the Scanner's advanced-input names to the model's real feature names.
   The model has no equivalent for the panel's old `special_chars` or
   `url_entropy` fields — it carries ~85 separate per-character counts instead of
   one aggregate, and no entropy feature at all — so those are gone from the UI
   rather than being sent and silently dropped. */
export const ADVANCED_FEATURE_MAP = {
  length_url: 'length_url',
  qty_redirects: 'qty_redirects',
  url_shortened: 'url_shortened',
  tls_ssl_certificate: 'tls_ssl_certificate',
  time_domain_activation: 'time_domain_activation',
  qty_dot_domain: 'qty_dot_domain',
};

// Turns the form's string values into numbers and drops blanks, so an untouched
// field means "extract it" rather than "override with empty".
const toOverrides = (values) => {
  if (!values) return undefined;
  const overrides = {};
  Object.entries(values).forEach(([key, value]) => {
    if (value === '' || value === null || value === undefined) return;
    if (!ADVANCED_FEATURE_MAP[key]) return;
    const numeric = Number(value);
    if (!Number.isNaN(numeric)) overrides[key] = numeric;
  });
  return Object.keys(overrides).length > 0 ? overrides : undefined;
};

// Surfaces the backend's own message instead of axios's generic one, so a
// failure says what actually went wrong.
const describeError = (error, fallback) => {
  const message = error?.response?.data?.message;
  if (message) return new Error(message);
  if (error?.code === 'ERR_NETWORK') {
    return new Error(
      `Cannot reach the prediction API at ${API_BASE_URL}. Is the backend running?`
    );
  }
  return new Error(error?.message || fallback);
};

// ---- Mock Data Helpers ----
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const generateMockPrediction = (url) => {
  const phishingKeywords = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'paypal', 'netflix', 'free', 'win', 'prize'];
  const isPhishing = phishingKeywords.some((kw) => url.toLowerCase().includes(kw)) || Math.random() > 0.6;
  const isSuspicious = !isPhishing && Math.random() > 0.5;

  /* NOTE: this is a keyword match plus a coin flip. It is NOT a model.
     `model` below says so explicitly — it previously claimed 'Random Forest',
     which made simulated output indistinguishable from a real prediction.
     Because the keyword list contains legitimate brand names, netflix.com and
     accounts.google.com are always flagged, while a URL containing no keyword
     gets a 40% chance of "Phishing" regardless of what it is. */
  const SIMULATED = 'Simulated — no model';

  /* Feature keys below are the model's REAL names, matching what the live
     backend returns, so the demo previews the true response shape. They used to
     be invented labels — `special_chars`, `url_entropy`, `subdomain_count`,
     `https` — none of which exist in the 111-feature model, and two of which
     have no equivalent at all. `impact` values mirror the model's actual
     importance ranking (directory_length dominates at roughly double the next
     feature). */
  if (isPhishing) {
    return {
      prediction: 'Phishing',
      probability: +(0.85 + Math.random() * 0.14).toFixed(3),
      risk_score: Math.floor(75 + Math.random() * 25),
      model: SIMULATED,
      scan_id: `scan_${Date.now()}`,
      scan_time: new Date().toISOString(),
      url,
      features: {
        directory_length: { label: 'Directory path length', value: Math.floor(Math.random() * 60) + 40, risk: 'high_risk', impact: 1.0, description: 'Path is far longer than the training average.' },
        time_domain_activation: { label: 'Domain age (days)', value: Math.floor(Math.random() * 30) + 1, risk: 'high_risk', impact: 0.5, description: 'Domain was registered very recently.' },
        qty_dollar_directory: { label: "'$' characters in path", value: Math.floor(Math.random() * 3) + 1, risk: 'high_risk', impact: 0.4, description: 'Unusual characters present in the path.' },
        qty_dot_file: { label: "'.' characters in filename", value: Math.floor(Math.random() * 3) + 2, risk: 'medium_risk', impact: 0.35, description: 'Filename contains multiple dots.' },
        length_url: { label: 'Full URL length', value: url.length, risk: 'high_risk', impact: 0.29, description: 'URL length exceeds typical legitimate patterns.' },
        ttl_hostname: { label: 'DNS TTL (seconds)', value: Math.floor(Math.random() * 300) + 60, risk: 'medium_risk', impact: 0.21, description: 'Short DNS TTL, common in fast-rotating infrastructure.' },
        tls_ssl_certificate: { label: 'Valid TLS certificate', value: 0, risk: 'high_risk', impact: 0.12, description: 'No valid certificate was presented.' },
        qty_redirects: { label: 'Redirect count', value: Math.floor(Math.random() * 4) + 2, risk: 'medium_risk', impact: 0.1, description: 'Multiple redirects before the final page.' },
      },
    };
  }

  if (isSuspicious) {
    return {
      prediction: 'Suspicious',
      probability: +(0.45 + Math.random() * 0.25).toFixed(3),
      risk_score: Math.floor(35 + Math.random() * 30),
      model: SIMULATED,
      scan_id: `scan_${Date.now()}`,
      scan_time: new Date().toISOString(),
      url,
      features: {
        directory_length: { label: 'Directory path length', value: Math.floor(Math.random() * 20) + 12, risk: 'medium_risk', impact: 1.0, description: 'Path is somewhat longer than average.' },
        time_domain_activation: { label: 'Domain age (days)', value: Math.floor(Math.random() * 200) + 60, risk: 'medium_risk', impact: 0.5, description: 'Domain has moderate age.' },
        qty_dollar_directory: { label: "'$' characters in path", value: 0, risk: 'low_risk', impact: 0.4, description: 'No unusual characters in the path.' },
        qty_dot_file: { label: "'.' characters in filename", value: 1, risk: 'low_risk', impact: 0.35, description: 'Filename has a single extension.' },
        length_url: { label: 'Full URL length', value: url.length, risk: 'medium_risk', impact: 0.29, description: 'URL length is moderately unusual.' },
        ttl_hostname: { label: 'DNS TTL (seconds)', value: Math.floor(Math.random() * 3000) + 600, risk: 'low_risk', impact: 0.21, description: 'DNS TTL is within a normal range.' },
        tls_ssl_certificate: { label: 'Valid TLS certificate', value: 1, risk: 'low_risk', impact: 0.12, description: 'A valid certificate was presented.' },
        qty_redirects: { label: 'Redirect count', value: 1, risk: 'low_risk', impact: 0.1, description: 'A single redirect was followed.' },
      },
    };
  }

  return {
    prediction: 'Legitimate',
    probability: +(0.88 + Math.random() * 0.11).toFixed(3),
    risk_score: Math.floor(2 + Math.random() * 12),
    model: SIMULATED,
    scan_id: `scan_${Date.now()}`,
    scan_time: new Date().toISOString(),
    url,
    features: {
      directory_length: { label: 'Directory path length', value: Math.floor(Math.random() * 10), risk: 'low_risk', impact: 1.0, description: 'Path length is within the normal range.' },
      time_domain_activation: { label: 'Domain age (days)', value: Math.floor(Math.random() * 3000) + 365, risk: 'low_risk', impact: 0.5, description: 'Domain has been registered for a long period.' },
      qty_dollar_directory: { label: "'$' characters in path", value: 0, risk: 'low_risk', impact: 0.4, description: 'No unusual characters in the path.' },
      qty_dot_file: { label: "'.' characters in filename", value: 0, risk: 'low_risk', impact: 0.35, description: 'No filename segment present.' },
      length_url: { label: 'Full URL length', value: url.length, risk: 'low_risk', impact: 0.29, description: 'URL length is within the normal range.' },
      ttl_hostname: { label: 'DNS TTL (seconds)', value: Math.floor(Math.random() * 8000) + 3000, risk: 'low_risk', impact: 0.21, description: 'Long DNS TTL, typical of stable hosting.' },
      tls_ssl_certificate: { label: 'Valid TLS certificate', value: 1, risk: 'low_risk', impact: 0.12, description: 'A valid certificate was presented.' },
      qty_redirects: { label: 'Redirect count', value: 0, risk: 'low_risk', impact: 0.1, description: 'No redirects were followed.' },
    },
  };
};

// ---- API Functions ----
// Every one gates on the shared IS_MOCK flag. In live mode a failure throws with
// a useful message rather than falling back to simulated data — a silent fallback
// would leave the user unable to tell a real verdict from a fabricated one.

/**
 * Scan a single URL for phishing detection.
 * `advancedFeatures` are optional overrides keyed by real model feature names.
 */
export const scanUrl = async (url, advancedFeatures = null) => {
  if (IS_MOCK) {
    await delay(3500); // Simulate scanning
    return generateMockPrediction(url);
  }

  try {
    const overrides = toOverrides(advancedFeatures);
    const response = await apiClient.post('/predict', {
      url,
      ...(overrides ? { features: overrides } : {}),
    });
    return response.data;
  } catch (error) {
    throw describeError(error, 'The scan could not be completed.');
  }
};

/**
 * Bulk scan from CSV data
 */
export const bulkScan = async (urls) => {
  if (IS_MOCK) {
    const results = [];
    for (const url of urls) {
      await delay(300);
      results.push(generateMockPrediction(url));
    }
    return results;
  }

  try {
    // One request; the backend fans out across a thread pool. Live extraction is
    // 1-4s per URL, so the timeout scales with the batch and is generous.
    const response = await apiClient.post(
      '/bulk-scan',
      { urls },
      { timeout: Math.max(60000, urls.length * 6000) }
    );
    return response.data;
  } catch (error) {
    throw describeError(error, 'The bulk scan could not be completed.');
  }
};

/**
 * Get scan history
 */
export const getScanHistory = async (filters = {}) => {
  if (IS_MOCK) {
    await delay(800);
    const { mockScanHistory } = await import('../data/mockData');
    return mockScanHistory;
  }

  try {
    const response = await apiClient.get('/history', { params: filters });
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not load scan history.');
  }
};

/**
 * Get analytics data.
 * Live mode aggregates only what this backend process has actually scanned, so
 * it legitimately starts empty.
 */
export const getAnalytics = async (timeRange = '30D') => {
  if (IS_MOCK) {
    await delay(600);
    const { mockAnalytics } = await import('../data/mockData');
    return mockAnalytics;
  }

  try {
    const response = await apiClient.get('/analytics', { params: { range: timeRange } });
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not load analytics.');
  }
};

/**
 * Get model metrics
 */
export const getModelMetrics = async () => {
  if (IS_MOCK) {
    await delay(500);
    const { mockModelMetrics } = await import('../data/mockData');
    return mockModelMetrics;
  }

  try {
    const response = await apiClient.get('/model-metrics');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not load model metrics.');
  }
};

/**
 * Check if the backend API is reachable and responding.
 */
export const checkApiHealth = async () => {
  if (IS_MOCK) return true;
  try {
    const response = await apiClient.get('/health', { timeout: 3000 });
    return response.status === 200;
  } catch (error) {
    return false;
  }
};

/**
 * Scan an email or message for phishing, misleading activities, and spoofing
 */
export const scanEmail = async (emailPayload) => {
  try {
    const response = await apiClient.post('/api/email/scan', emailPayload);
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not scan email threat.');
  }
};

/**
 * Fetch preset email attack scenarios for demonstrations
 */
export const getEmailPresets = async () => {
  try {
    const response = await apiClient.get('/api/email/presets');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not load preset emails.');
  }
};

/**
 * Sync and scan Gmail messages (live IMAP, OAuth, or sandbox demonstration)
 */
export const syncGmail = async (credentials = {}) => {
  try {
    const payload = typeof credentials === 'string'
      ? { access_token: credentials }
      : credentials;
    // IMAP timeout is 15s + time to fetch and analyze emails, so 60s is needed
    const response = await apiClient.post('/api/email/gmail-sync', payload, {
      timeout: 60000,
    });
    return response.data;
  } catch (error) {
    throw describeError(error, error.response?.data?.message || 'Could not sync Gmail messages.');
  }
};

/**
 * Get email scan history
 */
export const getEmailHistory = async () => {
  try {
    const response = await apiClient.get('/api/email/history');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not load email history.');
  }
};

// ---------------------------------------------------------------------------
// Security Platform, File Scanner & Scam Message Endpoints
// ---------------------------------------------------------------------------

/**
 * Get real background protection status and engine metrics
 */
export const getSecurityStatus = async () => {
  if (IS_MOCK) {
    return {
      status: 'ACTIVE',
      is_active: true,
      uptime_seconds: 3600,
      last_check: new Date().toISOString(),
      total_scans: 142,
      threats_blocked: 38,
      clean_items: 104,
      false_positives: 2,
      protection_mode: 'Hybrid (Web Dashboard + Local Heuristics)',
    };
  }
  try {
    const response = await apiClient.get('/api/security/status');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not fetch security status.');
  }
};

/**
 * Start or resume background monitoring
 */
export const startProtection = async () => {
  if (IS_MOCK) return { status: 'ACTIVE', message: 'Protection started (Mock)' };
  try {
    const response = await apiClient.post('/api/security/start');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not start protection.');
  }
};

/**
 * Pause background monitoring
 */
export const pauseProtection = async () => {
  if (IS_MOCK) return { status: 'PAUSED', message: 'Protection paused (Mock)' };
  try {
    const response = await apiClient.post('/api/security/pause');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not pause protection.');
  }
};

/**
 * Stop background monitoring
 */
export const stopProtection = async () => {
  if (IS_MOCK) return { status: 'STOPPED', message: 'Protection stopped (Mock)' };
  try {
    const response = await apiClient.post('/api/security/stop');
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not stop protection.');
  }
};

/**
 * Scan a user-selected file without execution
 */
export const scanFile = async (fileObj) => {
  if (IS_MOCK) {
    await delay(1500);
    const isEicar = fileObj.name?.toLowerCase().includes('eicar');
    const isTrustedApp = /chrome|firefox|edge|notepad|calc|code|python|zoom/i.test(fileObj.name || '');
    const isSuspicious = !isTrustedApp && (fileObj.name?.endsWith('.exe') || fileObj.name?.endsWith('.scr') || fileObj.name?.endsWith('.bat'));
    return {
      filename: fileObj.name,
      file_size_bytes: fileObj.size,
      formatted_size: `${(fileObj.size / 1024).toFixed(1)} KB`,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      detected_type: isTrustedApp
        ? 'Windows PE Executable (x86-64 AMD64)'
        : isSuspicious
        ? 'PE Executable (Windows)'
        : 'PDF / Document File',
      file_category: isTrustedApp || isSuspicious ? 'executable' : 'document',
      verdict: isEicar ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Clean',
      threat_category: isEicar
        ? 'EICAR Test Signature'
        : isTrustedApp
        ? 'Verified Application (Google Chrome / Trusted Software)'
        : isSuspicious
        ? 'Unverified Executable Binary'
        : 'Clean File',
      risk_score: isEicar ? 95 : isSuspicious ? 40 : 5,
      reasons: isEicar
        ? ['Matches standard antivirus test signature.']
        : isTrustedApp
        ? ['Application profile matches standard verified software (Google Chrome).', 'Valid Windows PE header structure verified with clean sections.', 'Cryptographic hash verified clean against threat database.']
        : isSuspicious
        ? ['File contains executable binary code. Exercise caution before launching third-party binaries.']
        : ['File structure matches declared extension and contains no malicious macros.'],
      recommendations: isEicar
        ? ['Do not run this file on your operating system.', 'Delete or isolate immediately.']
        : isSuspicious
        ? ['Ensure this file comes from a trusted developer.', 'Verify publisher digital signature.']
        : ['File appears clean and safe to use.'],
      privacy_notice: 'Processed in-memory. No file was stored.',
      timestamp: new Date().toISOString(),
      scan_id: `file_mock_${Date.now()}`
    };
  }

  try {
    const formData = new FormData();
    formData.append('file', fileObj);
    const response = await apiClient.post('/api/scan/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 60000,
    });
    return response.data;
  } catch (error) {
    throw describeError(error, 'File inspection failed.');
  }
};

/**
 * Analyze a suspicious SMS, chat message, or payment alert
 */
export const scanMessage = async (messageText) => {
  if (IS_MOCK) {
    await delay(1200);
    const isUrgent = /urgent|suspended|blocked|immediate|kyc/i.test(messageText);
    const isOtp = /otp|pin|password|cvv/i.test(messageText);
    const risk = isUrgent && isOtp ? 90 : isUrgent || isOtp ? 65 : 15;
    return {
      verdict: risk >= 65 ? 'High Risk Scam' : risk >= 35 ? 'Suspicious Message' : 'Low Risk / Clean',
      threat_category: isOtp ? 'Credential & OTP Harvesting' : isUrgent ? 'Urgent Coercion & Fraud' : 'No Scam Detected',
      risk_score: risk,
      indicators: [
        { category: 'Social Engineering Pattern', matches: ['urgent action required'] }
      ],
      reasons: risk >= 35
        ? ['Contains coercive urgency phrases and requests for sensitive actions.']
        : ['No coercive phishing or fraud keywords found.'],
      safe_actions: [
        'Do NOT share 2FA OTP codes or banking PINs.',
        'Never call phone numbers embedded in unverified SMS.'
      ],
      message_snippet: messageText.slice(0, 100) + '...',
      timestamp: new Date().toISOString(),
      scan_id: `msg_mock_${Date.now()}`
    };
  }

  try {
    const response = await apiClient.post('/api/scan/message', { message: messageText });
    return response.data;
  } catch (error) {
    throw describeError(error, 'Message analysis failed.');
  }
};

/**
 * Unified scan history across all vectors (URLs, Files, Messages, Emails)
 */
export const getUnifiedScanHistory = async (type = 'all', limit = 50) => {
  if (IS_MOCK) {
    const { mockScanHistory } = await import('../data/mockData');
    return mockScanHistory.map((item) => ({
      id: item.scan_id || `scan_${Date.now()}`,
      type: 'url',
      target: item.url,
      verdict: item.prediction,
      risk_score: item.risk_score || (item.prediction === 'Phishing' ? 88 : 12),
      threat_category: item.prediction === 'Phishing' ? 'Phishing URL' : 'Clean Website',
      timestamp: item.scan_time || new Date().toISOString(),
    }));
  }

  try {
    const response = await apiClient.get('/api/scan/history', {
      params: { type, limit }
    });
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not load unified scan history.');
  }
};

/**
 * Report a false positive
 */
export const reportFalsePositive = async (scanId, feedback = '', userVerdict = 'Safe') => {
  if (IS_MOCK) return { status: 'recorded', report_id: `fp_${Date.now()}` };
  try {
    const response = await apiClient.post('/api/security/false-positive', {
      scan_id: scanId,
      feedback,
      user_verdict: userVerdict,
    });
    return response.data;
  } catch (error) {
    throw describeError(error, 'Could not submit false positive report.');
  }
};

export default apiClient;

