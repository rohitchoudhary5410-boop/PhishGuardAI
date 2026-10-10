/**
 * PhishGuard AI — Background Service Worker
 * Real-time navigation monitoring, local caching, and backend security orchestration.
 */

const BACKEND_API = "http://localhost:5000/api/scan/url";
const CACHE_TTL_MS = 1000 * 60 * 30; // 30 minutes cache
const urlCache = new Map();
const userOverrides = new Set();

// Initialize protection state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    protectionEnabled: true,
    blockedCount: 0,
    scannedCount: 0
  });
});

// Check destination URL against backend
async function checkUrlThreat(url) {
  if (urlCache.has(url)) {
    const entry = urlCache.get(url);
    if (Date.now() - entry.timestamp < CACHE_TTL_MS) {
      return entry.data;
    }
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500); // 3.5s timeout for fast navigation

    const response = await fetch(BACKEND_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, with_network: false }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    if (!response.ok) return null;

    const result = await response.json();
    urlCache.set(url, { data: result, timestamp: Date.now() });
    return result;
  } catch (err) {
    // Fail-safe: Network timeout or offline backend should never freeze user navigation
    console.warn("PhishGuard extension query fallback:", err);
    return null;
  }
}

// Observe tabs on navigation
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;

  const url = tab.url;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  if (url.includes("localhost") || url.includes("127.0.0.1") || url.includes("warning.html")) return;

  const storage = await chrome.storage.local.get(["protectionEnabled", "blockedCount", "scannedCount"]);
  if (!storage.protectionEnabled) return;

  // Increment scanned count
  chrome.storage.local.set({ scannedCount: (storage.scannedCount || 0) + 1 });

  // If user previously chose to proceed, bypass check
  if (userOverrides.has(url)) return;

  const assessment = await checkUrlThreat(url);
  if (assessment && assessment.verdict === "Phishing" && assessment.risk_score >= 70) {
    // Update blocked counter
    chrome.storage.local.set({ blockedCount: (storage.blockedCount || 0) + 1 });

    // Redirect to warning page
    const warningUrl = chrome.runtime.getURL("warning.html") + 
      `?url=${encodeURIComponent(url)}` + 
      `&risk=${assessment.risk_score}` + 
      `&category=${encodeURIComponent(assessment.threat_category || "Phishing Website")}` +
      `&reason=${encodeURIComponent((assessment.detection_reasons || [])[0] || "Identified as deceptive by AI Model")}`;

    chrome.tabs.update(tabId, { url: warningUrl });
  }
});

// Handle override message from warning page
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "overrideThreat" && request.url) {
    userOverrides.add(request.url);
    if (sender.tab && sender.tab.id) {
      chrome.tabs.update(sender.tab.id, { url: request.url });
    }
    sendResponse({ success: true });
  }
});
