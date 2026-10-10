const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url") || "Unknown Destination";
const riskScore = params.get("risk") || "85";
const category = params.get("category") || "Phishing Website";
const reason = params.get("reason") || "Identified as deceptive by AI Model";

document.getElementById("targetUrl").textContent = targetUrl;
document.getElementById("threatCategory").textContent = category;
document.getElementById("detectionReason").textContent = reason;
document.getElementById("riskBadge").textContent = `${riskScore}% PHISHING RISK`;

document.getElementById("backBtn").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
});

document.getElementById("proceedBtn").addEventListener("click", () => {
  if (confirm("Warning: Visiting this site may compromise your credentials or security. Proceed anyway?")) {
    chrome.runtime.sendMessage({ action: "overrideThreat", url: targetUrl });
  }
});
