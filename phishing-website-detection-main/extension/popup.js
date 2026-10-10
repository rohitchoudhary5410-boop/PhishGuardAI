document.addEventListener("DOMContentLoaded", async () => {
  const toggle = document.getElementById("guardToggle");
  const dot = document.getElementById("shieldDot");
  const title = document.getElementById("statusTitle");
  const sub = document.getElementById("statusSub");
  const scanned = document.getElementById("scannedNum");
  const blocked = document.getElementById("blockedNum");

  const data = await chrome.storage.local.get(["protectionEnabled", "scannedCount", "blockedCount"]);
  const isEnabled = data.protectionEnabled !== false;

  toggle.checked = isEnabled;
  updateUI(isEnabled);
  scanned.textContent = (data.scannedCount || 0).toLocaleString();
  blocked.textContent = (data.blockedCount || 0).toLocaleString();

  toggle.addEventListener("change", () => {
    const nextState = toggle.checked;
    chrome.storage.local.set({ protectionEnabled: nextState });
    updateUI(nextState);
  });

  function updateUI(active) {
    if (active) {
      dot.classList.remove("disabled");
      title.textContent = "Protection Active";
      title.style.color = "#10b981";
      sub.textContent = "Monitoring active tab navigation";
    } else {
      dot.classList.add("disabled");
      title.textContent = "Protection Paused";
      title.style.color = "#ef4444";
      sub.textContent = "Background navigation checks disabled";
    }
  }
});
