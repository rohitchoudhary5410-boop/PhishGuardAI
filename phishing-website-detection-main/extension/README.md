# PhishGuard AI — Chrome / Edge Browser Extension

A Manifest V3 browser extension for real-time navigation protection, intercepting high-risk phishing websites before credentials or private data can be entered.

## Features
- **Real-Time URL Checking**: Inspects destination websites using the local detection engine and Flask backend API (`/api/scan/url`).
- **Interception Warning Page**: Redirects high-risk phishing and brand impersonation portals to an isolated warning screen.
- **Fail-Safe Operation**: 3.5s connection timeout ensures slow networks or offline local server never freeze browser navigation.
- **Privacy-Preserving**: Only destination URLs are evaluated against the local endpoint. Zero browsing history is collected or shared.
- **User Override Support**: Users can choose "Proceed Anyway" or return to safety.

## How to Install in Chrome / Edge

1. Open **Google Chrome** or **Microsoft Edge**.
2. Navigate to `chrome://extensions` or `edge://extensions`.
3. Enable **Developer Mode** (toggle in top right corner).
4. Click **Load unpacked**.
5. Select the `extension/` folder inside this repository:
   `d:\Infinity Coder\phishing-website-detection-main\extension`
6. Pin the **PhishGuard AI** icon to your toolbar.
7. Ensure your backend is running (`http://localhost:5000`).

## Permissions Breakdown
- `storage`: Preserves local protection on/off toggles and scan counters.
- `tabs`: Reads the active navigation destination URL to compare with known threat models.
- `host_permissions: ["http://*/*", "https://*/*"]`: Required to inspect web navigation destinations across the web.
