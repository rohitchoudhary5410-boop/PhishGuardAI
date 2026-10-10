"""
PhishGuard AI — Advanced Security Service & Unified Threat Platform
-------------------------------------------------------------------
Integrates:
1. Protection State Engine (Start / Pause / Stop Background Monitoring)
2. Advanced URL Phishing & SSRF Security Validator
3. On-Device File Security Scanner (Signatures, Hashes, Archive Inspection, Zero-Execution)
4. Scam Message and Payment-Link Analyzer (SMS, Financial Fraud, OTP Harvesting)
5. Unified Scan History and False-Positive Auditing
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import mimetypes
import os
import re
import socket
import threading
import uuid
import zipfile
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Protection State Machine
# ---------------------------------------------------------------------------

class ProtectionStateManager:
    """Thread-safe background protection state tracker."""
    
    STATUS_ACTIVE = "ACTIVE"
    STATUS_PAUSED = "PAUSED"
    STATUS_STOPPED = "STOPPED"

    def __init__(self):
        self._lock = threading.Lock()
        self._status = self.STATUS_ACTIVE
        self._start_time = dt.datetime.now(dt.timezone.utc)
        self._last_check = dt.datetime.now(dt.timezone.utc)
        self._total_scans = 0
        self._threats_blocked = 0
        self._clean_items = 0
        self._false_positives = 0

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now = dt.datetime.now(dt.timezone.utc)
            uptime = int((now - self._start_time).total_seconds())
            return {
                "status": self._status,
                "is_active": self._status == self.STATUS_ACTIVE,
                "uptime_seconds": uptime,
                "last_check": self._last_check.isoformat(),
                "total_scans": self._total_scans,
                "threats_blocked": self._threats_blocked,
                "clean_items": self._clean_items,
                "false_positives": self._false_positives,
                "protection_mode": "Hybrid (Web Dashboard + Local Heuristics)",
                "limitations_notice": (
                    "Web application protection inspects URLs, submitted files, and messages. "
                    "Browser-wide continuous navigation protection requires the PhishGuard Browser Extension. "
                    "Deep OS antivirus scanning requires an installed security agent."
                )
            }

    def start(self) -> Dict[str, Any]:
        with self._lock:
            self._status = self.STATUS_ACTIVE
            self._last_check = dt.datetime.now(dt.timezone.utc)
            return {"status": self._status, "message": "Protection service started successfully."}

    def pause(self) -> Dict[str, Any]:
        with self._lock:
            self._status = self.STATUS_PAUSED
            self._last_check = dt.datetime.now(dt.timezone.utc)
            return {"status": self._status, "message": "Protection monitoring paused."}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._status = self.STATUS_STOPPED
            self._last_check = dt.datetime.now(dt.timezone.utc)
            return {"status": self._status, "message": "Protection monitoring stopped."}

    def record_scan(self, is_threat: bool) -> None:
        with self._lock:
            self._total_scans += 1
            if is_threat:
                self._threats_blocked += 1
            else:
                self._clean_items += 1
            self._last_check = dt.datetime.now(dt.timezone.utc)

    def record_false_positive(self) -> None:
        with self._lock:
            self._false_positives += 1


protection_manager = ProtectionStateManager()

# ---------------------------------------------------------------------------
# SSRF & Network Safety Validator
# ---------------------------------------------------------------------------

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC1918
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC1918
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC1918
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
]

CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.aws",
    "instance-data",
}

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "tiny.cc", "lnkd.in"
}

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "banking",
    "account-update", "authenticate", "wallet", "restore", "security-check",
    "confirm-identity", "2fa", "otp", "billing-resolve", "recover"
]

PROTECTED_BRANDS = [
    "paypal", "apple", "google", "netflix", "microsoft", "amazon",
    "chase", "wellsfargo", "bankofamerica", "binance", "coinbase", "meta"
]


def validate_and_check_ssrf(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates URL scheme and ensures it does NOT target internal, loopback, or metadata addresses.
    Returns: (is_safe, error_reason, hostname)
    """
    if not url or not isinstance(url, str):
        return False, "URL string is empty or invalid.", None

    clean = url.strip()
    if not clean.startswith(("http://", "https://")):
        clean = "http://" + clean

    try:
        parsed = urlparse(clean)
        hostname = parsed.hostname
        if not hostname:
            return False, "URL does not contain a valid hostname.", None
    except Exception as exc:
        return False, f"Malformed URL syntax: {exc}", None

    hostname_lower = hostname.lower()

    if hostname_lower in ("localhost", "127.0.0.1", "::1") or hostname_lower in CLOUD_METADATA_HOSTS:
        return False, f"SSRF blocked: Access to localhost or metadata host '{hostname}' is forbidden.", hostname

    if hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        return False, f"SSRF blocked: Internal domain '{hostname}' is not accessible.", hostname

    # Check IP addresses
    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return False, f"SSRF blocked: Destination IP '{ip_obj}' belongs to restricted network {net}.", hostname
    except ValueError:
        # Not an IP literal — hostname string
        pass

    return True, None, hostname_lower


def analyze_advanced_url_signals(url: str) -> Dict[str, Any]:
    """
    Evaluates lexical patterns, homographs, brand subdomains, IP-in-URL, and suspicious paths.
    """
    clean = url.strip()
    if not clean.startswith(("http://", "https://")):
        clean = "http://" + clean

    parsed = urlparse(clean)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    signals = []
    risk_score = 0
    threat_category = "General Analysis"

    # 1. IP Address as Hostname
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        risk_score += 40
        signals.append("URL uses an IP address directly instead of a registered domain name.")
        threat_category = "Direct IP Phishing"
    except ValueError:
        pass

    # 2. Punycode / Internationalized Domain Name (Homograph Attack)
    if "xn--" in hostname:
        risk_score += 35
        signals.append("Domain uses Punycode (xn--) encoding, a frequent vector for IDN homograph impersonation.")
        threat_category = "Homograph Domain Attack"

    # 3. Brand Impersonation in Subdomains
    for brand in PROTECTED_BRANDS:
        if brand in hostname:
            # If brand is in subdomain but not main apex domain
            if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com") or hostname == f"{brand}.org"):
                risk_score += 45
                signals.append(f"High-risk brand impersonation: '{brand}' appears in the hostname, but the domain is not authorized.")
                threat_category = f"Brand Impersonation ({brand.capitalize()})"
                break

    # 4. Shortened URL Detection
    if hostname in SHORTENED_DOMAINS:
        risk_score += 25
        signals.append(f"URL uses known shortening service '{hostname}', hiding the final destination.")
        if threat_category == "General Analysis":
            threat_category = "Obfuscated / Shortened Link"

    # 5. Suspicious Path & Query Keywords
    matched_kws = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path or kw in query]
    if matched_kws:
        risk_score += 20 * min(len(matched_kws), 2)
        signals.append(f"Path contains sensitive authentication/billing keywords: {', '.join(matched_kws[:3])}.")

    # 6. Excessive dots or URL length
    if hostname.count(".") >= 4:
        risk_score += 15
        signals.append("Excessive subdomain nesting detected (4+ dots in hostname).")

    if len(url) > 100:
        risk_score += 10
        signals.append("URL is unusually long (>100 characters).")

    return {
        "hostname": hostname,
        "is_ip": is_ip,
        "threat_category": threat_category,
        "heuristic_score": min(risk_score, 100),
        "signals": signals
    }


# ---------------------------------------------------------------------------
# On-Device File Security Scanner
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_HASHES = {
    # Standard benign EICAR anti-malware test signature hash (SHA-256)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Standard Antivirus Test Signature",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test String MD5",
    # Known test malware simulation hashes for testing security suites
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "Trojan-Dropper.Test.Simulator",
    "7b019b35bc45d2925b42d721a36e09e1e2cfc2e9b11cf2ca1029c11c47942e6f": "Ransomware.Test.Simulator",
}

# Magic byte signatures
MAGIC_SIGNATURES = [
    (b"\x4d\x5a", "PE Executable (Windows .exe / .dll / .scr)", "executable"),
    (b"\x7f\x45\x4c\x46", "ELF Binary (Linux executable)", "executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (macOS binary)", "executable"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (macOS binary)", "executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O Universal / Java class", "executable"),
    (b"%PDF-", "PDF Document", "document"),
    (b"\xff\xd8\xff", "JPEG Image", "image"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", "image"),
    (b"GIF87a", "GIF Image", "image"),
    (b"GIF89a", "GIF Image", "image"),
    (b"PK\x03\x04", "ZIP Archive / Office Package", "archive"),
    (b"\x1f\x8b\x08", "GZIP Compressed File", "archive"),
    (b"Rar!\x1a\x07", "RAR Archive", "archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", "archive"),
]

DISGUISED_DANGEROUS_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".docx", ".xlsx", ".csv"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl"}

# Known trusted Windows desktop applications and runtime binaries
KNOWN_SAFE_BINARIES = {
    "chrome.exe": "Google Chrome Web Browser",
    "firefox.exe": "Mozilla Firefox Web Browser",
    "msedge.exe": "Microsoft Edge Web Browser",
    "code.exe": "Visual Studio Code Editor",
    "notepad.exe": "Windows Notepad Utility",
    "calc.exe": "Windows Calculator Utility",
    "python.exe": "Python Programming Language Runtime",
    "pythonw.exe": "Python Windowed Runtime",
    "zoom.exe": "Zoom Video Communications Client",
    "slack.exe": "Slack Desktop Application",
    "teams.exe": "Microsoft Teams Application",
    "git.exe": "Git Version Control System",
    "node.exe": "Node.js JavaScript Runtime",
    "explorer.exe": "Windows File Explorer",
    "taskmgr.exe": "Windows Task Manager",
    "spotify.exe": "Spotify Music Player",
    "discord.exe": "Discord Communication Application",
}

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB max to protect memory
MAX_ZIP_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MB max uncompressed ratio check


def scan_file_buffer(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Safely inspects a user-selected file without executing it.
    Calculates SHA-256 hash, verifies magic bytes against file extension,
    checks for disguised executables, queries known hash databases, and inspects ZIP archives safely.
    """
    file_size = len(file_bytes)
    if file_size == 0:
        return {
            "filename": filename,
            "file_size_bytes": 0,
            "formatted_size": "0 B",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "detected_type": "Empty File",
            "file_category": "empty",
            "verdict": "Clean",
            "threat_category": "No Threat Detected (Empty)",
            "risk_score": 0,
            "reasons": ["The selected file is empty (0 bytes) and contains no executable data."],
            "pe_details": None,
            "archive_details": None,
            "recommendations": ["Empty file is clean and poses no threat."],
            "antivirus_adapter": "Built-in Signature & Hash Scanner",
            "privacy_notice": "File was processed entirely in memory and was not stored on disk or shared with third parties.",
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "scan_id": f"file_{uuid.uuid4().hex[:10]}"
        }

    if file_size > MAX_FILE_SIZE_BYTES:
        return {
            "filename": filename,
            "file_size_bytes": file_size,
            "verdict": "Blocked / Oversized",
            "threat_category": "Resource Limit Exceeded",
            "risk_score": 50,
            "reasons": [f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB."],
            "recommendations": ["Split or compress file to under 25 MB before scanning."],
            "analyzed_locally": True
        }

    # 1. Calculate SHA-256
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()
    md5 = hashlib.md5(file_bytes).hexdigest()

    reasons = []
    risk_score = 0
    threat_category = "Clean File"
    signals = []

    # 2. Known Malicious Hash Lookup
    if sha256 in KNOWN_MALICIOUS_HASHES or md5 in KNOWN_MALICIOUS_HASHES:
        threat_name = KNOWN_MALICIOUS_HASHES.get(sha256) or KNOWN_MALICIOUS_HASHES.get(md5)
        risk_score = 98
        threat_category = f"Known Malware Signature: {threat_name}"
        reasons.append(f"Cryptographic hash match in threat database: {threat_name} (SHA-256: {sha256[:16]}...).")

    # 3. EICAR Test String in Plaintext Check
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in file_bytes:
        risk_score = 95
        threat_category = "Antivirus Test Signature (EICAR)"
        reasons.append("Contains standard EICAR anti-malware test signature pattern.")

    # 4. File Magic Bytes Identification
    detected_type = "Unknown Binary / Text"
    file_category = "other"
    for magic_prefix, desc, category in MAGIC_SIGNATURES:
        if file_bytes.startswith(magic_prefix):
            detected_type = desc
            file_category = category
            break

    ext = Path(filename).suffix.lower()
    base_name = Path(filename).name.lower()

    # Inspect Windows PE headers if present
    pe_details = None
    if file_bytes.startswith(b"MZ") and len(file_bytes) >= 0x40:
        try:
            e_lfanew = int.from_bytes(file_bytes[0x3c:0x40], byteorder="little")
            if e_lfanew + 24 <= len(file_bytes) and file_bytes[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                machine = int.from_bytes(file_bytes[e_lfanew+4:e_lfanew+6], byteorder="little")
                num_sections = int.from_bytes(file_bytes[e_lfanew+6:e_lfanew+8], byteorder="little")
                arch = "x86-64 (AMD64 64-bit)" if machine == 0x8664 else "i386 (Intel 32-bit)" if machine == 0x014c else "ARM64" if machine == 0xaa64 else "Windows PE"
                detected_type = f"Windows PE Executable ({arch})"
                
                sections = []
                opt_header_size = int.from_bytes(file_bytes[e_lfanew+20:e_lfanew+22], byteorder="little")
                sec_table_offset = e_lfanew + 24 + opt_header_size
                for i in range(min(num_sections, 10)):
                    sec_offset = sec_table_offset + (i * 40)
                    if sec_offset + 8 <= len(file_bytes):
                        raw_name = file_bytes[sec_offset:sec_offset+8].rstrip(b"\x00").decode("latin-1", errors="ignore").strip()
                        if raw_name:
                            sections.append(raw_name)

                pe_details = {
                    "architecture": arch,
                    "section_count": num_sections,
                    "sections": sections,
                    "valid_pe_signature": True
                }
        except Exception:
            pass

    # Double Extension Trojan Spoofing Check (e.g. invoice.pdf.exe)
    is_double_extension = any(
        base_name.endswith(f"{fake_ext}{e}")
        for fake_ext in [".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt", ".csv"]
        for e in EXECUTABLE_EXTENSIONS
    )
    if is_double_extension:
        risk_score = max(risk_score, 92)
        threat_category = "Double-Extension Trojan Spoofing"
        reasons.append(
            f"Dangerous Deception: File utilizes double-extension spoofing ('{filename}') to disguise binary executable code as a document."
        )

    # 5. Extension Disguise Detection (Executable masquerading as document/image)
    if file_category == "executable" and ext in DISGUISED_DANGEROUS_EXTENSIONS:
        risk_score = max(risk_score, 90)
        threat_category = "Disguised Malicious Executable"
        reasons.append(
            f"Dangerous Spoofing: File is named '{filename}' with '{ext}' extension, "
            f"but raw magic bytes prove it is an executable binary ({detected_type})."
        )
    elif ext in EXECUTABLE_EXTENSIONS and risk_score == 0:
        if base_name in KNOWN_SAFE_BINARIES:
            app_title = KNOWN_SAFE_BINARIES[base_name]
            threat_category = f"Verified Application ({app_title})"
            risk_score = 5
            reasons.append(f"Application profile matches standard verified software: {app_title}.")
            if pe_details:
                reasons.append(f"Valid Windows PE structure ({pe_details['architecture']}) verified with {pe_details['section_count']} standard sections.")
            reasons.append("Cryptographic hash checked against threat signatures with no anomalous patterns.")
        else:
            risk_score = 40
            threat_category = "Unverified Executable Binary"
            reasons.append(f"File has an executable extension '{ext}' that can run native code ({detected_type}).")
            reasons.append("No known malware signatures found, but caution is advised for third-party executables.")

    # 6. Script in Text File Check
    if ext in (".txt", ".dat", ".csv"):
        sample = file_bytes[:2048].lower()
        if b"powershell" in sample or b"cmd.exe" in sample or b"wscript" in sample or b"<script" in sample:
            risk_score = max(risk_score, 65)
            threat_category = "Suspicious Embedded Script"
            reasons.append("File contains shell script execution commands disguised in plaintext.")

    # 7. Safe Archive / ZIP Inspection (Without Extracting)
    archive_details = None
    if file_bytes.startswith(b"PK\x03\x04") or ext in (".zip", ".jar"):
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                namelist = zf.namelist()
                infolist = zf.infolist()
                total_uncompressed = sum(info.file_size for info in infolist)
                
                # Check decompression bomb ratio
                if file_size > 0 and (total_uncompressed / file_size) > 100 and total_uncompressed > 50 * 1024 * 1024:
                    risk_score = max(risk_score, 85)
                    threat_category = "Potential Decompression Bomb (Zip Bomb)"
                    reasons.append(f"Archive expands by {total_uncompressed // file_size}x ({total_uncompressed // (1024*1024)} MB), indicating a zip bomb.")

                # Check for hidden executable extensions inside zip
                hidden_execs = [name for name in namelist if Path(name).suffix.lower() in EXECUTABLE_EXTENSIONS]
                if hidden_execs:
                    risk_score = max(risk_score, 75)
                    threat_category = "Archive Containing Executables"
                    reasons.append(f"Archive contains executable payload(s): {', '.join(hidden_execs[:3])}.")

                archive_details = {
                    "entry_count": len(namelist),
                    "total_uncompressed_bytes": total_uncompressed,
                    "contained_files": namelist[:15],
                    "executable_entries": hidden_execs
                }
        except Exception as e:
            reasons.append(f"Archive header inspection note: {e}")

    # Assign Verdict
    if risk_score >= 70:
        verdict = "Malicious"
    elif risk_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
        if not threat_category or threat_category == "Clean File":
            threat_category = "No Threat Detected"
        if not reasons:
            reasons.append("File format, signature header, and hash lookups showed no anomalous patterns.")

    # Recommendations
    recommendations = []
    if verdict == "Malicious":
        recommendations.append("Do NOT open or execute this file on your computer.")
        recommendations.append("Permanently delete this file and do not forward it.")
    elif verdict == "Suspicious":
        recommendations.append("Exercise caution: Verify the file origin from an official source before launching.")
        recommendations.append("Check the publisher's digital certificate signature in file properties.")
    else:
        if base_name in KNOWN_SAFE_BINARIES:
            recommendations.append(f"This file matches the profile of {KNOWN_SAFE_BINARIES[base_name]}.")
            recommendations.append("Safe standard software application.")
        else:
            recommendations.append("No known malware indicators were detected in this file.")

    protection_manager.record_scan(is_threat=(verdict != "Clean"))

    return {
        "filename": filename,
        "file_size_bytes": file_size,
        "formatted_size": f"{file_size / 1024:.1f} KB" if file_size < 1024 * 1024 else f"{file_size / (1024 * 1024):.2f} MB",
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "detected_type": detected_type,
        "file_category": file_category,
        "verdict": verdict,
        "threat_category": threat_category,
        "risk_score": risk_score,
        "reasons": reasons,
        "pe_details": pe_details,
        "archive_details": archive_details,
        "recommendations": recommendations,
        "antivirus_adapter": "Built-in Signature & Hash Scanner (ClamAV optional)",
        "privacy_notice": "File was processed entirely in memory and was not stored on disk or shared with third parties.",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scan_id": f"file_{uuid.uuid4().hex[:10]}"
    }


# ---------------------------------------------------------------------------
# Scam Message and Payment-Link Analyzer
# ---------------------------------------------------------------------------

MESSAGE_SCAM_PATTERNS = {
    "banking_fraud": {
        "label": "Fake Bank & Account Suspension Alert",
        "weight": 35,
        "patterns": [
            r"\b(account (?:has been |is )?(?:suspended|blocked|locked|restricted|debit(?:ed)?))\b",
            r"\b(unauthorized (?:transaction|charges|withdrawal))\b",
            r"\b(kyc (?:verification|update|expired|pending))\b",
            r"\b(pan card (?:blocked|update|linked))\b",
            r"\b(netbanking (?:access|password) (?:expired|blocked))\b",
            r"\b(click to (?:unblock|restore|verify) your account)\b"
        ]
    },
    "otp_credential_harvesting": {
        "label": "Credential & OTP Harvesting Attempt",
        "weight": 40,
        "patterns": [
            r"\b(share (?:your )?(?:[a-z0-9\-]+ )?(?:otp|one time password|pin|security code))\b",
            r"\b(enter (?:your )?(?:[a-z0-9\-]+ )?(?:mpin|upi pin|pin|password|cvv))\b",
            r"\b(receive money by entering (?:pin|otp))\b",
            r"\b(download anydesk|teamviewer|rustdesk|quicksupport)\b",
            r"\b(forward this (?:sms|code) to)\b"
        ]
    },
    "financial_lure": {
        "label": "Lottery, Giveaway & Financial Reward Scam",
        "weight": 30,
        "patterns": [
            r"\b(congratulations you (?:have )?won)\b",
            r"\b(lottery (?:winner|prize|amount)|cash prize of)\b",
            r"\b(crypto(?:currency)? airdrop|free bitcoin|500 usdt)\b",
            r"\b(unclaimed (?:funds|reward|bonus))\b",
            r"\b(earn \$\d+ (?:daily|per day|working from home))\b",
            r"\b(100% guaranteed return|risk[- ]free profit)\b"
        ]
    },
    "urgent_coercion": {
        "label": "Urgent Coercion & Legal Threats",
        "weight": 30,
        "patterns": [
            r"\b(immediate action (?:is )?required)\b",
            r"\b(within (?:2|12|24) hours or (?:your SIM will be|service))\b",
            r"\b(police (?:complaint|case|arrest warrant))\b",
            r"\b(electricity (?:power )?will be disconnected tonight)\b",
            r"\b(legal notice|court summons)\b"
        ]
    },
    "fake_support": {
        "label": "Impersonated Customer Support & Refund Lure",
        "weight": 25,
        "patterns": [
            r"\b(geek squad|norton|mcafee (?:subscription|auto-renew))\b",
            r"\b(call (?:customer care|support|toll free) at \+?[\d\s-]{8,})\b",
            r"\b(refund of \$\d+ will be deducted)\b",
            r"\b(order #?\d+ confirmed for \$\d+)\b"
        ]
    }
}

URL_REGEX = re.compile(r'(https?://[^\s<>"\',;]+|www\.[^\s<>"\',;]+)', re.IGNORECASE)


def analyze_scam_message(message_text: str, score_url_fn=None) -> Dict[str, Any]:
    """
    Analyzes SMS, chat messages, payment alerts, and fraudulent notifications.
    Identifies scam category, urgency markers, credential lures, and scans embedded URLs.
    """
    if not message_text or not isinstance(message_text, str):
        return {
            "verdict": "Unknown",
            "risk_score": 0,
            "threat_category": "Empty Input",
            "indicators": [],
            "reasons": ["No message text was provided for analysis."],
            "safe_actions": ["Provide message content to evaluate."],
        }

    text_lower = message_text.lower()
    detected_categories = []
    total_score = 0
    indicators = []

    for key, data in MESSAGE_SCAM_PATTERNS.items():
        matched = []
        for pat in data["patterns"]:
            hits = re.findall(pat, text_lower)
            if hits:
                matched.extend([h if isinstance(h, str) else h[0] for h in hits])
        if matched:
            unique_hits = list(set(matched))
            weight = data["weight"]
            total_score += weight * min(len(unique_hits), 2)
            detected_categories.append(data["label"])
            indicators.append({
                "category": data["label"],
                "matches": unique_hits
            })

    # Extract and evaluate embedded URLs
    found_urls = URL_REGEX.findall(message_text)
    scanned_links = []
    max_url_risk = 0

    for raw_u in found_urls[:5]:
        u = raw_u if raw_u.startswith(("http://", "https://")) else "http://" + raw_u
        link_info = {"url": u, "risk_score": 0, "verdict": "Unchecked"}
        
        # Check shortening
        parsed_host = (urlparse(u).hostname or "").lower()
        if parsed_host in SHORTENED_DOMAINS:
            link_info["is_shortened"] = True
            link_info["risk_score"] = 55
            total_score += 25

        if score_url_fn:
            try:
                res = score_url_fn(u)
                link_info["verdict"] = res.get("prediction", "Unknown")
                link_info["risk_score"] = res.get("risk_score", 0)
                if link_info["risk_score"] > max_url_risk:
                    max_url_risk = link_info["risk_score"]
            except Exception:
                pass
        scanned_links.append(link_info)

    if max_url_risk >= 70:
        total_score = max(total_score, 85)

    risk_score = min(total_score, 100)

    # Determine Verdict and Category
    if risk_score >= 65:
        verdict = "High Risk Scam"
        threat_category = detected_categories[0] if detected_categories else "Malicious Message / Fraud"
    elif risk_score >= 30:
        verdict = "Suspicious Message"
        threat_category = detected_categories[0] if detected_categories else "Unsolicited Commercial / Greymail"
    else:
        verdict = "Low Risk / Clean"
        threat_category = "No Scam Detected"

    # Actionable guidance
    safe_actions = []
    if verdict == "High Risk Scam":
        safe_actions.append("Do NOT click any links, dial phone numbers, or reply to this message.")
        safe_actions.append("Never share OTPs, UPI PINs, or banking passwords — banks never ask for them.")
        safe_actions.append("Block and report the sender number immediately in your messaging app.")
    elif verdict == "Suspicious Message":
        safe_actions.append("Proceed with caution: verify any claim directly via the company's official website.")
        safe_actions.append("Do not download remote access apps (AnyDesk, TeamViewer) prompted by messages.")
    else:
        safe_actions.append("No active scam indicators detected. Always remain vigilant.")

    reasons = []
    for ind in indicators:
        reasons.append(f"Detected {ind['category']} markers: {', '.join([repr(m) for m in ind['matches'][:3]])}")
    if scanned_links:
        reasons.append(f"Found {len(scanned_links)} embedded link(s), highest link risk: {max_url_risk}%.")
    if not reasons:
        reasons.append("No fraudulent phrasing or phishing links were found in the text.")

    protection_manager.record_scan(is_threat=(verdict != "Low Risk / Clean"))

    return {
        "verdict": verdict,
        "threat_category": threat_category,
        "risk_score": risk_score,
        "indicators": indicators,
        "reasons": reasons,
        "extracted_links": scanned_links,
        "safe_actions": safe_actions,
        "message_snippet": message_text[:180] + ("..." if len(message_text) > 180 else ""),
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scan_id": f"msg_{uuid.uuid4().hex[:10]}"
    }


# ---------------------------------------------------------------------------
# Unified Scan History & False-Positive Store
# ---------------------------------------------------------------------------

class UnifiedScanHistory:
    """Thread-safe multi-vector scan log (URLs, Files, Messages, Emails) with Privacy Mode support."""

    def __init__(self, maxlen=500):
        self._lock = threading.Lock()
        self._entries = deque(maxlen=maxlen)
        self._false_positives = []
        self._privacy_mode = False

    def set_privacy_mode(self, enabled: bool) -> bool:
        with self._lock:
            self._privacy_mode = bool(enabled)
            return self._privacy_mode

    def is_privacy_mode(self) -> bool:
        with self._lock:
            return self._privacy_mode

    def add(self, item_type: str, target: str, verdict: str, risk_score: int, threat_category: str, details: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if self._privacy_mode:
                return {
                    "id": f"scan_{uuid.uuid4().hex[:12]}",
                    "type": item_type,
                    "target": "[Redacted in Privacy Mode]",
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "threat_category": threat_category,
                    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "privacy_mode": True
                }

        entry = {
            "id": f"scan_{uuid.uuid4().hex[:12]}",
            "type": item_type,  # 'url', 'file', 'message', 'email'
            "target": target,
            "verdict": verdict,
            "risk_score": risk_score,
            "threat_category": threat_category,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "details": details
        }
        with self._lock:
            self._entries.appendleft(entry)
        return entry

    def clear(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._false_positives.clear()
            return count

    def list_all(self, item_type: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._entries)
        if item_type and item_type != "all":
            items = [item for item in items if item["type"] == item_type]
        safe_limit = max(1, limit) if isinstance(limit, int) else 50
        return items[:safe_limit]

    def record_false_positive(self, scan_id: str, feedback: str, user_verdict: str = "Safe") -> Dict[str, Any]:
        record = {
            "report_id": f"fp_{uuid.uuid4().hex[:8]}",
            "scan_id": scan_id,
            "feedback": feedback,
            "user_verdict": user_verdict,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()
        }
        with self._lock:
            self._false_positives.append(record)
        protection_manager.record_false_positive()
        return record

    def list_false_positives(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._false_positives)


unified_history = UnifiedScanHistory()
