"""
PhishGuard AI — Email & Gmail Threat Scanner Engine
---------------------------------------------------
Detects misleading activities, phishing attacks, credential harvesting,
brand impersonation, spoofed headers, and malicious embedded links.
"""

from __future__ import annotations

import re
import email
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
import datetime as dt

# High-profile brands frequently targeted by impersonators
PROTECTED_BRANDS = {
    "google": ["google.com", "googlemail.com", "gmail.com", "google-workspace.com"],
    "gmail": ["gmail.com", "google.com"],
    "paypal": ["paypal.com", "paypal-communication.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wells fargo": ["wellsfargo.com"],
    "facebook": ["facebook.com", "meta.com", "facebookmail.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
    "instagram": ["instagram.com", "mail.instagram.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "irs": ["irs.gov"],
}

# Free webmail services often abused for corporate impersonation
FREE_MAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "protonmail.com"
]

# Executive / Corporate roles frequently targeted in BEC fraud
EXECUTIVE_ROLES = ["ceo", "cfo", "coo", "chief executive", "president", "director", "founder", "payroll", "hr", "it support", "admin"]

# Deceptive keyword sets categorized by attack intent
SCAM_INDICATORS = {
    "urgency_fear": {
        "label": "Urgency & Coercion",
        "weight": 25,
        "patterns": [
            r"\b(immediate(?:ly)? action (?:is )?required)\b",
            r"\b(account (?:has been |will be )?(?:suspended|locked|terminated|restricted))\b",
            r"\b(within (?:24|48|12) hours)\b",
            r"\b(unauthorized (?:activity|access|login|sign-in))\b",
            r"\b(security (?:alert|breach|incident))\b",
            r"\b(final notice|urgent notice)\b",
            r"\b(fail(?:ure)? to (?:respond|verify|update))\b",
            r"\b(legal action|law enforcement|arrest warrant)\b",
            r"\b(cannot take calls|in an urgent (?:meeting|conference))\b",
            r"\b(treat this with (?:utmost )?priority)\b"
        ]
    },
    "credential_harvesting": {
        "label": "Credential Harvesting",
        "weight": 35,
        "patterns": [
            r"\b(verify your (?:account|identity|password|credentials|identity))\b",
            r"\b(click (?:here|the link below) to (?:log in|verify|restore|sign in))\b",
            r"\b(reset (?:your )?(?:password|pin|security questions))\b",
            r"\b(update (?:your )?(?:billing|payment|credit card|banking) (?:information|details))\b",
            r"\b(confirm your (?:access|email address|phone number))\b",
            r"\b(enter your (?:passcode|2fa|otp|ssn|social security))\b",
            r"\b(validate your credentials)\b"
        ]
    },
    "financial_lure": {
        "label": "Financial Fraud & Deception",
        "weight": 35,
        "patterns": [
            r"\b(wire transfer|western union|moneygram)\b",
            r"\b(process (?:an? )?(?:immediate|confidential)? ?transfer)\b",
            r"\b(cryptocurrency|bitcoin|ethereum|airdrop|crypto reward)\b",
            r"\b(lottery (?:winner|jackpot|prize)|congratulations you won)\b",
            r"\b(inheritance|beneficiary|unclaimed funds)\b",
            r"\b(gift card|apple gift card|steam card|google play card)\b",
            r"\b(invoice #?\d+ (?:is due|payment due|overdue))\b",
            r"\b(geek squad|norton 360|mcafee (?:subscription|renewed|charged))\b",
            r"\b(refund of \$\d+|\$\d+ has been deducted|\$\d+,\d+)\b"
        ]
    },
    "generic_scam": {
        "label": "Generic Scam Phrasing",
        "weight": 15,
        "patterns": [
            r"\b(dear (?:beloved|customer|user|friend|sir/madam))\b",
            r"\b(confidential proposal|urgent business proposition|confidential:)\b",
            r"\b(kindly (?:reply|send|provide|click|contact|process))\b",
            r"\b(100% guaranteed|risk-free profit)\b"
        ]
    }
}

URL_REGEX = re.compile(
    r'(https?://[^\s<>"\',;]+|www\.[^\s<>"\',;]+)',
    re.IGNORECASE
)
HREF_REGEX = re.compile(
    r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)


def extract_domain(email_or_url: str) -> str:
    """Extract clean lowercase domain from email or URL."""
    val = email_or_url.strip().lower()
    if "@" in val:
        parts = val.split("@")
        return parts[-1].strip(" >")
    if not val.startswith(("http://", "https://")):
        val = "http://" + val
    try:
        parsed = urlparse(val)
        domain = parsed.hostname or ""
        return domain.lower()
    except Exception:
        return ""


def parse_email_message(raw_content: str) -> Dict[str, Any]:
    """Parse raw RFC-822 email or plain formatted text."""
    if "From:" in raw_content or "Subject:" in raw_content:
        try:
            msg = Parser(policy=policy.default).parsestr(raw_content)
            subject = str(msg.get("subject", "") or "")
            from_hdr = str(msg.get("from", "") or "")
            to_hdr = str(msg.get("to", "") or "")
            date_hdr = str(msg.get("date", "") or "")
            
            body_parts = []
            html_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype == "text/plain":
                        body_parts.append(part.get_content())
                    elif ctype == "text/html":
                        html_parts.append(part.get_content())
            else:
                ctype = msg.get_content_type()
                if ctype == "text/html":
                    html_parts.append(msg.get_content())
                else:
                    body_parts.append(msg.get_content())
            
            body_text = "\n".join(body_parts) if body_parts else ("\n".join(html_parts))
            raw_html = "\n".join(html_parts)
            
            return {
                "subject": subject,
                "from": from_hdr,
                "to": to_hdr,
                "date": date_hdr,
                "body": body_text,
                "html": raw_html,
                "headers": dict(msg.items())
            }
        except Exception:
            pass

    # Fallback for simple paste format: Subject / From / Body
    lines = raw_content.splitlines()
    subject = ""
    from_hdr = ""
    body_lines = []
    in_body = False
    
    for line in lines:
        if not in_body and line.lower().startswith("subject:"):
            subject = line[8:].strip()
        elif not in_body and line.lower().startswith("from:"):
            from_hdr = line[5:].strip()
        elif not in_body and (line.strip() == "" or line.lower().startswith("body:")):
            in_body = True
        else:
            body_lines.append(line)
            
    return {
        "subject": subject,
        "from": from_hdr,
        "to": "",
        "date": "",
        "body": "\n".join(body_lines).strip() or raw_content,
        "html": "",
        "headers": {}
    }


def analyze_sender_spoofing(from_header: str) -> Dict[str, Any]:
    """Inspects sender for brand impersonation and spoofing tricks."""
    display_name = ""
    address = ""
    
    match = re.search(r'^(.*?)\s*<([^>]+)>$', from_header.strip())
    if match:
        display_name = match.group(1).strip().strip('"\'')
        address = match.group(2).strip()
    elif "@" in from_header:
        address = from_header.strip()
    else:
        display_name = from_header.strip()
        
    sender_domain = extract_domain(address)
    name_lower = display_name.lower()
    
    signals = []
    risk_score = 0
    impersonated_brand = None
    
    # Brand Impersonation check
    for brand, legitimate_domains in PROTECTED_BRANDS.items():
        if brand in name_lower:
            impersonated_brand = brand.capitalize()
            # Check if domain actually matches the brand's authorized domains
            is_authorized = any(sender_domain == d or sender_domain.endswith("." + d) for d in legitimate_domains)
            if not is_authorized:
                risk_score += 45
                signals.append({
                    "severity": "critical",
                    "title": f"High-Confidence Brand Impersonation ({impersonated_brand})",
                    "description": f"The sender claims to be '{display_name}', but the email originates from unverified domain '{sender_domain}'."
                })
                break
                
    # Corporate impersonation using free email accounts
    if impersonated_brand and sender_domain in FREE_MAIL_PROVIDERS:
        risk_score += 35
        signals.append({
            "severity": "high",
            "title": "Corporate Impersonation on Free Webmail",
            "description": f"Sender claims to represent {impersonated_brand} but sends from public webmail service ({sender_domain})."
        })

    # Executive / Role Impersonation on Free Webmail (BEC attack)
    matched_role = next((role for role in EXECUTIVE_ROLES if re.search(r'\b' + role + r'\b', name_lower)), None)
    if matched_role and sender_domain in FREE_MAIL_PROVIDERS:
        risk_score += 55
        signals.append({
            "severity": "critical",
            "title": f"Executive / BEC Impersonation ({matched_role.upper()})",
            "description": f"Sender claims executive role '{display_name}' ({matched_role.upper()}) while originating from free consumer webmail '{sender_domain}', a signature pattern of Business Email Compromise (BEC)."
        })
        
    # Suspicious domain structure
    if sender_domain:
        if any(sender_domain.endswith(tld) for tld in [".xyz", ".top", ".tk", ".ml", ".cf", ".buzz", ".work", ".click"]):
            risk_score += 25
            signals.append({
                "severity": "medium",
                "title": "Suspicious Top-Level Domain (TLD)",
                "description": f"Domain '{sender_domain}' uses a TLD commonly associated with throwaway spam domains."
            })
        if "-" in sender_domain and impersonated_brand:
            risk_score += 20
            signals.append({
                "severity": "high",
                "title": "Typosquatting / Deceptive Domain Slug",
                "description": f"Domain '{sender_domain}' employs hyphenated lookalike patterning."
            })

    return {
        "display_name": display_name,
        "address": address,
        "domain": sender_domain,
        "impersonated_brand": impersonated_brand,
        "risk_score": min(risk_score, 100),
        "signals": signals
    }


def analyze_scam_content(subject: str, body: str) -> Dict[str, Any]:
    """Evaluates text for social engineering, coercive psychological tactics, and fraud lures."""
    full_text = f"{subject}\n{body}".lower()
    
    detected_categories = []
    total_score = 0
    findings = []
    
    for category_key, data in SCAM_INDICATORS.items():
        matched_patterns = []
        for pat in data["patterns"]:
            matches = re.findall(pat, full_text)
            if matches:
                matched_patterns.extend(matches)
                
        if matched_patterns:
            unique_matches = list(set([m if isinstance(m, str) else m[0] for m in matched_patterns]))
            weight = data["weight"]
            total_score += weight * min(len(unique_matches), 3)
            
            detected_categories.append({
                "category": data["label"],
                "matches": unique_matches,
                "count": len(unique_matches)
            })
            
            findings.append({
                "severity": "high" if weight >= 30 else "medium",
                "title": f"Social Engineering: {data['label']}",
                "description": f"Detected manipulative keywords: {', '.join([repr(m) for m in unique_matches[:4]])}"
            })
            
    # Check for generic impersonation greetings
    if re.search(r"dear (customer|user|client|valued member|friend)", full_text):
        total_score += 10
        findings.append({
            "severity": "low",
            "title": "Impersonal / Generic Greeting",
            "description": "Legitimate enterprise communications usually address account holders by name."
        })
        
    return {
        "risk_score": min(total_score, 100),
        "categories": detected_categories,
        "findings": findings
    }


def extract_and_inspect_links(text: str, html: str = "") -> List[Dict[str, Any]]:
    """Extracts all hyperlinks and identifies deceptive anchor text vs target URL."""
    links = []
    seen = set()
    
    # 1. Inspect HTML anchor tags for deceptive mismatch
    if html:
        for match in HREF_REGEX.finditer(html):
            href = match.group(1).strip()
            anchor_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            if href in seen:
                continue
            seen.add(href)
            
            anchor_domain = extract_domain(anchor_text)
            target_domain = extract_domain(href)
            
            is_mismatched = False
            deception_warning = None
            if anchor_domain and target_domain and anchor_domain != target_domain:
                if any(brand in anchor_domain for brand in PROTECTED_BRANDS):
                    is_mismatched = True
                    deception_warning = f"Anchor text displays '{anchor_text}' ({anchor_domain}), but link actually routes to deceptive target '{target_domain}'."
            
            links.append({
                "url": href,
                "anchor_text": anchor_text or href,
                "target_domain": target_domain,
                "anchor_domain": anchor_domain,
                "is_mismatched": is_mismatched,
                "deception_warning": deception_warning
            })
            
    # 2. Inspect plain text URLs
    for match in URL_REGEX.finditer(text):
        url = match.group(1).strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if url in seen:
            continue
        seen.add(url)
        target_domain = extract_domain(url)
        links.append({
            "url": url,
            "anchor_text": url,
            "target_domain": target_domain,
            "anchor_domain": target_domain,
            "is_mismatched": False,
            "deception_warning": None
        })
        
    return links


def evaluate_email_threat(
    raw_content: str = "",
    subject: str = "",
    sender: str = "",
    body: str = "",
    predict_fn = None
) -> Dict[str, Any]:
    """
    Main evaluation pipeline.
    Combines Sender Verification + Content Social Engineering + ML URL Scanner.
    """
    if raw_content and (not subject and not body):
        parsed = parse_email_message(raw_content)
        subject = parsed.get("subject", "")
        sender = parsed.get("from", "")
        body = parsed.get("body", "")
        html = parsed.get("html", "")
    else:
        html = ""
        
    sender_analysis = analyze_sender_spoofing(sender)
    content_analysis = analyze_scam_content(subject, body)
    extracted_links = extract_and_inspect_links(body, html)
    
    # Run ML Model over extracted URLs
    url_results = []
    max_url_phishing_prob = 0.0
    malicious_link_count = 0
    
    for link_item in extracted_links[:10]: # inspect up to 10 URLs
        url = link_item["url"]
        url_threat_info = {
            "url": url,
            "target_domain": link_item["target_domain"],
            "anchor_text": link_item["anchor_text"],
            "is_mismatched": link_item["is_mismatched"],
            "deception_warning": link_item["deception_warning"],
            "prediction": "Unknown",
            "phishing_probability": 0.0,
            "risk_score": 0
        }
        
        if predict_fn:
            try:
                res = predict_fn(url)
                prob = res.get("phishing_probability", 0.0)
                url_threat_info["phishing_probability"] = round(prob, 4)
                url_threat_info["prediction"] = res.get("prediction", "Unknown")
                url_threat_info["risk_score"] = res.get("risk_score", int(prob * 100))
                
                if prob > max_url_phishing_prob:
                    max_url_phishing_prob = prob
                if prob >= 0.5 or link_item["is_mismatched"]:
                    malicious_link_count += 1
            except Exception as e:
                url_threat_info["error"] = str(e)
                
        url_results.append(url_threat_info)
        
    # Aggregate Composite Risk Score (0-100)
    # Weights: Sender (35%), Content (30%), URLs (35%)
    sender_score = sender_analysis["risk_score"]
    content_score = content_analysis["risk_score"]
    url_score = int(max_url_phishing_prob * 100)
    if any(l["is_mismatched"] for l in extracted_links):
        url_score = max(url_score, 85)
        
    if not extracted_links:
        composite_score = int((sender_score * 0.50) + (content_score * 0.50))
    else:
        composite_score = int(
            (sender_score * 0.35) +
            (content_score * 0.30) +
            (url_score * 0.35)
        )
        
    # Force high risk if critical brand impersonation or malicious URL detected
    if any(s["severity"] == "critical" for s in sender_analysis["signals"]):
        composite_score = max(composite_score, 82)
    if malicious_link_count > 0:
        composite_score = max(composite_score, 80)
        
    # Assign Verdict
    if composite_score >= 70:
        verdict = "Phishing / Scam"
        threat_level = "High Risk"
        theme = "danger"
    elif composite_score >= 35:
        verdict = "Suspicious Activity"
        threat_level = "Medium Risk"
        theme = "warning"
    else:
        verdict = "Legitimate"
        threat_level = "Low Risk"
        theme = "safe"
        
    # Compile All Evidence Flags
    evidence = []
    for sig in sender_analysis["signals"]:
        evidence.append({
            "source": "Sender & Headers",
            "severity": sig["severity"],
            "title": sig["title"],
            "description": sig["description"]
        })
    for finding in content_analysis["findings"]:
        evidence.append({
            "source": "Message Content",
            "severity": finding["severity"],
            "title": finding["title"],
            "description": finding["description"]
        })
    for link in url_results:
        if link.get("is_mismatched"):
            evidence.append({
                "source": "Embedded Hyperlinks",
                "severity": "critical",
                "title": "Anchor Text URL Mismatch Detected",
                "description": link["deception_warning"]
            })
        elif link.get("phishing_probability", 0) >= 0.7:
            evidence.append({
                "source": "Embedded Hyperlinks",
                "severity": "high",
                "title": "High-Confidence Phishing Link Detected",
                "description": f"URL '{link['url']}' identified as malicious by Random Forest model ({int(link['phishing_probability']*100)}% risk)."
            })

    # Recommended Actions
    recommendations = []
    if verdict == "Phishing / Scam":
        recommendations.append("Do NOT click any links, open attachments, or reply to this sender.")
        recommendations.append("Report this message as Phishing / Fraud in your mail provider.")
        recommendations.append("If you entered login credentials on any linked site, immediately reset your password.")
    elif verdict == "Suspicious Activity":
        recommendations.append("Exercise extreme caution: Verify the sender through a known, trusted official phone number or website.")
        recommendations.append("Do not click direct links. Navigate manually to the service's official homepage.")
    else:
        recommendations.append("No active misleading patterns detected. Always remain vigilant.")

    return {
        "scan_id": f"mail_{dt.datetime.now().strftime('%Y%m%d%H%M%S')}_{abs(hash(subject)) % 10000}",
        "scan_time": dt.datetime.now(dt.timezone.utc).isoformat(),
        "subject": subject,
        "sender": sender,
        "verdict": verdict,
        "threat_level": threat_level,
        "risk_score": composite_score,
        "theme": theme,
        "sender_score": sender_score,
        "content_score": content_score,
        "url_score": url_score,
        "sender_analysis": sender_analysis,
        "content_analysis": content_analysis,
        "links": url_results,
        "evidence": evidence,
        "recommendations": recommendations,
        "analyzed_locally": True
    }


# Realistic Preset Email Samples for Hackathon & Demo Scenarios
PRESET_EMAILS = [
    {
        "id": "netflix-scam",
        "title": "Netflix Billing Suspension Scam",
        "category": "Phishing Impersonation",
        "sender": '"Netflix Support" <billing-alert@netflix-billing-resolve39.com>',
        "subject": "Urgent: Your Netflix membership is temporarily on hold",
        "body": """Dear Customer,

We were unable to process your monthly payment for your Netflix subscription.

Immediate action is required within 24 hours. Your account has been temporarily restricted, and will be permanently suspended if billing details are not validated.

Please update your billing and payment information immediately:
https://netflix-account-restore-portal.com/login

Thank you for choosing Netflix,
The Netflix Customer Security Team"""
    },
    {
        "id": "chase-kyc",
        "title": "Chase Bank Security & KYC Alert",
        "category": "Financial Credential Harvesting",
        "sender": '"Chase Security Alerts" <no-reply@chase-support-notice.info>',
        "subject": "Security Alert: Unauthorized login attempt from new device",
        "body": """Chase Online Banking Notice

We detected an unauthorized sign-in attempt to your checking account from an unrecognized IP address.

For your protection, your access has been locked. Click the link below to verify your account credentials, confirm your 2FA security PIN, and restore access:

https://chase-security-verify-398.biz/secure/auth

Failure to verify within 12 hours will result in legal compliance account hold.

JPMorgan Chase & Co. Security Division"""
    },
    {
        "id": "ceo-wire",
        "title": "Executive / CEO Wire Fraud",
        "category": "Business Email Compromise (BEC)",
        "sender": '"David Henderson (CEO)" <d.henderson.corp@gmail.com>',
        "subject": "Confidential: Urgent Wire Transfer Request",
        "body": """Hi,

I am currently in an urgent offsite board meeting and cannot take calls.

Kindly process an immediate confidential wire transfer of $48,500 to our acquisition vendor before 3 PM today.

Send me the transaction confirmation slip as soon as completed. Treat this with utmost priority.

Regards,
David Henderson
Chief Executive Officer"""
    },
    {
        "id": "crypto-airdrop",
        "title": "Binance 500 USDT Airdrop Lure",
        "category": "Crypto Phishing & Giveaway Scam",
        "sender": '"Binance Rewards" <rewards@binance-airdrop-claim.xyz>',
        "subject": "Congratulations: You have 500 USDT waiting to be claimed!",
        "body": """Congratulations!

You have been selected in the Binance VIP Anniversary Giveaway. You won an airdrop reward of 500 USDT!

Claim your cryptocurrency prize now by connecting your wallet:
https://binance-claim-airdrop-2026.xyz/connect-wallet

This offer expires in 12 hours. 100% guaranteed reward.

Binance Global Community Team"""
    },
    {
        "id": "safe-receipt",
        "title": "Legitimate Amazon Order Confirmation",
        "category": "Safe / Legitimate",
        "sender": '"Amazon.com" <auto-confirm@amazon.com>',
        "subject": "Your Amazon.com order of 'Anker USB-C Cable' has shipped",
        "body": """Hello Alex,

Thank you for shopping with us. Your item has shipped and is on the way!

Order Details:
Order #112-9842103-4920192
Item: Anker Powerline USB-C Cable (6ft)
Estimated Delivery: Friday, Oct 10

Track your package directly at Amazon:
https://www.amazon.com/your-orders

We hope to see you again soon!
Amazon.com"""
    }
]


def fetch_gmail_via_imap(user_email: str, app_password: str, max_emails: int = 8, predict_fn = None) -> List[Dict[str, Any]]:
    """
    Connects to Gmail via IMAP SSL and fetches real messages for scanning.
    Requires a Google App Password (generated at myaccount.google.com/apppasswords).
    """
    import imaplib
    import socket
    clean_pwd = app_password.replace(" ", "").strip()
    clean_email = user_email.strip()
    
    try:
        # Set a 15-second timeout so the UI doesn't freeze when port 993 is
        # blocked by a firewall or corporate network.
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=15)
        mail.login(clean_email, clean_pwd)
    except imaplib.IMAP4.error as e:
        err_str = str(e)
        if "AUTHENTICATIONFAILED" in err_str.upper() or "Invalid credentials" in err_str:
            raise ValueError(
                "Gmail login failed — invalid credentials. "
                "Make sure you are using a 16-character Google App Password, "
                "NOT your regular Gmail password. "
                "Generate one at: https://myaccount.google.com/apppasswords  "
                "(2-Step Verification must be turned ON first)."
            )
        raise ValueError(
            f"Gmail authentication error: {e}. "
            "Please verify your email address and App Password."
        )
    except (socket.timeout, TimeoutError, OSError) as e:
        raise ValueError(
            "Could not reach Gmail's IMAP server (connection timed out). "
            "This usually means your network or firewall is blocking outbound "
            "connections on port 993. Try switching to a different WiFi/hotspot, "
            "or check that your antivirus/firewall allows IMAP connections."
        )
    except Exception as e:
        raise ValueError(f"Could not connect to Gmail: {e}")
        
    try:
        mail.select("INBOX", readonly=True)
        status, msg_nums = mail.search(None, "ALL")
        if status != "OK" or not msg_nums or not msg_nums[0]:
            mail.logout()
            return []
            
        ids = msg_nums[0].split()
        latest_ids = ids[-max_emails:]
        latest_ids.reverse() # Newest first
        
        results = []
        for msg_id in latest_ids:
            try:
                status, data = mail.fetch(msg_id, "(RFC822)")
                if status != "OK" or not data:
                    continue
                raw_email = None
                for part in data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw_email = part[1]
                        break
                if not raw_email:
                    continue
                    
                if isinstance(raw_email, bytes):
                    raw_str = raw_email.decode("utf-8", errors="ignore")
                else:
                    raw_str = str(raw_email)
                report = evaluate_email_threat(raw_content=raw_str, predict_fn=predict_fn)
                report["imap_id"] = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
                results.append(report)
            except Exception:
                continue
                
        mail.logout()
        return results
    except Exception as e:
        try:
            mail.logout()
        except Exception:
            pass
        raise e

