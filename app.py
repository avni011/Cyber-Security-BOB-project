"""
ThreatLens - SMS Phishing & URL Threat Scanner
A beginner-friendly cybersecurity dashboard built with Streamlit.
No APIs, no databases, no machine learning — just smart rule-based detection.
"""

import streamlit as st
import re
from datetime import datetime

# ─────────────────────────────────────────────
# PAGE CONFIGURATION
# Must be the very first Streamlit call in the file.
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
# CUSTOM CSS  — deep-navy cybersecurity theme
# ─────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0a0f1e;
    color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, sans-serif;
}
[data-testid="stHeader"] { background-color: #0a0f1e; }
[data-testid="stSidebar"] { background-color: #0d1427; }

/* ── Hero heading ── */
.hero-title {
    font-size: 3rem;
    font-weight: 800;
    background: linear-gradient(90deg, #00d4ff, #0080ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0;
    line-height: 1.1;
}
.hero-tagline {
    font-size: 1.15rem;
    color: #94a3b8;
    margin-top: 0.25rem;
    margin-bottom: 1.5rem;
}

/* ── Metric cards ── */
.metric-card {
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    text-align: center;
}
.metric-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: #00d4ff;
    line-height: 1;
}
.metric-label {
    font-size: 0.8rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.35rem;
}

/* ── Result cards ── */
.result-card {
    background: #111827;
    border-radius: 14px;
    padding: 1.5rem 1.75rem;
    margin-top: 1rem;
    border-left: 5px solid #00d4ff;
}
.result-card.high   { border-left-color: #ef4444; }
.result-card.medium { border-left-color: #f59e0b; }
.result-card.low    { border-left-color: #22c55e; }

.risk-badge {
    display: inline-block;
    padding: 0.3rem 0.9rem;
    border-radius: 999px;
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.04em;
}
.badge-high   { background: #450a0a; color: #fca5a5; border: 1px solid #ef4444; }
.badge-medium { background: #451a03; color: #fcd34d; border: 1px solid #f59e0b; }
.badge-low    { background: #052e16; color: #86efac; border: 1px solid #22c55e; }

/* ── Section header ── */
.section-title {
    font-size: 1.05rem;
    font-weight: 600;
    color: #00d4ff;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.4rem;
    margin-bottom: 0.75rem;
    margin-top: 1.25rem;
}

/* ── Reason bullet ── */
.reason-item {
    background: #1e293b;
    border-radius: 8px;
    padding: 0.5rem 0.85rem;
    margin-bottom: 0.4rem;
    font-size: 0.9rem;
    color: #cbd5e1;
}

/* ── Action bullet ── */
.action-item {
    background: #0f2a1e;
    border-radius: 8px;
    padding: 0.5rem 0.85rem;
    margin-bottom: 0.4rem;
    font-size: 0.9rem;
    color: #86efac;
}

/* ── Streamlit input overrides ── */
textarea, .stTextInput > div > div > input {
    background-color: #111827 !important;
    color: #e2e8f0 !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 10px !important;
}
.stButton > button {
    background: linear-gradient(135deg, #0080ff, #00d4ff);
    color: #0a0f1e;
    font-weight: 700;
    border: none;
    border-radius: 10px;
    padding: 0.6rem 1.8rem;
    font-size: 1rem;
    transition: opacity 0.2s;
}
.stButton > button:hover { opacity: 0.85; }
.stSelectbox > div > div {
    background-color: #111827 !important;
    color: #e2e8f0 !important;
    border: 1px solid #1e3a5f !important;
}

/* ── Divider ── */
hr { border-color: #1e3a5f; }

/* ── Score bar background ── */
.score-bar-bg {
    background: #1e293b;
    border-radius: 999px;
    height: 10px;
    margin: 0.6rem 0 1rem 0;
    overflow: hidden;
}
.score-bar-fill {
    height: 10px;
    border-radius: 999px;
    transition: width 0.4s;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# SESSION STATE  — persists across reruns
# ─────────────────────────────────────────────
def init_state():
    """Initialise counters the first time the app loads."""
    defaults = {
        "total_scans": 0,
        "safe_scans": 0,
        "high_risk_scans": 0,
        "suspicious_scans": 0,
        "last_result": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_state()


# ─────────────────────────────────────────────
# DETECTION ENGINE  — rule-based logic
# ─────────────────────────────────────────────

# Keywords associated with smishing / phishing
URGENCY_KEYWORDS = [
    "urgent", "immediately", "right now", "act now", "limited time",
    "expires today", "last chance", "within 24 hours", "within 48 hours",
    "account suspended", "account locked", "verify immediately",
]

CREDENTIAL_KEYWORDS = [
    "otp", "one-time password", "pin", "password", "username",
    "login credentials", "enter your code", "verification code",
    "confirm your details", "update your details",
]

PAYMENT_KEYWORDS = [
    "payment required", "pay now", "overdue bill", "outstanding balance",
    "click to pay", "avoid penalty", "penalty fee", "processing fee",
    "wire transfer", "gift card", "bitcoin", "crypto payment",
    "send money", "transfer funds",
]

REWARD_KEYWORDS = [
    "you have won", "congratulations", "claim your prize",
    "free gift", "selected winner", "lottery", "reward waiting",
    "special offer", "exclusive deal", "you are chosen",
]

THREAT_KEYWORDS = [
    "your account will be", "your account has been",
    "legal action", "arrested", "police", "suspended",
    "blocked", "deactivated", "report to authorities",
]

# Common URL shorteners used in phishing
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "rebrand.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "bl.ink", "clck.ru",
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site",
    ".info", ".biz", ".tk", ".ml", ".ga", ".cf",
]

# Legitimate brand names commonly spoofed
SPOOFED_BRANDS = [
    "paypal", "amazon", "netflix", "apple", "google",
    "microsoft", "bank of america", "chase", "citibank",
    "irs", "fedex", "ups", "dhl", "whatsapp", "facebook",
]


def extract_urls(text: str) -> list[str]:
    """Pull every URL out of the given text string."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def analyse_url(url: str, seen_brands: set | None = None) -> tuple[list[str], int]:
    """
    Score a single URL and return (reasons, score_contribution).
    Checks for shorteners, suspicious TLDs, and IP addresses.
    seen_brands: set of brand names already flagged by analyse_text so we
                 don't double-count the same brand across text and URL.
    """
    if seen_brands is None:
        seen_brands = set()

    reasons = []
    score = 0

    url_lower = url.lower()

    # Check URL shorteners
    for shortener in SHORTENER_DOMAINS:
        if shortener in url_lower:
            reasons.append(f"Shortened URL detected ({shortener}) — hides the real destination")
            score += 20
            break

    # Check suspicious top-level domains
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or (tld + "/") in url_lower or (tld + "?") in url_lower:
            reasons.append(f"Suspicious domain extension ({tld})")
            score += 15
            break

    # Check if URL uses raw IP address instead of domain name
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url_lower):
        reasons.append("URL uses an IP address instead of a domain name — very suspicious")
        score += 25

    # Unusually long URL (common in obfuscated phishing links)
    if len(url) > 100:
        reasons.append("Unusually long URL — may be obfuscating the real destination")
        score += 10

    # Many subdomains (e.g. secure.paypal.login.evil.com)
    domain_part = re.sub(r'https?://', '', url_lower).split('/')[0]
    subdomain_count = domain_part.count('.')
    if subdomain_count >= 3:
        reasons.append(f"Too many subdomains ({subdomain_count}) — common in spoofed sites")
        score += 15

    # Spoofed brand in URL but not the official domain.
    # Skip if the same brand was already flagged in the message text (avoids double-counting).
    for brand in SPOOFED_BRANDS:
        if brand in url_lower and brand not in seen_brands:
            official = brand.replace(" ", "") + ".com"
            if official not in domain_part:
                reasons.append(f"Brand name '{brand}' appears in URL but domain is not official")
                score += 20
            break

    return reasons, min(score, 50)   # cap URL contribution at 50


def analyse_text(message: str) -> tuple[list[str], int, set]:
    """
    Score the SMS/message text and return (reasons, score_contribution, seen_brands).
    seen_brands is passed to analyse_url to prevent double-counting the same brand.
    """
    reasons = []
    score = 0
    seen_brands: set = set()
    text_lower = message.lower()

    # ── Urgency language ──
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
    if urgency_hits:
        reasons.append(f"Urgency language detected: \"{urgency_hits[0]}\"")
        score += 15

    # ── Credential / OTP requests ──
    cred_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in text_lower]
    if cred_hits:
        reasons.append(f"Requests sensitive information: \"{cred_hits[0]}\"")
        score += 25

    # ── Payment demands ──
    pay_hits = [kw for kw in PAYMENT_KEYWORDS if kw in text_lower]
    if pay_hits:
        reasons.append(f"Payment-related demand detected: \"{pay_hits[0]}\"")
        score += 20

    # ── Reward / prize lure ──
    reward_hits = [kw for kw in REWARD_KEYWORDS if kw in text_lower]
    if reward_hits:
        reasons.append(f"Prize/reward lure detected: \"{reward_hits[0]}\"")
        score += 20

    # ── Threat language ──
    threat_hits = [kw for kw in THREAT_KEYWORDS if kw in text_lower]
    if threat_hits:
        reasons.append(f"Threatening language detected: \"{threat_hits[0]}\"")
        score += 20

    # ── Phone number in message ──
    phone_pattern = r'\b(\+?\d[\d\s\-]{7,}\d)\b'
    if re.search(phone_pattern, message):
        reasons.append("Phone number present — smishing often asks you to call back")
        score += 10

    # ── Spoofed brand names ──
    for brand in SPOOFED_BRANDS:
        if brand in text_lower:
            reasons.append(f"Well-known brand name mentioned: '{brand}' — verify authenticity")
            score += 10
            seen_brands.add(brand)   # remember it so URL check won't count it again
            break

    # ── ALL CAPS words (shouting / urgency) ──
    caps_words = re.findall(r'\b[A-Z]{4,}\b', message)
    if caps_words:
        reasons.append(f"ALL CAPS words used ({', '.join(caps_words[:3])}) — creates false urgency")
        score += 5

    # ── Excessive exclamation marks ──
    if message.count('!') >= 3:
        reasons.append("Multiple exclamation marks — a classic high-pressure tactic")
        score += 5

    return reasons, min(score, 75), seen_brands   # cap text contribution at 75


def get_safety_actions(category: str) -> list[str]:
    """Return recommended safety steps based on the risk level."""
    if category == "High Risk":
        return [
            "🚫  Do NOT click any links in this message.",
            "🚫  Do NOT call back any number in this message.",
            "🚫  Do NOT share OTPs, passwords, or personal information.",
            "🗑️  Delete the message immediately.",
            "📢  Report it to your mobile carrier by forwarding to 7726 (SPAM).",
            "🔒  If you already clicked a link, change your passwords now.",
        ]
    elif category == "Suspicious":
        return [
            "⚠️  Be cautious — do not act on this message impulsively.",
            "🔍  Verify the sender by contacting the company through their official website.",
            "🔗  Do not click shortened or unfamiliar URLs.",
            "📵  Avoid sharing any personal or financial information.",
            "📢  Report it as spam if it feels wrong.",
        ]
    else:
        return [
            "✅  This message appears safe, but always stay vigilant.",
            "🔎  If you are ever unsure, verify with the sender directly.",
            "📖  Learn more about smishing at consumer.ftc.gov.",
        ]


def run_scan(message: str, extra_url: str = "") -> dict:
    """
    Master scan function — combines text and URL analysis,
    returns a result dictionary with all details.
    """
    all_reasons = []
    total_score = 0

    # ── Analyse the message text ──
    # analyse_text now also returns seen_brands to prevent double-counting
    text_reasons, text_score, seen_brands = analyse_text(message)
    all_reasons.extend(text_reasons)
    total_score += text_score

    # ── Analyse URLs embedded in the message ──
    embedded_urls = extract_urls(message)
    for url in embedded_urls:
        url_reasons, url_score = analyse_url(url, seen_brands)
        all_reasons.extend(url_reasons)
        total_score += url_score

    # ── Analyse the optional manually entered URL ──
    if extra_url.strip():
        url_reasons, url_score = analyse_url(extra_url.strip(), seen_brands)
        if url_reasons:
            all_reasons.extend(url_reasons)
            total_score += url_score
        else:
            all_reasons.append("Manually entered URL looks clean — no obvious red flags")

    # ── Cap score at 100 ──
    total_score = min(total_score, 100)

    # ── Classify the risk level ──
    if total_score >= 60:
        category = "High Risk"
        css_class = "high"
        badge_class = "badge-high"
        bar_color = "#ef4444"
    elif total_score >= 25:
        category = "Suspicious"
        css_class = "medium"
        badge_class = "badge-medium"
        bar_color = "#f59e0b"
    else:
        category = "Low Risk"
        css_class = "low"
        badge_class = "badge-low"
        bar_color = "#22c55e"

    return {
        "score": total_score,
        "category": category,
        "css_class": css_class,
        "badge_class": badge_class,
        "bar_color": bar_color,
        "reasons": all_reasons if all_reasons else ["No suspicious patterns detected."],
        "actions": get_safety_actions(category),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }


# ─────────────────────────────────────────────
# HELPER — render a metric card
# ─────────────────────────────────────────────
def metric_card(label: str, value: int):
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# SAMPLE MESSAGES for beginners to test
# ─────────────────────────────────────────────
SAMPLE_MESSAGES = {
    "— Choose a sample —": "",
    "🔴 Phishing (Bank OTP)": (
        "URGENT: Your bank account has been suspended! "
        "Verify your identity immediately by entering your OTP at http://bit.ly/secure-login now "
        "or your account will be permanently closed within 24 hours!!!"
    ),
    "🔴 Phishing (Prize Scam)": (
        "Congratulations! You have won a $1,000 Amazon gift card. "
        "Claim your prize NOW before it expires: https://amaz0n-rewards.xyz/claim "
        "Limited time offer!"
    ),
    "🟡 Suspicious (Payment Demand)": (
        "Your FedEx package could not be delivered. An outstanding balance of $3.20 is due. "
        "Click here to pay: https://fedex-delivery.top/pay"
    ),
    "🟢 Safe (Normal Bank Alert)": (
        "Chase Bank: A payment of $54.00 was made to Netflix on 12/01. "
        "If you did not authorise this, call 1-800-935-9935. Do not reply to this message."
    ),
    "🟢 Safe (Appointment Reminder)": (
        "Hi! This is a reminder from Dr. Smith's office that you have an appointment "
        "tomorrow at 10:00 AM. Reply CONFIRM or call us at 555-123-4567."
    ),
}


# ─────────────────────────────────────────────
# MAIN UI
# ─────────────────────────────────────────────

# ── Hero Header ──
st.markdown("""
<div style="padding: 1.5rem 0 0.5rem 0;">
    <div class="hero-title">🛡️ ThreatLens</div>
    <div class="hero-tagline">See the Threat Before It Strikes.</div>
</div>
""", unsafe_allow_html=True)

st.markdown("<hr/>", unsafe_allow_html=True)

# ── Dashboard Metric Cards ──
st.markdown('<div class="section-title">📊 Dashboard</div>', unsafe_allow_html=True)
col1, col2, col3, col4 = st.columns(4)
with col1:
    metric_card("Total Scans", st.session_state.total_scans)
with col2:
    metric_card("Safe Scans", st.session_state.safe_scans)
with col3:
    metric_card("High-Risk Detections", st.session_state.high_risk_scans)
with col4:
    metric_card("Suspicious Activities", st.session_state.suspicious_scans)

st.markdown("<hr/>", unsafe_allow_html=True)

# ── Scanner Section ──
st.markdown('<div class="section-title">🔍 SMS & URL Scanner</div>', unsafe_allow_html=True)

# Sample message selector
selected_sample = st.selectbox(
    "Load a sample message to test:",
    options=list(SAMPLE_MESSAGES.keys()),
    key="sample_selector",
)

# Auto-fill the text area when a sample is selected
prefill = SAMPLE_MESSAGES.get(selected_sample, "")

# Message text area
message_input = st.text_area(
    "Paste your suspicious SMS or message here:",
    value=prefill,
    height=150,
    placeholder="e.g. 'URGENT: Your account has been suspended. Click here to verify...'",
    key="message_input",
)

# Optional URL input
url_input = st.text_input(
    "Optional: Paste a suspicious URL to scan separately",
    placeholder="https://example.com/suspicious-link",
    key="url_input",
)

# Buttons row
btn_col1, btn_col2, _ = st.columns([1, 1, 4])
with btn_col1:
    scan_clicked = st.button("🔍 Scan for Threats", use_container_width=True)
with btn_col2:
    clear_clicked = st.button("🗑️ Clear", use_container_width=True)

# Handle Clear — resets inputs by rerunning with cleared state
if clear_clicked:
    st.session_state.message_input = ""
    st.session_state.url_input = ""
    st.session_state.sample_selector = "— Choose a sample —"
    st.session_state.last_result = None
    st.rerun()

# Handle Scan
if scan_clicked:
    if not message_input.strip() and not url_input.strip():
        st.warning("⚠️ Please paste a message or a URL before scanning.")
    else:
        # If only a URL was entered (no message text), use a placeholder
        text_to_scan = message_input.strip() if message_input.strip() else "(No message text — URL only)"

        # Run the detection engine
        result = run_scan(text_to_scan, url_input)
        st.session_state.last_result = result

        # Update session counters
        st.session_state.total_scans += 1
        if result["category"] == "Low Risk":
            st.session_state.safe_scans += 1
        elif result["category"] == "High Risk":
            st.session_state.high_risk_scans += 1
        else:
            st.session_state.suspicious_scans += 1

        st.rerun()   # Refresh so the updated dashboard cards show immediately

# ─────────────────────────────────────────────
# RESULTS PANEL
# ─────────────────────────────────────────────
if st.session_state.last_result:
    r = st.session_state.last_result

    st.markdown("<hr/>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">📋 Scan Result</div>', unsafe_allow_html=True)

    # Open result card
    st.markdown(f'<div class="result-card {r["css_class"]}">', unsafe_allow_html=True)

    # Score row
    res_col1, res_col2 = st.columns([1, 2])
    with res_col1:
        st.markdown(f"""
        <div style="font-size:0.8rem; color:#64748b; text-transform:uppercase; letter-spacing:0.05em;">Risk Score</div>
        <div style="font-size:3rem; font-weight:800; color:{r['bar_color']}; line-height:1.1;">{r['score']}<span style="font-size:1.2rem; color:#64748b;">/100</span></div>
        <div class="score-bar-bg">
            <div class="score-bar-fill" style="width:{r['score']}%; background:{r['bar_color']};"></div>
        </div>
        <span class="risk-badge {r['badge_class']}">{r['category']}</span>
        """, unsafe_allow_html=True)

    with res_col2:
        # Reasons detected
        st.markdown('<div style="font-size:0.8rem; color:#64748b; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.5rem;">Why this score?</div>', unsafe_allow_html=True)
        for reason in r["reasons"]:
            st.markdown(f'<div class="reason-item">⚡ {reason}</div>', unsafe_allow_html=True)

    # Safety recommendations
    st.markdown('<div style="margin-top:1rem; font-size:0.8rem; color:#64748b; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.5rem;">Recommended Actions</div>', unsafe_allow_html=True)
    for action in r["actions"]:
        st.markdown(f'<div class="action-item">{action}</div>', unsafe_allow_html=True)

    # Timestamp
    st.markdown(f'<div style="margin-top:0.75rem; font-size:0.75rem; color:#475569;">Scanned at {r["timestamp"]}</div>', unsafe_allow_html=True)

    # Close result card
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.markdown("<hr/>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align:center; color:#334155; font-size:0.78rem; padding: 0.5rem 0 1rem 0;">
    🛡️ <strong style="color:#0080ff;">ThreatLens</strong> &nbsp;·&nbsp;
    Built for education only &nbsp;·&nbsp;
    No messages are stored or transmitted &nbsp;·&nbsp;
    Stay safe online
</div>
""", unsafe_allow_html=True)
