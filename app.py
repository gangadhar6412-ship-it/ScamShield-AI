
import csv
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import streamlit as st


# ============================================================
# SCAMSHIELD AI — CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="ScamShield AI | Digital Safety",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_NAME = "ScamShield AI"

# Gemini is optional. Set GEMINI_API_KEY in Streamlit Secrets
# or as an environment variable to enable AI explanations.
try:
    GEMINI_API_KEY = st.secrets.get(
        "GEMINI_API_KEY", os.getenv("GEMINI_API_KEY", "")
    )
except Exception:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


# ============================================================
# DESIGN
# ============================================================

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    .stApp {
        background: #0a1020;
        color: #eef3ff;
        font-family: 'DM Sans', sans-serif;
    }

    [data-testid="stSidebar"] {
        background: #10192b;
        border-right: 1px solid #25314a;
    }

    h1, h2, h3 {
        font-family: 'Space Grotesk', sans-serif !important;
        letter-spacing: -0.5px;
    }

    .hero {
        background: linear-gradient(125deg, #172a4c, #142039 60%, #102c34);
        border: 1px solid #2c4566;
        padding: 30px;
        border-radius: 22px;
        margin-bottom: 20px;
    }

    .hero-title {
        font-family: 'Space Grotesk', sans-serif;
        font-size: clamp(28px, 4vw, 43px);
        font-weight: 700;
        line-height: 1.12;
        color: #ffffff;
        margin-bottom: 12px;
    }

    .hero-subtitle {
        color: #b9c9e5;
        font-size: 16px;
        line-height: 1.65;
        max-width: 760px;
    }

    .eyebrow {
        color: #6ee7c5;
        text-transform: uppercase;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 2px;
        margin-bottom: 12px;
    }

    .metric-card {
        background: #111c30;
        border: 1px solid #283851;
        padding: 19px;
        border-radius: 16px;
        min-height: 112px;
    }

    .metric-label {
        color: #9cacc7;
        font-size: 13px;
        margin-bottom: 8px;
    }

    .metric-value {
        color: #ffffff;
        font-size: 25px;
        font-weight: 700;
        font-family: 'Space Grotesk', sans-serif;
    }

    .panel {
        background: #111c30;
        border: 1px solid #283851;
        border-radius: 17px;
        padding: 20px;
        margin: 10px 0;
    }

    .muted {
        color: #a7b6d0;
        font-size: 14px;
        line-height: 1.65;
    }

    .pill {
        display: inline-block;
        background: #1b3049;
        color: #a9f4df;
        border: 1px solid #31516a;
        padding: 5px 10px;
        border-radius: 30px;
        font-size: 12px;
        margin: 3px 5px 3px 0;
    }

    div.stButton > button {
        border-radius: 11px;
        min-height: 43px;
        font-weight: 600;
    }

    div[data-testid="stMetric"] {
        background: #111c30;
        border: 1px solid #283851;
        padding: 15px;
        border-radius: 14px;
    }

    [data-testid="stProgressBar"] > div > div {
        background-color: #52e0b6;
    }

    footer {visibility: hidden;}
    </style>
    
/* ScamShield AI — readable light theme */
.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stMain"] {
    background: #F4F7FC !important;
    color: #172033 !important;
}

[data-testid="stHeader"] {
    background: #F4F7FC !important;
}

[data-testid="stMarkdownContainer"],
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
[data-testid="stMarkdownContainer"] span,
[data-testid="stMarkdownContainer"] label,
.stApp h1,
.stApp h2,
.stApp h3,
.stApp h4,
.stApp label,
.stApp .stCaption {
    color: #172033 !important;
}

[data-testid="stVerticalBlockBorderWrapper"],
[data-testid="stForm"],
[data-testid="stExpander"] {
    background-color: #FFFFFF !important;
    border-color: #DCE4EF !important;
}

.stTextInput input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"],
.stNumberInput input {
    background-color: #FFFFFF !important;
    color: #172033 !important;
    border-color: #CBD5E1 !important;
}

.stTextInput input::placeholder,
.stTextArea textarea::placeholder {
    color: #64748B !important;
    opacity: 1 !important;
}

.stButton button,
.stDownloadButton button {
    background-color: #126E82 !important;
    color: #FFFFFF !important;
    border: 1px solid #126E82 !important;
    border-radius: 10px !important;
}

.stButton button:hover,
.stDownloadButton button:hover {
    background-color: #0D5667 !important;
    color: #FFFFFF !important;
}

[data-testid="stSidebar"] {
    background-color: #FFFFFF !important;
}

[data-testid="stSidebar"] * {
    color: #172033;
}

[data-testid="stAlert"] {
    color: #172033 !important;
}

[data-testid="stCode"] {
    background-color: #F1F5F9 !important;
    color: #172033 !important;
}

    """,
    unsafe_allow_html=True,
)


# ============================================================
# DETECTION RULES
# These are heuristic signals, not a certified security engine.
# ============================================================

PATTERNS = [
    (
        "Urgency or pressure",
        r"\b(urgent|immediately|act now|within \d+ minutes|expires today|last chance|right now)\b",
        14,
        "The message pressures the recipient to act quickly.",
    ),
    (
        "Credential request",
        r"\b(password|passcode|otp|one.time password|pin number|login credentials)\b",
        24,
        "The message refers to sensitive authentication information.",
    ),
    (
        "Account threat",
        r"\b(account (will be|has been|is) (blocked|suspended|locked|closed)|suspend your account|account verification required)\b",
        20,
        "The message threatens an account restriction or requests verification.",
    ),
    (
        "Prize or unexpected reward",
        r"\b(you have won|winner selected|claim your prize|free gift|congratulations.*won|lottery winner)\b",
        16,
        "The message promises an unexpected reward or prize.",
    ),
    (
        "Payment pressure",
        r"\b(pay immediately|transfer money|send money now|processing fee|advance fee|pay to release|refund fee)\b",
        19,
        "The message requests money or creates payment pressure.",
    ),
    (
        "Impersonation language",
        r"\b(bank officer|government officer|police officer|customs department|official support team)\b",
        8,
        "The sender may be invoking an authority or trusted organisation.",
    ),
    (
        "Remote access request",
        r"\b(install anydesk|install teamviewer|remote access|screen sharing app|share your screen)\b",
        24,
        "The message suggests remote access or screen sharing.",
    ),
    (
        "Suspicious contact",
        r"\b(whatsapp me|contact me on telegram|message me privately|move this conversation)\b",
        7,
        "The message encourages moving the conversation to another channel.",
    ),
    (
        "Sensitive identity request",
        r"\b(aadhaar|social security number|card cvv|cvv number|full card details)\b",
        20,
        "The message refers to sensitive identity or payment information.",
    ),
    (
        "Suspicious payment method",
        r"\b(gift card|crypto wallet|cryptocurrency transfer|bitcoin payment|upi collect request)\b",
        16,
        "The message refers to a payment method that can be difficult to reverse.",
    ),
]

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".click", ".top", ".work", ".country", ".gq", ".tk"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "rb.gy", "rebrand.ly"
}


def normalize_url(raw_url):
    """Return a parseable URL without visiting it."""
    raw_url = raw_url.strip().strip("<>()[]{}\"'.,;")
    if not raw_url:
        return None

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "https://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
        if not parsed.hostname:
            return None
        return parsed
    except ValueError:
        return None


def inspect_url(raw_url):
    """Inspect URL structure only. This function does not open the URL."""
    parsed = normalize_url(raw_url)

    if not parsed:
        return {
            "score": 0,
            "signals": [],
            "host": "Could not parse URL",
            "valid": False,
        }

    host = (parsed.hostname or "").lower().rstrip(".")
    signals = []
    score = 0

    if parsed.scheme.lower() != "https":
        score += 12
        signals.append(
            "The URL does not use HTTPS. This alone does not prove it is malicious."
        )

    if "@" in parsed.netloc:
        score += 25
        signals.append("The URL contains an @ symbol in its network location.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 18
        signals.append("The hostname contains an internationalised domain label.")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 20
        signals.append("The URL uses an IP address instead of a regular domain name.")

    if len(host) > 35:
        score += 8
        signals.append("The hostname is unusually long.")

    if host.count("-") >= 3:
        score += 8
        signals.append("The hostname contains several hyphens.")

    if any(host == shortener or host.endswith("." + shortener)
           for shortener in URL_SHORTENERS):
        score += 12
        signals.append("The domain is a URL-shortening service, hiding the final destination.")

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 10
        signals.append("The domain uses a top-level domain that deserves additional scrutiny.")

    if re.search(r"(login|verify|secure|account|wallet|update|claim)", host):
        score += 8
        signals.append("The hostname includes words commonly used in account-related lures.")

    if len(parsed.path) > 70:
        score += 5
        signals.append("The URL path is unusually long.")

    if re.search(r"(login|verify|password|otp|payment|banking)", parsed.path, re.I):
        score += 8
        signals.append("The URL path contains account or payment-related keywords.")

    if not signals:
        signals.append(
            "No obvious structural warning was found. A clean structure does not prove a URL is safe."
        )

    return {
        "score": min(score, 100),
        "signals": signals,
        "host": host,
        "valid": True,
    }


def analyse_text(message):
    """Calculate a transparent heuristic score from text indicators."""
    found = []
    score = 0

    for name, pattern, weight, explanation in PATTERNS:
        if re.search(pattern, message, flags=re.IGNORECASE):
            found.append({
                "name": name,
                "weight": weight,
                "explanation": explanation,
            })
            score += weight

    urls = re.findall(
        r"(?:(?:https?://)|(?:www\.))[^\s<>\"']+|"
        r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>\"']*)?",
        message,
        flags=re.IGNORECASE,
    )

    url_results = []
    for item in urls[:10]:
        result = inspect_url(item)
        if result["valid"]:
            url_results.append({
                "url": item,
                **result,
            })

    # URL indicators contribute to the final risk estimate.
    max_url_score = max(
        (item["score"] for item in url_results),
        default=0,
    )
    score = min(100, score + round(max_url_score * 0.45))

    if score >= 60:
        level = "High"
        advice = "Do not click links or send money. Verify independently using an official channel."
    elif score >= 30:
        level = "Medium"
        advice = "Pause and verify the sender, request, and destination before taking action."
    else:
        level = "Low"
        advice = "No strong indicators were detected by these checks. Stay cautious and verify unexpected requests."

    return {
        "score": score,
        "level": level,
        "indicators": found,
        "urls": url_results,
        "advice": advice,
    }


# ============================================================
# OPTIONAL GEMINI EXPLANATION
# ============================================================

def get_ai_explanation(message, analysis):
    """Request a concise explanation from Gemini when configured."""
    if not GEMINI_API_KEY:
        return None

    prompt = f"""
You are the explanation assistant for ScamShield AI, a digital safety
prototype. Explain potential scam signals in the supplied message.
Do not claim certainty. Do not tell the user to click links or share
private information. Never ask for passwords, OTPs, or financial data.

Message to analyse:
{message[:6000]}

Heuristic risk score: {analysis['score']}/100
Heuristic risk level: {analysis['level']}
Detected indicators: {json.dumps(analysis['indicators'])}
URL findings: {json.dumps(analysis['urls'])}

Respond in plain text with:
1. A short explanation
2. The strongest warning signs
3. Safe next steps

Clearly state that the result is an estimate, not a guarantee.
"""

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.0-flash:generateContent?key="
        + urllib.parse.quote(GEMINI_API_KEY)
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 500,
        },
    }

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        return (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        ) or None

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, KeyError, IndexError):
        return None


# ============================================================
# SESSION STATE
# ============================================================

if "history" not in st.session_state:
    st.session_state.history = []

if "latest_result" not in st.session_state:
    st.session_state.latest_result = None


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🛡️ ScamShield AI")
    st.caption("Digital safety, made understandable.")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Scan a Message",
            "Scan a URL",
            "Business Mode",
            "AI Safety Assistant",
            "Safety Centre",
            "About the Project",
        ],
        label_visibility="visible",
    )

    st.divider()
    mode = st.selectbox(
        "Workspace",
        ["Personal", "Business"],
        help="Choose how you want to present the analysis.",
    )

    st.markdown(
        """
        <div class="panel">
          <div class="eyebrow">Our mission</div>
          <div style="font-size:18px;font-weight:700;color:white">
            Detect. Explain. Protect.
          </div>
          <p class="muted">
            Help people recognise suspicious digital messages before
            they take risky actions.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("Prototype • Results are estimates")


# ============================================================
# REUSABLE UI
# ============================================================

def show_hero(kicker, title, subtitle):
    st.markdown(
        f"""
        <div class="hero">
          <div class="eyebrow">{kicker}</div>
          <div class="hero-title">{title}</div>
          <div class="hero-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_result(analysis, label="Message analysis"):
    score = analysis["score"]
    level = analysis["level"]

    st.markdown("### Risk assessment")

    c1, c2, c3 = st.columns(3)
    c1.metric("Estimated risk", f"{score}/100")
    c2.metric("Risk category", level)
    c3.metric("Signals found", len(analysis["indicators"]))

    st.progress(score / 100)

    if level == "High":
        st.error("High-risk indicators detected. Stop and verify independently.")
    elif level == "Medium":
        st.warning("Some warning signs were detected. Check carefully before acting.")
    else:
        st.info("Few warning signs were detected. This is not proof that the message is safe.")

    st.markdown("**Recommended next step**")
    st.write(analysis["advice"])

    st.markdown("### Why did we flag it?")

    if analysis["indicators"]:
        for indicator in analysis["indicators"]:
            with st.container(border=True):
                st.markdown(f"**{indicator['name']}**")
                st.write(indicator["explanation"])
                st.caption(f"Rule contribution: +{indicator['weight']} points")
    else:
        st.write("No matching text indicators were found.")

    if analysis.get("urls"):
        st.markdown("### Links found in the message")
        for item in analysis["urls"]:
            with st.container(border=True):
                st.markdown(f"**{item['host']}**")
                st.caption(item["url"])
                st.write(f"URL structure score: {item['score']}/100")
                for signal in item["signals"]:
                    st.write(f"• {signal}")

    if analysis.get("ai_explanation"):
        st.markdown("### AI explanation")
        st.write(analysis["ai_explanation"])

    st.caption(
        "Scoring is based on heuristic rules and optional AI assistance. "
        "It is not a guarantee, a formal security audit, or a substitute "
        "for verification with the real organisation."
    )


def save_history(kind, content, analysis):
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": kind,
        "content": content[:1000],
        "score": analysis["score"],
        "risk": analysis["level"],
        "indicators": "; ".join(
            item["name"] for item in analysis["indicators"]
        ),
    }
    st.session_state.history.insert(0, entry)
    st.session_state.latest_result = {
        "kind": kind,
        "content": content,
        "analysis": analysis,
    }


# ============================================================
# DASHBOARD
# ============================================================

if page == "Dashboard":
    show_hero(
        "YOUR DIGITAL SAFETY COMPANION",
        "Think before you click.",
        "ScamShield AI helps you examine suspicious messages and URLs, "
        "understand warning signs, and choose safer next steps.",
    )

    total = len(st.session_state.history)
    high = sum(1 for x in st.session_state.history if x["risk"] == "High")
    medium = sum(1 for x in st.session_state.history if x["risk"] == "Medium")

    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">Session scans</div>'
            f'<div class="metric-value">{total}</div></div>',
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">High-risk results</div>'
            f'<div class="metric-value">{high}</div></div>',
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">Medium-risk results</div>'
            f'<div class="metric-value">{medium}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("## What can you do?")
    a, b, c = st.columns(3)

    with a:
        st.markdown(
            '<div class="panel"><h3>💬 Message Scan</h3>'
            '<p class="muted">Identify pressure tactics, credential requests, '
            'payment lures, and other warning signs.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Scan a message", use_container_width=True):
            st.session_state["nav_target"] = "Scan a Message"
            st.rerun()

    with b:
        st.markdown(
            '<div class="panel"><h3>🔗 URL Scan</h3>'
            '<p class="muted">Inspect a URL for suspicious structural '
            'features without opening it.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Inspect a URL", use_container_width=True):
            st.session_state["nav_target"] = "Scan a URL"
            st.rerun()

    with c:
        st.markdown(
            '<div class="panel"><h3>🏢 Business Mode</h3>'
            '<p class="muted">Review findings in a workflow suited to '
            'teams and awareness demonstrations.</p></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open Business Mode", use_container_width=True):
            st.session_state["nav_target"] = "Business Mode"
            st.rerun()

    st.markdown("## How ScamShield works")
    steps = st.columns(3)
    steps[0].markdown("**01 · Analyse**\n\nExamine the text and any URLs.")
    steps[1].markdown("**02 · Explain**\n\nShow the warning signs behind the estimate.")
    steps[2].markdown("**03 · Protect**\n\nRecommend safer actions before you respond.")

    st.info(
        "Demo tip: Open **Scan a Message**, load one of the sample scenarios, "
        "and explain each flagged indicator to the judges."
    )


# ============================================================
# MESSAGE SCANNER
# ============================================================

elif page == "Scan a Message":
    show_hero(
        "MESSAGE INTELLIGENCE",
        "Check before you trust.",
        "Paste a suspicious SMS, email, chat, or payment request. "
        "ScamShield will explain the warning signs it recognises.",
    )

    samples = {
        "Choose a demo example": "",
        "Example 1 — Fake account alert":
            "URGENT: Your bank account will be blocked today. Verify your account immediately and share your OTP to restore access.",
        "Example 2 — Prize scam":
            "Congratulations! You have won a free gift. Pay a processing fee now to claim your prize.",
        "Example 3 — Suspicious link":
            "Your account needs verification. Visit http://secure-account-check.example.com/login and enter your password immediately.",
        "Example 4 — Remote access request":
            "I am from official support. Install AnyDesk and share your screen so I can fix your banking issue.",
        "Example 5 — Ordinary message":
            "Hi, our study group meeting is scheduled for 4 PM tomorrow. Please bring your notes.",
    }

    selected = st.selectbox("Try a sample", list(samples.keys()))
    default_text = samples[selected]

    message = st.text_area(
        "Message to analyse",
        value=default_text,
        height=190,
        placeholder="Paste the message here. Avoid including real passwords, OTPs, or private financial information.",
        max_chars=10000,
    )

    st.caption("Privacy tip: Remove names, phone numbers, account numbers, and other personal information before scanning.")

    if st.button("🛡️ Analyse message", type="primary", use_container_width=True):
        if not message.strip():
            st.warning("Enter a message or choose a demo example first.")
        else:
            with st.spinner("Examining message indicators..."):
                result = analyse_text(message)
                result["ai_explanation"] = get_ai_explanation(message, result)
                save_history("Message", message, result)

            st.success("Analysis complete.")
            show_result(result)

    elif st.session_state.latest_result and st.session_state.latest_result["kind"] == "Message":
        st.markdown("### Latest result")
        show_result(st.session_state.latest_result["analysis"])


# ============================================================
# URL SCANNER
# ============================================================

elif page == "Scan a URL":
    show_hero(
        "LINK INSPECTION",
        "Look closely at the destination.",
        "Inspect a URL's visible structure for warning signs. "
        "ScamShield does not visit the website or guarantee its safety.",
    )

    url = st.text_input(
        "URL to inspect",
        placeholder="https://example.com/login",
    )

    st.warning(
        "Do not enter private access links or URLs containing personal tokens. "
        "This scanner examines the URL text only; it does not verify the site's reputation."
    )

    if st.button("🔎 Inspect URL", type="primary", use_container_width=True):
        if not url.strip():
            st.warning("Enter a URL to inspect.")
        else:
            result_url = inspect_url(url)

            if not result_url["valid"]:
                st.error("That URL could not be parsed. Check its format.")
            else:
                score = result_url["score"]
                level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"

                analysis = {
                    "score": score,
                    "level": level,
                    "indicators": [],
                    "urls": [result_url],
                    "advice": (
                        "Avoid opening the link if you were not expecting it. "
                        "Verify the domain using a known official source."
                    ),
                }
                save_history("URL", url, analysis)

                st.markdown("### URL assessment")
                col1, col2 = st.columns(2)
                col1.metric("Structural risk estimate", f"{score}/100")
                col2.metric("Risk category", level)
                st.progress(score / 100)

                for signal in result_url["signals"]:
                    st.write(f"• {signal}")

                st.info(analysis["advice"])
                st.caption(
                    "A low score does not mean a site is legitimate. "
                    "No domain reputation, malware, or phishing database was queried."
                )


# ============================================================
# BUSINESS MODE
# ============================================================

elif page == "Business Mode":
    show_hero(
        "FOR TEAMS & ORGANISATIONS",
        "Make safer decisions together.",
        "A prototype review workspace for staff awareness, suspicious-message "
        "triage, and explaining risk indicators.",
    )

    st.markdown("## Review a suspicious message")
    st.write(
        "Use this workflow for a training exercise or a message that your "
        "organisation has received. Do not paste confidential company data."
    )

    department = st.selectbox(
        "Team / use case",
        [
            "General awareness",
            "Customer support",
            "Finance",
            "Human resources",
            "IT and security",
        ],
    )

    business_message = st.text_area(
        "Message for review",
        height=160,
        placeholder="Paste a sanitised message for analysis...",
        key="business_message",
    )

    if st.button("Run business review", type="primary", use_container_width=True):
        if not business_message.strip():
            st.warning("Enter a message first.")
        else:
            analysis = analyse_text(business_message)
            analysis["ai_explanation"] = get_ai_explanation(
                business_message, analysis
            )
            save_history(f"Business: {department}", business_message, analysis)

            st.success(f"Review prepared for: {department}")
            show_result(analysis)

            st.markdown("### Suggested team actions")
            if analysis["level"] == "High":
                st.write(
                    "1. Do not reply, pay, or follow the link.\n"
                    "2. Verify the request using a known internal contact.\n"
                    "3. Follow your organisation's reporting process."
                )
            else:
                st.write(
                    "1. Verify the sender and the reason for the request.\n"
                    "2. Use a separate, trusted communication channel.\n"
                    "3. Report anything that remains suspicious."
                )

    st.markdown("## Business product direction")
    st.markdown(
        """
        - **Starter:** message and URL checks for individuals.
        - **Team:** shared workflows, training, and review exports.
        - **Enterprise (future):** approved integrations, admin controls,
          and organisation-specific reporting.
        """
    )
    st.caption(
        "These are proposed product tiers, not currently implemented paid features."
    )


# ============================================================
# AI SAFETY ASSISTANT
# ============================================================

elif page == "AI Safety Assistant":
    show_hero(
        "SAFETY KNOWLEDGE",
        "Ask before you act.",
        "Get practical guidance on suspicious messages, online scams, "
        "account safety, and safer digital habits.",
    )

    question = st.text_area(
        "What would you like help with?",
        placeholder="Example: Someone called me and asked for my OTP. What should I do?",
        height=130,
    )

    if st.button("Get safety guidance", type="primary", use_container_width=True):
        if not question.strip():
            st.warning("Enter a question first.")
        elif GEMINI_API_KEY:
            with st.spinner("Preparing safety guidance..."):
                assistant_analysis = {
                    "score": 0,
                    "level": "Unknown",
                    "indicators": [],
                    "urls": [],
                }
                response = get_ai_explanation(question, assistant_analysis)

            if response:
                st.markdown("### Guidance")
                st.write(response)
            else:
                st.error("The AI service could not respond. Use the checklist below.")
        else:
            st.info(
                "Optional AI assistance is not configured. You can still use "
                "the message and URL scanners. For immediate guidance, never "
                "share an OTP or password, and verify unexpected requests "
                "through a trusted official channel."
            )

    st.markdown("## Quick safety rules")
    st.markdown(
        """
        - Never share your OTP, password, PIN, or card CVV with a caller or message sender.
        - Do not trust a message only because it uses a familiar logo or organisation name.
        - Avoid clicking unexpected links or installing apps at a stranger's request.
        - Verify payment requests using a separate, trusted contact method.
        - If you already shared credentials, contact the relevant provider through its official channel immediately.
        """
    )


# ============================================================
# SAFETY CENTRE
# ============================================================

elif page == "Safety Centre":
    show_hero(
        "PRACTICAL PROTECTION",
        "Small checks. Safer choices.",
        "Use this checklist whenever a message asks for money, credentials, "
        "personal details, or urgent action.",
    )

    checklist = [
        "The sender's identity is independently verified.",
        "The request was expected and makes sense.",
        "I have not shared an OTP, password, PIN, or CVV.",
        "I have checked the destination domain carefully.",
        "I verified payment requests through a separate channel.",
        "I have not installed remote-access software at a stranger's request.",
    ]

    checked_count = 0
    for item in checklist:
        if st.checkbox(item, key="safety_" + str(checklist.index(item))):
            checked_count += 1

    st.progress(checked_count / len(checklist))
    st.caption(f"{checked_count} of {len(checklist)} checks completed.")

    st.markdown("## If you suspect fraud")
    st.markdown(
        """
        1. Stop communicating with the suspicious sender.
        2. Do not send more money or disclose additional information.
        3. Contact your bank or service provider using official contact details.
        4. Change compromised credentials and enable multi-factor authentication.
        5. Preserve relevant evidence and report the incident to the appropriate authority.
        """
    )
    st.caption(
        "If you are in India and have experienced financial cyber fraud, "
        "consider contacting the official cybercrime reporting service or "
        "the relevant authorities promptly."
    )


# ============================================================
# ABOUT / PITCH
# ============================================================

elif page == "About the Project":
    show_hero(
        "BUILT FOR DIGITAL AWARENESS",
        "ScamShield AI",
        "A hackathon prototype designed to make suspicious digital messages "
        "easier to understand and safer to handle.",
    )

    st.markdown("## The problem")
    st.write(
        "Fraudulent messages often rely on urgency, fear, impersonation, "
        "unexpected rewards, or requests for sensitive information. "
        "People may notice something feels wrong without knowing why."
    )

    st.markdown("## Our approach")
    left, right = st.columns(2)

    with left:
        st.markdown("### 🔍 Explainable checks")
        st.write(
            "Rule-based indicators highlight patterns in message text and URL structure."
        )

        st.markdown("### 🧠 Optional AI assistance")
        st.write(
            "When configured, Gemini can produce a readable explanation "
            "and practical safety guidance."
        )

    with right:
        st.markdown("### 🏢 Personal and Business workflows")
        st.write(
            "The interface supports individual checks and a business-oriented review demonstration."
        )

        st.markdown("### 📊 Session reporting")
        st.write(
            "Scan results can be reviewed and exported during the active session."
        )

    st.markdown("## Technology")
    st.markdown(
        """
        <span class="pill">Python</span>
        <span class="pill">Streamlit</span>
        <span class="pill">Rule-based analysis</span>
        <span class="pill">Optional Gemini API</span>
        <span class="pill">CSV reporting</span>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("## Business model — proposal")
    st.markdown(
        """
        | Tier | Possible offering |
        |---|---|
        | Personal | Free basic checks and safety guidance |
        | Business | Team workflows, awareness training, reporting |
        | Enterprise | Future integrations, administration, and support |
        """
    )

    st.markdown("## Current limitations")
    st.markdown(
        """
        - This prototype does not connect to a verified global scam database.
        - URL inspection is structural and does not open or scan the destination.
        - Heuristic scoring can produce false positives and false negatives.
        - Optional AI output may be incorrect and must be reviewed.
        - Business accounts, shared storage, billing, and enterprise controls are not implemented.
        """
    )

    st.success(
        "Our motto: Detect. Explain. Protect."
    )


# ============================================================
# SESSION HISTORY AND EXPORT
# ============================================================

st.divider()
st.markdown("## Recent session activity")

if st.session_state.history:
    st.caption(
        "This history exists only in the current Streamlit session. "
        "It is not a permanent database."
    )

    for index, entry in enumerate(st.session_state.history[:10]):
        with st.expander(
            f"{entry['time']} · {entry['type']} · {entry['risk']} risk ({entry['score']}/100)"
        ):
            st.write(entry["content"])
            st.write("Indicators:", entry["indicators"] or "No matching text indicators")

    csv_buffer = io.StringIO()
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=[
            "time", "type", "content", "score", "risk", "indicators"
        ],
    )
    writer.writeheader()
    writer.writerows(st.session_state.history)

    st.download_button(
        "⬇️ Export session history as CSV",
        data=csv_buffer.getvalue(),
        file_name="scamshield_session_history.csv",
        mime="text/csv",
        use_container_width=True,
    )

    if st.button("Clear session history"):
        st.session_state.history = []
        st.session_state.latest_result = None
        st.rerun()
else:
    st.caption("No scans yet. Analyse a sample message to populate your session activity.")

st.divider()
st.markdown(
    """
    <div style="text-align:center;color:#8495b2;font-size:12px;padding:8px 0 18px">
        🛡️ ScamShield AI · Detect. Explain. Protect.<br>
        An educational prototype. Always verify suspicious requests independently.
    </div>
    """,
    unsafe_allow_html=True,
)
