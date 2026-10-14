import re
import os
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import streamlit.components.v1 as components
import base64
import json
import html

st.set_page_config(
    page_title="ScamShield | Verify Before You Trust",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Visual theme: accessible light UI ----------
st.markdown("""
<style>
:root { color-scheme: light; }
.stApp { background: #f4f7fc; color: #172033; }
.block-container { max-width: 1240px; padding-top: 1.4rem; padding-bottom: 3rem; }
[data-testid="stHeader"] { background: rgba(244,247,252,.92); }
[data-testid="stSidebar"] { background: #ffffff; border-right: 1px solid #e2e8f0; }
[data-testid="stSidebar"] * { color: #24324a !important; }
.stApp, .stApp p, .stApp label, .stApp li, .stApp [data-testid="stMarkdownContainer"] { color: #24324a; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4 { color: #111c32; letter-spacing: -.025em; }
.hero { padding: 2rem 2.1rem; border: 1px solid #dbe5f3; border-radius: 24px;
        background: linear-gradient(120deg, #10274d 0%, #1b4f85 58%, #176e83 100%);
        box-shadow: 0 16px 36px rgba(26,54,93,.12); }
.hero h1 { margin: .25rem 0 .55rem; font-size: clamp(2.1rem, 4vw, 3.1rem); color: #ffffff !important; letter-spacing: -.05em; }
.hero p { color: #e4efff !important; font-size: 1.06rem; max-width: 850px; line-height: 1.65; margin-bottom: .8rem; }
.hero .kicker { color: #7ef0d0 !important; font-size: .76rem; font-weight: 900; letter-spacing: .16em; }
.kicker { color: #087e8b; font-size: .78rem; font-weight: 800; letter-spacing: .15em; }
.pill { display:inline-block; border:1px solid rgba(255,255,255,.35); border-radius:999px; padding:6px 11px;
        color:#f0f7ff !important; background:rgba(255,255,255,.1); font-size:.8rem; margin: 3px 5px 3px 0; }
.panel { background: #ffffff; color:#24324a; border: 1px solid #e0e8f3; padding: 1rem 1.1rem; border-radius: 16px; box-shadow: 0 5px 18px rgba(29,55,90,.045); }
.panel b, .panel strong { color: #14213a !important; }
.link-check { background:#fff; border:1px solid #e0e8f3; border-radius:12px; padding:12px 14px; margin:10px 0; overflow-wrap:anywhere; word-break:break-word; }
.link-check code { white-space:normal !important; overflow-wrap:anywhere; word-break:break-word; font-size:.88rem; }
.link-check p { margin:.6rem 0 0; }
.reminder { margin-top:16px; }
.reminder p { margin:.45rem 0 0; }
[data-testid="stMarkdownContainer"] code { overflow-wrap:anywhere; word-break:break-word; }
.smallmuted { color:#64748b !important; font-size:.9rem; line-height:1.55; }
.stButton > button, .stDownloadButton > button { border-radius: 12px; font-weight: 750; min-height: 2.8rem; border: 1px solid #d6e0ee; }
.stButton > button[kind="primary"] { background: #126e82; border-color: #126e82; color: #ffffff; }
.stButton > button[kind="primary"] p { color: #ffffff !important; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: #16899c; color: #07566b; }
div[data-testid="stMetric"] { background:#ffffff; border:1px solid #e0e8f3; padding:16px; border-radius:16px; box-shadow:0 5px 18px rgba(29,55,90,.045); }
div[data-testid="stMetric"] label, div[data-testid="stMetric"] [data-testid="stMetricLabel"] { color:#64748b !important; }
div[data-testid="stMetric"] [data-testid="stMetricValue"] { color:#14213a !important; }
.stTextArea textarea, .stTextInput input, .stSelectbox div[data-baseweb="select"], .stNumberInput input {
  background:#ffffff !important; color:#172033 !important; border-color:#cbd7e6 !important; border-radius:12px !important;
}
.stTextArea textarea::placeholder, .stTextInput input::placeholder { color:#78879b !important; opacity:1 !important; }
.stSelectbox [data-baseweb="select"] * { color:#172033 !important; }
.stCheckbox label p { color:#24324a !important; }
[data-testid="stExpander"] { background:#ffffff; border:1px solid #e0e8f3; border-radius:12px; }
[data-testid="stAlert"] { border-radius:14px; }
hr { border-color:#dce5f0 !important; }
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ---------- Explainable detection rules ----------
RULES = [
    ("Credential or account takeover", 30, [
        r"\bshare (?:your )?(?:otp|one[- ]time password|upi pin|pin number)\b",
        r"\bprovide (?:your )?(?:password|otp|upi pin)\b", r"\bcard cvv\b",
        r"\bbank password\b", r"\baccount will be (?:blocked|suspended|closed) unless\b",
        r"\bverify your (?:bank|account|wallet) immediately\b", r"\bremote access\b"
    ], "Requests for OTPs, passwords, UPI PINs, CVVs, or remote access are serious warning signs."),
    ("Upfront fee or payment", 24, [
        r"\bregistration fee\b", r"\bpay (?:a |the )?(?:fee|amount|deposit)\b",
        r"\bpayment required\b", r"\bprocessing fee\b", r"\bsecurity deposit\b",
        r"\bpay to get (?:the )?(?:job|internship|offer|certificate|prize|loan)\b",
        r"\brefundable fee\b", r"\btraining fee\b", r"\bjoining fee\b",
        r"\bapplication fee\b", r"\bpay now\b", r"\bpay to release\b",
        r"\badvance payment\b", r"\bcustoms fee\b", r"\bdelivery fee\b"
    ], "Unexpected advance payments, release fees, or pressure to pay should be independently verified."),
    ("Urgency, threats, or pressure", 14, [
        r"\blimited (?:slots|seats|time)\b", r"\bonly today\b", r"\bact now\b",
        r"\blast chance\b", r"\bimmediately\b", r"\bwithin \d+ minutes\b",
        r"\boffer expires\b", r"\bdon't miss\b", r"\burgent\b",
        r"\byour account will be blocked\b", r"\blegal action will be taken\b",
        r"\bpay within \d+\b", r"\bfinal warning\b"
    ], "Scammers often use urgency or threats to prevent independent verification."),
    ("Unrealistic profit, prize, or income claim", 15, [
        r"\bguaranteed (?:profit|returns|income)\b", r"\bdouble your money\b",
        r"\bearn money easily\b", r"\bno risk.*returns\b", r"\b100% returns\b",
        r"\bwon (?:a|the) prize\b", r"\byou have won\b", r"\bclaim your reward\b",
        r"\bearn (?:₹|rs\.?|inr)?\s?\d[\d,]*(?:\s?(?:per|/)\s?(?:day|hour|week))\b",
        r"\bno experience.*high salary\b", r"\beasy money\b"
    ], "Guaranteed returns, unexpected prizes, and unrealistic income claims deserve extra scrutiny."),
    ("Job, internship, or placement red flags", 16, [
        r"\bguaranteed (?:job|placement|internship|selection)\b",
        r"\b100% placement\b", r"\bjob guaranteed\b", r"\bconfirmed placement\b",
        r"\bwork from home.*registration fee\b", r"\bpay to get hired\b"
    ], "Verify jobs and recruiters through the organization's independently found official careers page."),
    ("Suspicious link or app instruction", 12, [
        r"\bclick (?:this|the) link\b", r"\bverify your account\b",
        r"\bclaim your offer\b", r"\bdownload this apk\b", r"\binstall this app\b",
        r"\bopen the attachment\b", r"\blog in here\b", r"\bupdate kyc\b"
    ], "Unexpected links, APK files, and login prompts can lead to phishing or malware. Verify through an official app or site."),
    ("Impersonation or fake support", 14, [
        r"\bwe are from (?:your )?(?:bank|police|customs|income tax)\b",
        r"\bcustomer support agent\b", r"\bpay fine to avoid arrest\b",
        r"\bpolice case against you\b", r"\bdigital arrest\b",
        r"\bpretend to be\b", r"\baccount manager on whatsapp\b"
    ], "Verify identity using a phone number or contact method published by the real organization."),
    ("Unverified contact channel", 7, [
        r"\bwhatsapp only\b", r"\bcontact only on whatsapp\b",
        r"\btelegram only\b", r"\bno official website\b"
    ], "A messaging app does not prove fraud, but verify the sender independently."),
    ("Webinar or course paid upsell", 8, [r"\bfree webinar\b", r"\bfree masterclass\b", r"\bwebinar\b", r"\bcertificate course\b"],
     "A webinar or course is not automatically suspicious. Check for high-pressure sales and unclear fees."),
    ("Crypto, trading, or investment language", 8, [
        r"\bcrypto investment\b", r"\btrading signals\b", r"\bguaranteed returns\b",
        r"\bdouble your investment\b", r"\bforex signals\b", r"\bmining pool\b"
    ], "Do not rely on guaranteed-profit claims or unverified investment groups; check official regulator guidance."),
    ("Personal or financial data request", 18, [
        r"\bsend (?:your )?(?:aadhaar|pan card|passport)\b", r"\bshare bank details\b",
        r"\benter your card number\b", r"\bsubmit your identity documents\b",
        r"\bupi pin\b", r"\bcard cvv\b"
    ], "Share sensitive identity or financial data only when you have verified the recipient and the need.")
]

URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".work", ".monster", ".buzz", ".rest", ".gq", ".tk"}

def scan_text(text):
    low = text.lower()
    findings = []
    score = 0
    for name, points, patterns, explanation in RULES:
        hits = [p for p in patterns if re.search(p, low, re.I)]
        if hits:
            # The webinar indicator only becomes a warning when paired with payment/pressure language.
            if name == "Webinar or course paid upsell":
                paired = any(re.search(p, low, re.I) for p in RULES[1][2]) or any(
                    re.search(p, low, re.I) for p in RULES[2][2])
                if not paired:
                    continue
            score += points
            findings.append({"name": name, "points": points, "explanation": explanation})
    urls = URL_RE.findall(text)
    url_notes = []
    for raw in urls:
        cleaned = raw.rstrip(".,);]")
        candidate = cleaned if cleaned.lower().startswith("http") else "https://" + cleaned
        try:
            host = (urlparse(candidate).hostname or "").lower()
        except Exception:
            host = ""
        if host.startswith("www."):
            host = host[4:]
        if not host:
            continue
        if host in SHORTENERS:
            score += 12
            url_notes.append((cleaned, "Shortened URL hides the final destination. Verify it independently."))
        elif host.startswith("xn--") or ".xn--" in host:
            score += 12
            url_notes.append((cleaned, "Internationalized domain: check carefully for lookalike characters."))
        elif any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 7
            url_notes.append((cleaned, f"The domain ending in this link ({host}) merits extra checking; this alone does not prove fraud."))
        else:
            url_notes.append((cleaned, f"Check that {host} exactly matches the organization's official domain."))
    score = min(score, 100)
    if score >= 60:
        level, color, headline = "HIGH RISK", "#b4233c", "Pause before paying, clicking, or sharing information."
    elif score >= 30:
        level, color, headline = "CAUTION", "#946200", "Verify the organization and the offer before proceeding."
    else:
        level, color, headline = "LOWER SIGNAL", "#087e8b", "Few known warning signs were detected; this is not proof of legitimacy."
    if not text.strip():
        level, color, headline, score = "NOT SCANNED", "#64748b", "Paste a message to begin.", 0
    return score, level, color, headline, findings, url_notes

def make_checklist(text):
    low = text.lower()
    tasks = [
        ("Find the role on the company's official careers website.", True),
        ("Verify the recruiter using contact details published on the official website.", True),
        ("Search the exact company name + 'scam', 'reviews', or 'complaint'.", True),
        ("Read the offer letter, role description, salary, and terms carefully.", True),
    ]
    if re.search(r"fee|pay|payment|deposit|registration|training fee|joining fee", low):
        tasks.insert(0, ("Do not pay a fee until the employer and the reason for payment are independently verified.", True))
    if re.search(r"otp|password|upi pin|cvv|bank details|aadhaar|pan", low):
        tasks.insert(0, ("Do not share OTPs, passwords, UPI PINs, or unnecessary identity/bank details.", True))
    if URL_RE.search(text):
        tasks.append(("Do not use the message link to log in; navigate to the official website yourself.", True))
    return tasks


def speech_player(text, language, label):
    """A real, user-activated browser speech control (no autoplay)."""
    safe_text = html.escape(text, quote=True)
    safe_language = html.escape(language, quote=True)
    safe_label = html.escape(label, quote=True)
    components.html(f"""
    <div style="font-family:Arial,sans-serif;padding:2px 0">
      <button type="button" aria-label="{safe_label}" data-text="{safe_text}" data-lang="{safe_language}"
        onclick="const u=new SpeechSynthesisUtterance(this.dataset.text); u.lang=this.dataset.lang; u.rate=0.82; window.speechSynthesis.cancel(); window.speechSynthesis.speak(u);"
        style="width:100%;min-height:58px;border:2px solid #126e82;border-radius:12px;background:#126e82;color:white;font-size:18px;font-weight:700;cursor:pointer;padding:12px">
        {safe_label}
      </button>
      <div style="font-size:12px;color:#526174;margin-top:5px">Tap to hear this advice. Audio support depends on your browser and installed language voices.</div>
    </div>
    """, height=88)


def get_gemini_client():
    """Read the server-side Gemini secret; never ask end users for a key."""
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        try:
            key = str(st.secrets.get("GEMINI_API_KEY", "")).strip()
        except Exception:
            key = ""
    if not key:
        return None
    from google import genai
    return genai.Client(api_key=key)


def gemini_text(prompt, parts=None):
    """Call Gemini using the server-configured key."""
    from google.genai import types
    client = get_gemini_client()
    if client is None:
        raise RuntimeError("Gemini is not configured on the server. Set GEMINI_API_KEY in the environment or Streamlit secrets.")
    contents = [prompt]
    if parts:
        contents.extend(parts)
    response = client.models.generate_content(model="gemini-2.5-flash", contents=contents,
        config=types.GenerateContentConfig(temperature=0.2, max_output_tokens=700))
    return (response.text or "I could not prepare an answer. Please try again.").strip()

LANGUAGE_META = {
    "English": {"code":"en-IN", "instruction":"Reply in simple English."},
    "తెలుగు (Telugu)": {"code":"te-IN", "instruction":"Reply only in simple, natural Telugu (తెలుగు). Use short sentences understandable to an older adult. Do not switch to English except for common technical terms like OTP and UPI PIN."},
    "हिन्दी (Hindi)": {"code":"hi-IN", "instruction":"Reply only in simple, natural Hindi (हिन्दी). Use short sentences understandable to an older adult. Do not switch to English except for common technical terms like OTP and UPI PIN."},
}

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("## 🛡️ ScamShield")
    st.caption("General-purpose scam & spam safety")
    language_choice = st.selectbox("Language / భాష / भाषा", list(LANGUAGE_META.keys()), key="global_language")
    language_code = LANGUAGE_META[language_choice]["code"]
    language_instruction = LANGUAGE_META[language_choice]["instruction"]
    pages = ["Easy Mode — Speak or Show", "Scan a message", "AI Security Assistant", "How it works", "Safety checklist", "About the project"]
    page_names = {
      "English": {p:p for p in pages},
      "తెలుగు (Telugu)": {"Easy Mode — Speak or Show":"సులభమైన విధానం — మాట్లాడండి లేదా చూపించండి", "Scan a message":"సందేశాన్ని తనిఖీ చేయండి", "AI Security Assistant":"AI భద్రతా సహాయకుడు", "How it works":"ఇది ఎలా పనిచేస్తుంది", "Safety checklist":"భద్రతా తనిఖీ జాబితా", "About the project":"ప్రాజెక్ట్ గురించి"},
      "हिन्दी (Hindi)": {"Easy Mode — Speak or Show":"आसान मोड — बोलें या दिखाएँ", "Scan a message":"संदेश जाँचें", "AI Security Assistant":"AI सुरक्षा सहायक", "How it works":"यह कैसे काम करता है", "Safety checklist":"सुरक्षा जाँच सूची", "About the project":"प्रोजेक्ट के बारे में"}
    }
    page = st.radio("Navigate / వెళ్లండి / जाएँ", pages, format_func=lambda p: page_names[language_choice].get(p,p))
    st.divider()
    st.markdown("**Built for:**")
    st.markdown("• SMS, email & chat messages\n• Phishing & impersonation\n• Shopping, payment & job scams\n• Suspicious links & data requests")
    st.caption("Broad rule-based screening • Optional AI assistant")

# ---------- Hero ----------
st.markdown("""
<div class="hero">
  <div class="kicker">STUDENT CYBER SAFETY</div>
  <h1>🛡️ ScamShield</h1>
  <p><b>Verify before you trust.</b> Screen suspicious SMS, emails, chats, links, payment requests, shopping offers, job posts and impersonation attempts. Get explanations and safer next steps.</p>
  <span class="pill">Multi-category screening</span><span class="pill">Explainable risk signals</span><span class="pill">Built-in security assistant</span>
</div>
""", unsafe_allow_html=True)
st.write("")

if page == "Easy Mode — Speak or Show":
    st.markdown("### 💙 Easy Mode — for everyone")
    st.markdown("## You do not need to type.")
    st.write("Choose what happened, speak your question, or show us a screenshot. ScamShield will explain the next step in simple language.")
    st.markdown("<style>div.stButton>button{min-height:4.2rem;font-size:1.05rem;white-space:normal;} .easy-copy{font-size:1.15rem;line-height:1.7}</style>", unsafe_allow_html=True)
    simple_guidance = {
        "Someone is asking me to pay": ("PAUSE. Do not send money yet.", "Unexpected fees, delivery charges, job fees, and fees to release prizes can be warning signs. Ask a trusted person to help verify the sender using an official phone number or website you find yourself."),
        "Someone asked for my OTP or PIN": ("STOP. Never share your OTP or PIN.", "Your bank, payment app, or real support staff should not ask you to tell them your UPI PIN, password, or OTP. If you already shared it, contact your bank or payment provider immediately using its official app or number."),
        "I got a strange link": ("Do not tap the link yet.", "A link in a message may lead to a fake website or harmful download. Open the official app yourself or ask a trusted person to check the exact website address. Do not enter passwords or bank details on a page opened from an unexpected message."),
        "A job or prize sounds too good": ("Check it before you trust it.", "Be careful if someone promises guaranteed jobs, easy money, a prize you did not enter to win, or asks you to pay first. Check with the real company using contact details from its official website."),
        "Someone says I will be arrested or my account blocked": ("Take a breath. Do not panic or pay immediately.", "Scammers may use threats to rush people. Do not share codes or give remote access to your phone. Contact the real bank or agency through an official number you find independently, and ask a trusted person to help."),
        "I already paid or shared details": ("Act quickly. You can still ask for help.", "Contact your bank or payment provider immediately using its official app or number and ask whether the payment or account can be secured. In India, report suspected cyber financial fraud promptly through the official 1930 helpline or cybercrime.gov.in. Keep messages and transaction details; do not send more money to someone promising recovery.")
    }
    # Fixed, offline guidance in three languages: core help remains available without an API key.
    translated_labels = {
        "English": {
            "Someone is asking me to pay": "Someone is asking me to pay",
            "Someone asked for my OTP or PIN": "Someone asked for my OTP or PIN",
            "I got a strange link": "I got a strange link",
            "A job or prize sounds too good": "A job or prize sounds too good",
            "Someone says I will be arrested or my account blocked": "Someone says I will be arrested or my account blocked",
            "I already paid or shared details": "I already paid or shared details",
        },
        "తెలుగు (Telugu)": {
            "Someone is asking me to pay": "డబ్బులు చెల్లించమంటున్నారా?",
            "Someone asked for my OTP or PIN": "OTP లేదా PIN అడిగారా?",
            "I got a strange link": "అనుమానాస్పద లింక్ వచ్చిందా?",
            "A job or prize sounds too good": "ఉద్యోగం లేదా బహుమతి నిజం కాదనిపిస్తుందా?",
            "Someone says I will be arrested or my account blocked": "అరెస్ట్ చేస్తామని లేదా ఖాతా బ్లాక్ చేస్తామని బెదిరిస్తున్నారా?",
            "I already paid or shared details": "ఇప్పటికే డబ్బులు పంపారా లేదా వివరాలు ఇచ్చారా?",
        },
        "हिन्दी (Hindi)": {
            "Someone is asking me to pay": "कोई पैसे माँग रहा है",
            "Someone asked for my OTP or PIN": "किसी ने OTP या PIN माँगा",
            "I got a strange link": "मुझे एक संदिग्ध लिंक मिला",
            "A job or prize sounds too good": "नौकरी या इनाम सच नहीं लग रहा",
            "Someone says I will be arrested or my account blocked": "कोई गिरफ्तारी या खाता बंद करने की धमकी दे रहा है",
            "I already paid or shared details": "मैंने पैसे भेज दिए या जानकारी साझा कर दी",
        },
    }
    translated_guidance = {
        "తెలుగు (Telugu)": {
            "Someone is asking me to pay": ("ఆగండి. వెంటనే డబ్బులు పంపకండి.", "అనుకోని డెలివరీ ఛార్జీలు, ఉద్యోగ రుసుములు లేదా బహుమతి తీసుకోవడానికి డబ్బులు అడగడం మోసానికి సంకేతం కావచ్చు. డబ్బులు పంపే ముందు అధికారిక నంబర్ ద్వారా నిజమో కాదో తెలుసుకోండి. అవసరమైతే నమ్మకమైన వ్యక్తి సహాయం తీసుకోండి."),
            "Someone asked for my OTP or PIN": ("ఆగండి. OTP లేదా PIN ఎవరికీ చెప్పకండి.", "మీ OTP, UPI PIN, పాస్‌వర్డ్ లేదా CVV ఎవరికీ చెప్పకండి. ఇప్పటికే చెప్పి ఉంటే వెంటనే మీ బ్యాంక్ అధికారిక యాప్ లేదా అధికారిక నంబర్ ద్వారా సంప్రదించండి."),
            "I got a strange link": ("ఇప్పుడే ఆ లింక్‌ను తెరవకండి.", "ఆ లింక్ నకిలీ వెబ్‌సైట్‌కు తీసుకెళ్లవచ్చు. మెసేజ్‌లోని లింక్ బదులుగా అధికారిక యాప్‌ను మీరే తెరవండి. పాస్‌వర్డ్ లేదా బ్యాంక్ వివరాలు నమోదు చేయకండి."),
            "A job or prize sounds too good": ("నమ్మే ముందు తనిఖీ చేయండి.", "ఉద్యోగం ఖాయం, సులభంగా డబ్బు, లేదా మీరు పాల్గొనని పోటీలో బహుమతి వచ్చిందని చెబితే జాగ్రత్త. ముందుగా డబ్బులు చెల్లించకండి. సంస్థ అధికారిక వెబ్‌సైట్ ద్వారా నిర్ధారించండి."),
            "Someone says I will be arrested or my account blocked": ("భయపడకండి. వెంటనే డబ్బులు చెల్లించకండి.", "మోసగాళ్లు భయపెట్టి తొందరపెడతారు. OTP చెప్పకండి, ఫోన్‌కు రిమోట్ యాక్సెస్ ఇవ్వకండి. అధికారిక నంబర్ ద్వారా సంస్థను సంప్రదించి, నమ్మకమైన వ్యక్తి సహాయం తీసుకోండి."),
            "I already paid or shared details": ("త్వరగా సహాయం తీసుకోండి.", "మీ బ్యాంక్ లేదా చెల్లింపు యాప్ అధికారిక నంబర్‌కు వెంటనే ఫోన్ చేసి లావాదేవీని ఆపగలరా అని అడగండి. భారతదేశంలో సైబర్ ఆర్థిక మోసం జరిగితే 1930కు త్వరగా కాల్ చేయండి లేదా cybercrime.gov.in లో నివేదించండి. సందేశాలు, లావాదేవీ వివరాలు భద్రపరచండి. డబ్బులు తిరిగి ఇప్పిస్తామని చెప్పేవారికి మరిన్ని డబ్బులు పంపకండి."),
        },
        "हिन्दी (Hindi)": {
            "Someone is asking me to pay": ("रुकें। अभी पैसे न भेजें।", "अचानक डिलीवरी शुल्क, नौकरी की फीस या इनाम पाने के लिए पैसे माँगना धोखाधड़ी का संकेत हो सकता है। पैसे भेजने से पहले आधिकारिक नंबर से जाँच करें और ज़रूरत हो तो किसी भरोसेमंद व्यक्ति की मदद लें।"),
            "Someone asked for my OTP or PIN": ("रुकें। OTP या PIN किसी को न बताएं।", "अपना OTP, UPI PIN, पासवर्ड या CVV किसी के साथ साझा न करें। अगर आपने साझा कर दिया है, तो तुरंत अपने बैंक के आधिकारिक ऐप या नंबर से संपर्क करें।"),
            "I got a strange link": ("अभी उस लिंक पर क्लिक न करें।", "लिंक नकली वेबसाइट खोल सकता है। संदेश के लिंक के बजाय आधिकारिक ऐप खुद खोलें। पासवर्ड या बैंक की जानकारी न डालें।"),
            "A job or prize sounds too good": ("भरोसा करने से पहले जाँचें।", "गारंटी वाली नौकरी, आसानी से कमाई या ऐसे इनाम का दावा सावधानी से देखें जिसमें आपने हिस्सा नहीं लिया। पहले पैसे न दें। कंपनी की आधिकारिक वेबसाइट से जाँच करें।"),
            "Someone says I will be arrested or my account blocked": ("घबराएँ नहीं। तुरंत पैसे न दें।", "धोखेबाज़ डराकर जल्दी फैसला करवाते हैं। OTP न बताएँ और फोन का रिमोट एक्सेस न दें। आधिकारिक नंबर से जाँच करें और किसी भरोसेमंद व्यक्ति की मदद लें।"),
            "I already paid or shared details": ("जल्दी मदद लें।", "अपने बैंक या भुगतान सेवा से तुरंत उनके आधिकारिक नंबर पर संपर्क करें। भारत में साइबर वित्तीय धोखाधड़ी होने पर 1930 पर जल्द कॉल करें या cybercrime.gov.in पर रिपोर्ट करें। संदेश और लेन-देन का रिकॉर्ड रखें। पैसे वापस दिलाने का दावा करने वालों को और पैसे न दें।"),
        },
    }
    st.markdown("#### 1. Tap the option that matches your situation")
    options = list(simple_guidance.items())
    for i in range(0, len(options), 2):
        cols = st.columns(2)
        for col, (key, _) in zip(cols, options[i:i+2]):
            with col:
                visible_label = translated_labels[language_choice][key]
                if st.button(visible_label, key="easy_" + str(i) + key, use_container_width=True):
                    st.session_state["easy_answer"] = translated_guidance.get(language_choice, {}).get(key, simple_guidance[key])
                    st.session_state["easy_answer_language"] = language_code
    helper_labels = {
        "English": "🤝 I need help from someone I trust",
        "తెలుగు (Telugu)": "🤝 నాకు నమ్మకమైన వ్యక్తి సహాయం కావాలి",
        "हिन्दी (Hindi)": "🤝 मुझे किसी भरोसेमंद व्यक्ति की मदद चाहिए",
    }
    if st.button(helper_labels[language_choice], key="easy_trusted_helper", use_container_width=True):
        helper_messages = {
            "English": ("Please help me check this.", "I received a message or request that I do not fully understand. Please help me verify it using an official contact method before I pay, click a link, or share information."),
            "తెలుగు (Telugu)": ("దయచేసి దీన్ని తనిఖీ చేయడంలో సహాయం చేయండి.", "నాకు పూర్తిగా అర్థం కాని సందేశం లేదా అభ్యర్థన వచ్చింది. డబ్బులు చెల్లించే ముందు, లింక్ తెరవడానికి ముందు లేదా వివరాలు ఇచ్చే ముందు అధికారిక మార్గంలో నిజమో కాదో తనిఖీ చేయడంలో సహాయం చేయండి."),
            "हिन्दी (Hindi)": ("कृपया इसे जाँचने में मेरी मदद करें।", "मुझे एक ऐसा संदेश या अनुरोध मिला है जिसे मैं पूरी तरह नहीं समझता/समझती। पैसे भेजने, लिंक खोलने या जानकारी साझा करने से पहले कृपया आधिकारिक तरीके से इसकी जाँच करने में मदद करें।"),
        }
        st.session_state["easy_answer"] = helper_messages[language_choice]
        st.session_state["easy_answer_language"] = language_code
    if "easy_answer" in st.session_state:
        title, explanation = st.session_state["easy_answer"]
        st.subheader(title)
        st.write(explanation)
        spoken = title + " " + explanation
        speech_player(spoken, st.session_state.get("easy_answer_language", language_code), "🔊 Read this aloud / చదివి వినిపించు / सुनकर समझें")

    st.divider()
    st.markdown("#### 2. Show a screenshot or speak your concern")
    st.write("Upload a screenshot or record your question. Gemini runs using the app owner's securely configured server key; users do not need their own key.")
    shot = st.file_uploader("📷 Upload a screenshot/photo of the suspicious message", type=["png", "jpg", "jpeg", "webp"], key="easy_screenshot")
    if shot and st.button("Read and check this screenshot", type="primary", use_container_width=True):
        try:
            from google.genai import types
            mime = shot.type or "image/png"
            prompt = "You are ScamShield, a patient cyber-safety helper for elders and people with low literacy. " + language_instruction + " Read text visible in this screenshot, explain what it asks the person to do, list warning signs, and give safe next steps. Never claim it is definitely safe. Warn against sharing OTPs, passwords, UPI PINs, CVVs, or sending money under pressure. If unreadable, say so. Keep it short."
            answer = gemini_text(prompt, [types.Part.from_bytes(data=shot.getvalue(), mime_type=mime)])
            st.session_state["easy_answer"] = ("ScamShield", answer)
            st.session_state["easy_answer_language"] = language_code
            st.rerun()
        except Exception as exc:
            if "not configured on the server" in str(exc):
                st.error("AI screenshot help is not configured by the app administrator yet. One-tap safety guidance still works.")
            else:
                st.error("I couldn't read the screenshot. Please try a clearer image or use a one-tap option. " + str(exc)[:160])
    audio = st.audio_input("🎙️ Tap to record your question", key="easy_voice_recording")
    if audio and st.button("Understand my voice and help me", use_container_width=True):
        try:
            from google.genai import types
            mime = getattr(audio, "type", None) or "audio/wav"
            prompt = "Listen to the attached audio, understand the spoken question, and answer it as ScamShield, a patient cyber-safety helper for elders and people who find typing difficult. " + language_instruction + " First briefly state what you understood, then give simple safe next steps. Use short sentences. Never claim certainty. Warn against sharing OTPs, passwords, UPI PINs or sending money under pressure. If speech is unclear, ask the user to record again."
            answer = gemini_text(prompt, [types.Part.from_bytes(data=audio.getvalue(), mime_type=mime)])
            st.session_state["easy_answer"] = ("ScamShield says", answer)
            st.session_state["easy_answer_language"] = language_code
            st.rerun()
        except Exception as exc:
            if "not configured on the server" in str(exc):
                st.error("AI voice help is not configured by the app administrator yet. One-tap safety guidance still works.")
            else:
                st.error("I couldn't understand the recording. Please try speaking slowly or use a one-tap option. " + str(exc)[:160])
    if "easy_answer" in st.session_state:
        title, explanation = st.session_state["easy_answer"]
        st.markdown("#### Simple answer")
        st.write("**" + title + "**")
        st.write(explanation)
        speech_player(title + ". " + explanation, st.session_state.get("easy_answer_language", language_code), "🔊 Speak answer aloud")
    st.markdown("#### 🚨 If money has already been sent")
    st.write("Contact your bank or payment app immediately using its official contact details. In India, report suspected cyber financial fraud promptly through the national helpline.")
    st.markdown("- **Cyber fraud helpline:** [Call 1930](tel:1930)\n- **Official reporting portal:** [cybercrime.gov.in](https://cybercrime.gov.in/)")
    st.info("For safety: ScamShield can make mistakes. If money is involved, pause and ask someone you trust to help verify it. Never share OTPs, passwords, or UPI PINs.")

if page == "Scan a message":
    st.markdown("### Check a message or link")
    st.markdown("Paste suspicious text from SMS, email, WhatsApp, Telegram, social media, shopping sites, job ads or other sources. ScamShield checks a broad set of known warning patterns; it cannot guarantee detection of every scam.")
    examples = {
        "Choose a demo example": "",
        "Paid internship offer": "Congratulations! You are selected for a guaranteed internship. Pay a refundable registration fee of Rs. 1999 today to confirm your seat. Limited slots!",
        "WhatsApp webinar upsell": "Join our free career webinar on WhatsApp tonight. At the end, pay the training and placement registration fee now for guaranteed job placement. Only today!",
        "Suspicious credential request": "Your bank account will be blocked today. Click this link to verify KYC and send your OTP and UPI PIN to avoid suspension.",
        "Fake delivery fee": "Your parcel is on hold. Pay a small customs release fee now using this link or the parcel will be returned within 10 minutes.",
        "Investment scam": "Join our private crypto group. Guaranteed 100% returns this week with no risk. Double your money by sending an advance payment today.",
        "Fake prize message": "Congratulations! You have won a prize. Pay a refundable processing fee now to release your reward. Limited time only!",
        "Account impersonation": "We are from your bank customer support. Your account will be blocked unless you share your OTP immediately.",
        "Ordinary opportunity message": "Hello, we are inviting applications for a software engineering internship. Please review the job description on our official careers page and apply through the listed process."
    }
    selected = st.selectbox("Try a sample (optional)", list(examples.keys()))
    default_text = examples[selected]
    message = st.text_area("Message / email / post / offer text", value=default_text, height=190,
                           placeholder="Paste the full message here, including payment instructions and links if present.")
    c1, c2 = st.columns([1, 1])
    with c1:
        scan = st.button("🔎 Analyze warning signs", type="primary", use_container_width=True)
    with c2:
        clear = st.button("Clear message", use_container_width=True)
    if clear:
        st.session_state["last_scan"] = None
        st.rerun()
    if scan:
        if not message.strip():
            st.warning("Paste a message or choose a demo example first.")
        else:
            st.session_state["last_scan"] = {
                "message": message,
                "time": datetime.now().strftime("%d %b %Y, %I:%M %p"),
                "result": scan_text(message)
            }
    last = st.session_state.get("last_scan")
    if last:
        score, level, color, headline, findings, url_notes = last["result"]
        st.divider()
        st.markdown("### Analysis result")
        m1, m2, m3 = st.columns([1, 1, 2])
        with m1:
            st.metric("Warning signal score", f"{score}/100")
        with m2:
            st.markdown(f"<div class='panel'><div style='color:{color};font-weight:900;font-size:1.2rem'>{level}</div><div class='smallmuted'>Rule-based assessment</div></div>", unsafe_allow_html=True)
        with m3:
            st.markdown(f"<div class='panel'><b>Recommended action</b><br><span style='color:#24324a'>{headline}</span></div>", unsafe_allow_html=True)
        st.progress(score / 100)
        st.caption("This score represents detected warning signals, not a verified probability that the message is a scam.")
        # Use a single-column result flow so long URLs and safety advice never
        # collide in narrow screens or at browser zoom levels.
        st.markdown("#### Why it was flagged")
        if findings:
            for item in findings:
                with st.expander(f"⚠️ {item['name']}  (+{item['points']} points)", expanded=True):
                    st.write(item["explanation"])
        else:
            st.success("No listed warning pattern was detected. Scams can still look professional or use new tactics.")

        st.markdown("#### Link checks")
        if url_notes:
            for url, note in url_notes:
                st.markdown(f"<div class='link-check'><code>{html.escape(url)}</code><p>{html.escape(note)}</p></div>", unsafe_allow_html=True)
        else:
            st.info("No web link was found in the submitted text.")

        st.markdown("#### What to do next")
        for task, _ in make_checklist(last["message"]):
            st.markdown(f"- [ ] {task}")
        st.markdown("<div class='panel reminder'><b>Remember</b><p>Never share an OTP, password, UPI PIN or pay under pressure.</p><p>Verify through official channels you find yourself.</p></div>", unsafe_allow_html=True)
        report = f"""SCAMSHIELD MESSAGE REVIEW
Reviewed: {last['time']}
Risk signal score: {score}/100
Level: {level}

Message:
{last['message']}

Warning signs:
""" + ("\n".join(f"- {x['name']}: {x['explanation']}" for x in findings) if findings else "- No listed warning patterns detected.") + "\n\nNext steps:\n" + "\n".join(f"- {task}" for task, _ in make_checklist(last["message"])) + "\n\nDisclaimer: This is an educational rule-based assessment, not proof of fraud or legitimacy."
        st.download_button("⬇️ Download review report (.txt)", report, file_name="scamshield_review.txt", mime="text/plain")
    st.write("")
    st.caption("Privacy note: this demo analyzes text in the running app and does not intentionally send it to a third-party AI API. Avoid pasting passwords, OTPs, or private personal information.")

elif page == "AI Security Assistant":
    st.markdown("### 🧠 ScamShield AI Security Assistant")
    st.write("Ask about a suspicious message, link, payment request, job offer, investment pitch, account alert, or online interaction. Replies follow the language selected in the sidebar.")
    st.info("Do not paste passwords, OTPs, full card numbers, or private identity details. Your question is sent to Gemini only when the app administrator has configured the server API key.")
    if "assistant_history" not in st.session_state:
        st.session_state["assistant_history"] = []
    for item in st.session_state["assistant_history"]:
        with st.chat_message(item["role"]):
            st.markdown(item["content"])
    question = st.chat_input("Ask ScamShield about a suspicious message or online safety…")
    if question:
        st.session_state["assistant_history"].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)
        try:
            history = st.session_state["assistant_history"][-10:]
            history_text = "\n".join(("User: " if x["role"] == "user" else "ScamShield: ") + x["content"] for x in history)
            prompt = "You are ScamShield, a careful cybersecurity assistant for everyday users. " + language_instruction + " Help assess scams, phishing, impersonation, payment fraud, shopping fraud, job scams, investment pitches, suspicious links, and account-security issues. Give concise, practical, non-alarmist advice. Explain warning signs, recommend verification through official channels, and state uncertainty. Never claim a message or URL is definitely safe from text alone. Tell users never to share OTPs, passwords, UPI PINs, CVVs, recovery codes, or grant remote access to strangers. For suspected fraud in India, suggest contacting the bank/payment provider promptly and reporting through official cybercrime channels. Do not ask for secrets or sensitive personal data.\n\nConversation:\n" + history_text + "\nScamShield response:"
            answer = gemini_text(prompt)
            st.session_state["assistant_mode"] = "Gemini AI connected"
        except Exception as exc:
            q = question.lower()
            if "not configured on the server" in str(exc):
                if any(x in q for x in ["otp", "password", "upi pin", "cvv", "bank", "kyc", "blocked"]):
                    answer = "Treat requests for OTPs, passwords, UPI PINs, CVVs, or urgent KYC updates as high risk. Do not click the message link. Contact your bank through its official app or number. If you shared details, contact the bank immediately."
                elif any(x in q for x in ["job", "internship", "recruit", "placement", "webinar", "course"]):
                    answer = "Verify the role on the organisation's official website, check the recruiter independently, and be cautious about upfront fees or guaranteed placement. A fee alone does not prove fraud."
                else:
                    answer = "Pause before paying, clicking, or sharing personal details. Check who sent the message, what they want, whether there is pressure, and verify using an official contact method you find yourself."
                st.session_state["assistant_mode"] = "Built-in safety guidance (Gemini key not configured)"
            else:
                answer = "Gemini could not respond right now. Please try again later. You can still use the message scanner and one-tap safety guidance."
                st.session_state["assistant_mode"] = "Temporary fallback"
        st.session_state["assistant_history"].append({"role": "assistant", "content": answer})
        with st.chat_message("assistant"):
            st.markdown(answer)
        speech_player(answer, language_code, "🔊 Listen to answer / సమాధానం వినండి / जवाब सुनें")
    st.caption("Assistant mode: " + st.session_state.get("assistant_mode", "Gemini will connect automatically when the server key is configured"))
    if st.button("Clear assistant conversation"):
        st.session_state["assistant_history"] = []
        st.rerun()

elif page == "How it works":
    st.markdown("### How ScamShield works")
    st.write("ScamShield uses transparent, explainable rules. It does not claim to verify a company or predict fraud with certainty.")
    steps = [
        ("01", "Input", "The user pastes SMS, email, social posts, shopping offers, job ads, payment requests, or other suspicious text."),
        ("02", "Signal detection", "The app checks patterns related to credentials, payment demands, urgency, prizes, investments, impersonation, jobs, and suspicious links."),
        ("03", "Risk score", "Each matched signal adds points. The score is capped at 100 and grouped into Lower Signal, Caution, or High Risk."),
        ("04", "Actionable guidance", "The app explains the detected signals and gives a checklist for independent verification.")
    ]
    for n, title, desc in steps:
        st.markdown(f"<div class='panel' style='margin-bottom:10px'><span style='color:#087e8b;font-weight:900'>{n}</span> &nbsp; <b>{title}</b><br><span class='smallmuted'>{desc}</span></div>", unsafe_allow_html=True)
    st.markdown("#### Current technical design")
    st.markdown("""- **Frontend:** Streamlit web interface
- **Detection:** Python pattern rules and a weighted warning-signal score across several scam categories
- **AI assistant:** Gemini-powered security Q&A when the server key is configured
- **Output:** risk band, matched warning signs, link notes, safety checklist, downloadable text report
- **Deployment:** Streamlit Community Cloud
- **External API:** Gemini API key must be configured by the app owner for live AI assistance""")
    st.warning("A production version should add a tested dataset, measured precision/recall, official-domain checks, safe URL reputation integrations, user feedback, and expert review.")

elif page == "Safety checklist":
    st.markdown("### Before you pay or accept")
    st.write("Use this checklist for job offers, internships, online courses, webinars, and placement programs.")
    items = [
        "I found the role/program on the organization's official website.",
        "I checked the sender's email domain and recruiter identity independently.",
        "I understand why any fee is being charged and verified it with the official organization.",
        "I checked written terms, refund policy, role details, and realistic placement claims.",
        "I did not share an OTP, password, UPI PIN, card CVV, or remote-access permission.",
        "I did not let a countdown, limited-seat claim, or pressure tactic rush my decision.",
        "I checked the URL carefully and did not install an unknown APK or app.",
        "I spoke to a trusted person or college placement cell if I am unsure."
    ]
    checked = []
    for item in items:
        if st.checkbox(item, key="check_" + str(items.index(item))):
            checked.append(item)
    st.progress(len(checked) / len(items))
    st.caption(f"{len(checked)} of {len(items)} checks completed.")
    if len(checked) == len(items):
        st.success("Good. Continue only if the opportunity and terms have been independently verified.")

elif page == "About the project":
    st.markdown("### A practical student-safety tool")
    st.markdown("""
**The problem:** Students looking for internships and first jobs may be targeted by offers that use familiar WhatsApp groups, free webinars, fake urgency, placement promises, or upfront fees.

**The solution:** ScamShield makes warning signs visible and gives users a concrete verification checklist before they pay, click, or share information.

**Who benefits:** College students, fresh graduates, campus placement cells, and career communities.

**What makes it useful:** It does not just return a label. It explains the warning signs and suggests safer next steps.
""")
    st.markdown("#### Business and impact model")
    st.markdown("- **Free student tool:** basic message scanning and safety checklist.\n- **College partnership:** awareness workshops and a campus safety portal.\n- **Placement-cell dashboard (future):** anonymized trend reporting and scam-awareness campaigns.\n- **Employer verification (future):** verified links and official contact details, only with reliable sources.")
    st.info("Do not present future features as already implemented. The current prototype is a rule-based educational screening tool, not an official fraud investigation service.")
    st.markdown("#### Limitations")
    st.markdown("- A suspicious phrase may appear in a legitimate message; false positives are possible.\n- Scammers can avoid known phrases; false negatives are possible.\n- A low score does not certify that an employer or URL is safe.\n- The app does not contact employers, verify legal registration, or query a live threat-intelligence database.")

st.divider()
st.markdown("<div style='text-align:center;color:#8da2ba;font-size:.82rem'>SCAMSHIELD • VERIFY BEFORE YOU TRUST<br>Educational prototype — use independent verification for important decisions.</div>", unsafe_allow_html=True)
