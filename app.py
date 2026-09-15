import streamlit as st
import requests
import re
from urllib.parse import urlparse

from hybrid_detector import predict_url


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberShield | Phishing URL Detection",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CSS
# ============================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

* {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(0,230,160,0.06), transparent 30%),
        radial-gradient(circle at 90% 20%, rgba(0,140,255,0.06), transparent 30%),
        #05080d;
    color: #e8eef5;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1200px;
}


/* HERO */

.hero {
    text-align: center;
    padding: 25px 20px 20px;
}

.logo {
    font-size: 55px;
}

.hero-title {
    font-size: 46px;
    font-weight: 800;
    letter-spacing: -2px;
    color: white;
}

.hero-title span {
    color: #00e6a0;
}

.hero-subtitle {
    margin-top: 8px;
    color: #8d9aaa;
    font-size: 17px;
}

.badge {
    display: inline-block;
    margin-top: 18px;
    padding: 8px 16px;
    border-radius: 30px;
    border: 1px solid rgba(0,230,160,0.3);
    background: rgba(0,230,160,0.06);
    color: #00e6a0;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
}


/* SCANNER */

.scanner-card {
    margin-top: 25px;
    padding: 30px;
    border-radius: 18px;
    border: 1px solid #1c2935;
    background: linear-gradient(
        145deg,
        rgba(14,22,31,0.95),
        rgba(7,13,20,0.95)
    );
    box-shadow: 0 15px 50px rgba(0,0,0,0.35);
}

.scanner-title {
    font-size: 21px;
    font-weight: 700;
    color: white;
}

.scanner-description {
    color: #7f8d9d;
    font-size: 14px;
    margin-top: 5px;
}


/* INPUT */

.stTextInput label {
    color: #aab6c3 !important;
    font-weight: 600 !important;
}

.stTextInput input {
    background: #080e15 !important;
    border: 1px solid #263543 !important;
    color: white !important;
    border-radius: 10px !important;
    padding: 14px !important;
}

.stTextInput input:focus {
    border-color: #00e6a0 !important;
    box-shadow: 0 0 0 1px #00e6a0 !important;
}


/* BUTTON */

.stButton button {
    width: 100%;
    height: 48px;
    border: none;
    border-radius: 10px;
    background: linear-gradient(90deg,#00c98b,#00e6a0);
    color: #03110c;
    font-weight: 800;
    font-size: 15px;
}

.stButton button:hover {
    transform: translateY(-1px);
    box-shadow: 0 8px 25px rgba(0,230,160,0.18);
}


/* RESULT */

.result-card {
    margin-top: 25px;
    padding: 28px;
    border-radius: 18px;
    background: #0b1118;
}

.result-safe {
    border: 1px solid rgba(0,230,160,0.35);
}

.result-danger {
    border: 1px solid rgba(255,75,75,0.35);
}

.result-icon {
    font-size: 45px;
}

.result-title {
    font-size: 30px;
    font-weight: 800;
}

.safe-text {
    color: #00e6a0;
}

.danger-text {
    color: #ff5757;
}

.result-url {
    margin-top: 8px;
    color: #8b9aaa;
    word-break: break-all;
    font-size: 14px;
}


/* METRICS */

.metric-box {
    padding: 18px;
    border-radius: 12px;
    background: #080e15;
    border: 1px solid #1c2935;
    text-align: center;
}

.metric-value {
    font-size: 27px;
    font-weight: 800;
    color: white;
}

.metric-label {
    margin-top: 4px;
    font-size: 12px;
    color: #7f8d9d;
    text-transform: uppercase;
    letter-spacing: 0.7px;
}


/* SECTIONS */

.section-title {
    margin-top: 30px;
    margin-bottom: 15px;
    color: white;
    font-size: 19px;
    font-weight: 700;
}


/* REASONS */

.reason-box {
    margin-bottom: 10px;
    padding: 14px 16px;
    border-radius: 10px;
    background: #080e15;
    border-left: 3px solid #00e6a0;
    color: #c7d0da;
    font-size: 14px;
    line-height: 1.5;
}

.reason-danger {
    border-left-color: #ff5757;
}


/* TECHNICAL */

.tech-box {
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 10px;
    background: #080e15;
    border: 1px solid #17232e;
}

.tech-label {
    color: #6f7e8e;
    font-size: 12px;
    text-transform: uppercase;
}

.tech-value {
    color: #e7edf3;
    font-size: 15px;
    font-weight: 600;
    margin-top: 4px;
}


/* NOTICE */

.notice {
    margin-top: 25px;
    padding: 16px 18px;
    border-radius: 10px;
    background: rgba(0,140,255,0.05);
    border: 1px solid rgba(0,140,255,0.15);
    color: #8fa0b1;
    font-size: 13px;
    line-height: 1.6;
}


/* FOOTER */

.footer {
    text-align: center;
    margin-top: 45px;
    padding-top: 20px;
    border-top: 1px solid #17232e;
    color: #536171;
    font-size: 12px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# HERO
# ============================================================

st.markdown("""
<div class="hero">

<div class="logo">🛡️</div>

<div class="hero-title">
Cyber<span>Shield</span>
</div>

<div class="hero-subtitle">
Intelligent Phishing URL Detection & Risk Analysis
</div>

<div class="badge">
AI SECURITY ENGINE &nbsp;|&nbsp; MACHINE LEARNING + HEURISTICS
</div>

</div>
""", unsafe_allow_html=True)


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "google.co.in",
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazon.in",
    "wikipedia.org",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "netflix.com",
    "github.com",
    "youtube.com",
    "gmail.com",
    "yahoo.com",
    "adobe.com",
    "dropbox.com",
    "zoom.us",
    "spotify.com",
    "kkmu.edu.in"
}


# ============================================================
# SUSPICIOUS WORDS
# ============================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "confirm",
    "bank",
    "paypal",
    "payment",
    "wallet",
    "bonus",
    "free",
    "alert",
    "suspend",
    "unlock",
    "authenticate",
    "authentication",
    "credential"
]


# ============================================================
# URL INFORMATION
# ============================================================

def get_url_information(url):

    clean_url = str(url).strip()

    if clean_url.lower().startswith("https://"):

        protocol = "HTTPS"
        parse_url = clean_url

    elif clean_url.lower().startswith("http://"):

        protocol = "HTTP"
        parse_url = clean_url

    else:

        # IMPORTANT:
        # Do not assume HTTP when user enters only a domain.
        protocol = "Not specified"
        parse_url = "https://" + clean_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""

    return {
        "protocol": protocol,
        "domain": hostname,
        "path": parsed.path,
        "query": parsed.query,
        "url_length": len(clean_url),
        "parse_url": parse_url
    }


# ============================================================
# HTTPS AVAILABILITY
# ============================================================

def check_https_availability(domain):

    if not domain:
        return "Unable to verify"

    try:

        response = requests.get(
            f"https://{domain}",
            timeout=5,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if response.ok:
            return "Available"

        return "Reachable"

    except requests.RequestException:

        return "Unable to verify"


# ============================================================
# BASIC FEATURES
# ============================================================

def get_basic_features(url):

    clean_url = str(url).strip()

    if clean_url.lower().startswith(
        ("http://", "https://")
    ):
        parse_url = clean_url
    else:
        parse_url = "https://" + clean_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""

    # IP detection

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    is_ip = bool(
        re.match(
            ip_pattern,
            hostname
        )
    )

    # Suspicious words

    url_lower = clean_url.lower()

    found_words = [
        word
        for word in SUSPICIOUS_WORDS
        if word in url_lower
    ]

    # Subdomains

    parts = hostname.split(".")

    if len(parts) >= 3:
        subdomains = len(parts) - 2
    else:
        subdomains = 0

    return {
        "domain": hostname,
        "is_ip": is_ip,
        "suspicious_words": found_words,
        "subdomains": subdomains,
        "has_at": "@" in clean_url,
        "has_double_slash": "//" in clean_url[8:],
        "url_length": len(clean_url)
    }


# ============================================================
# TRUSTED DOMAIN CHECK
# ============================================================

def is_trusted_domain(domain):

    domain = domain.lower().strip()

    if domain.startswith("www."):
        domain = domain[4:]

    if domain in TRUSTED_DOMAINS:
        return True

    for trusted in TRUSTED_DOMAINS:

        if domain.endswith("." + trusted):
            return True

    return False


# ============================================================
# REASONS
# ============================================================

def generate_reasons(url, result):

    features = get_basic_features(url)

    domain = features["domain"]

    reasons = []

    phishing = (
        result["prediction"] == 1
    )

    # ========================================================
    # PHISHING
    # ========================================================

    if phishing:

        if features["is_ip"]:

            reasons.append(
                "The URL uses an IP address instead of a normal "
                "domain name, which is commonly associated with "
                "phishing infrastructure."
            )

        if features["has_at"]:

            reasons.append(
                "The URL contains an '@' symbol, which can be "
                "used to disguise the actual destination."
            )

        if features["has_double_slash"]:

            reasons.append(
                "The URL contains a suspicious double-slash "
                "pattern inside the address."
            )

        if features["suspicious_words"]:

            words = ", ".join(
                features["suspicious_words"][:4]
            )

            reasons.append(
                f"The URL contains phishing-related keywords "
                f"such as {words}."
            )

        if features["url_length"] > 150:

            reasons.append(
                "The URL is unusually long and may contain "
                "hidden parameters or deceptive information."
            )

        if features["subdomains"] >= 3:

            reasons.append(
                "The URL contains multiple subdomains, which "
                "can be used to create deceptive domain names."
            )

        if not reasons:

            reasons.append(
                "The machine-learning model identified URL "
                "characteristics associated with phishing."
            )

        if len(reasons) < 2:

            reasons.append(
                "The combined heuristic and machine-learning "
                "analysis indicates elevated phishing risk."
            )

    # ========================================================
    # LEGITIMATE
    # ========================================================

    else:

        if is_trusted_domain(domain):

            reasons.append(
                "The domain matches a recognized trusted-domain "
                "pattern."
            )

        if not features["is_ip"]:

            reasons.append(
                "The URL uses a conventional domain name rather "
                "than a raw IP address."
            )

        if not features["has_at"]:

            reasons.append(
                "The URL does not contain an '@' symbol, avoiding "
                "a common URL deception technique."
            )

        if not features["suspicious_words"]:

            reasons.append(
                "No common phishing-related keywords were detected "
                "in the URL."
            )

        if features["subdomains"] <= 2:

            reasons.append(
                "The domain does not contain an unusually large "
                "number of subdomains."
            )

        if not reasons:

            reasons.append(
                "The combined machine-learning and heuristic "
                "analysis did not identify significant phishing "
                "indicators."
            )

    # Remove duplicate reasons

    unique_reasons = []

    for reason in reasons:

        if reason not in unique_reasons:
            unique_reasons.append(reason)

    return unique_reasons[:4]


# ============================================================
# SCANNER
# ============================================================

st.markdown("""
<div class="scanner-card">

<div class="scanner-title">
🔎 URL Security Scanner
</div>

<div class="scanner-description">
Enter a website URL to analyze its structure, security indicators,
machine-learning prediction and phishing risk.
</div>

</div>
""", unsafe_allow_html=True)


# ============================================================
# INPUT
# ============================================================

url = st.text_input(
    "Website URL",
    placeholder="Example: https://example.com or example.com"
)


# ============================================================
# BUTTON
# ============================================================

analyze = st.button(
    "🔍 Analyze URL"
)


# ============================================================
# MAIN ANALYSIS
# ============================================================

if analyze:

    if not url.strip():

        st.warning(
            "Please enter a URL before starting the analysis."
        )

    else:

        with st.spinner(
            "Analyzing URL security..."
        ):

            try:

                # ----------------------------------------------
                # ML + HEURISTIC DETECTOR
                # ----------------------------------------------

                result = predict_url(
                    url.strip()
                )

                # ----------------------------------------------
                # URL INFORMATION
                # ----------------------------------------------

                url_info = get_url_information(
                    url.strip()
                )

                features = get_basic_features(
                    url.strip()
                )

                # ----------------------------------------------
                # HTTPS CHECK
                # ----------------------------------------------

                https_status = check_https_availability(
                    url_info["domain"]
                )

                # ----------------------------------------------
                # REASONS
                # ----------------------------------------------

                reasons = generate_reasons(
                    url,
                    result
                )

                # ----------------------------------------------
                # RESULTS
                # ----------------------------------------------

                legitimate_probability = float(
                    result.get(
                        "legitimate_probability",
                        0
                    )
                )

                phishing_probability = float(
                    result.get(
                        "phishing_probability",
                        0
                    )
                )

                risk_score = result.get(
                    "risk_score",
                    0
                )

                phishing = (
                    result["prediction"] == 1
                )

                # ==================================================
                # RESULT CARD
                # ==================================================

                if phishing:

                    st.markdown(
                        f"""
<div class="result-card result-danger">

<div class="result-icon">
🚨
</div>

<div class="result-title danger-text">
PHISHING URL
</div>

<div class="result-url">
{url.strip()}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                else:

                    st.markdown(
                        f"""
<div class="result-card result-safe">

<div class="result-icon">
🛡️
</div>

<div class="result-title safe-text">
LEGITIMATE URL
</div>

<div class="result-url">
{url.strip()}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                # ==================================================
                # DETECTION ANALYSIS
                # ==================================================

                st.markdown(
                    '<div class="section-title">📊 Detection Analysis</div>',
                    unsafe_allow_html=True
                )

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.markdown(
                        f"""
<div class="metric-box">

<div class="metric-value">
{legitimate_probability * 100:.2f}%
</div>

<div class="metric-label">
Legitimate Probability
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col2:

                    st.markdown(
                        f"""
<div class="metric-box">

<div class="metric-value">
{phishing_probability * 100:.2f}%
</div>

<div class="metric-label">
Phishing Probability
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col3:

                    st.markdown(
                        f"""
<div class="metric-box">

<div class="metric-value">
{risk_score}
</div>

<div class="metric-label">
Risk Score
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                # ==================================================
                # RISK BAR
                # ==================================================

                st.markdown(
                    '<div class="section-title">⚠️ Risk Assessment</div>',
                    unsafe_allow_html=True
                )

                st.progress(
                    min(
                        max(
                            phishing_probability,
                            0.0
                        ),
                        1.0
                    )
                )

                if phishing_probability >= 0.70:

                    st.error(
                        "High Risk: The URL contains significant "
                        "indicators associated with phishing activity."
                    )

                elif phishing_probability >= 0.40:

                    st.warning(
                        "Moderate Risk: Verify the website carefully "
                        "before entering sensitive information."
                    )

                else:

                    st.success(
                        "Low Risk: No significant phishing indicators "
                        "were identified."
                    )

                # ==================================================
                # SECURITY FINDINGS
                # ==================================================

                st.markdown(
                    '<div class="section-title">🔬 Security Findings</div>',
                    unsafe_allow_html=True
                )

                for reason in reasons:

                    css = (
                        "reason-box reason-danger"
                        if phishing
                        else "reason-box"
                    )

                    icon = "⚠️" if phishing else "✓"

                    st.markdown(
                        f"""
<div class="{css}">

<strong>{icon}</strong>
&nbsp;&nbsp;
{reason}

</div>
""",
                        unsafe_allow_html=True
                    )

                # ==================================================
                # TECHNICAL DETAILS
                # ==================================================

                st.markdown(
                    '<div class="section-title">🧪 Technical URL Details</div>',
                    unsafe_allow_html=True
                )

                # ----------------------------------------------
                # ROW 1
                # ----------------------------------------------

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
Protocol
</div>

<div class="tech-value">
{url_info["protocol"]}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col2:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
Domain
</div>

<div class="tech-value">
{url_info["domain"]}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col3:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
URL Length
</div>

<div class="tech-value">
{url_info["url_length"]} characters
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                # ----------------------------------------------
                # ROW 2
                # ----------------------------------------------

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
Subdomains
</div>

<div class="tech-value">
{features["subdomains"]}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col2:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
HTTPS in Input
</div>

<div class="tech-value">
{
    "Yes"
    if url_info["protocol"] == "HTTPS"
    else
    "No"
    if url_info["protocol"] == "HTTP"
    else
    "Not specified"
}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col3:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
HTTPS Availability
</div>

<div class="tech-value">
{https_status}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                # ----------------------------------------------
                # ROW 3
                # ----------------------------------------------

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
IP-based Domain
</div>

<div class="tech-value">
{"Yes" if features["is_ip"] else "No"}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col2:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
Suspicious Keywords
</div>

<div class="tech-value">
{len(features["suspicious_words"])}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                with col3:

                    st.markdown(
                        f"""
<div class="tech-box">

<div class="tech-label">
Trusted Domain
</div>

<div class="tech-value">
{"Yes" if is_trusted_domain(features["domain"]) else "No"}
</div>

</div>
""",
                        unsafe_allow_html=True
                    )

                # ==================================================
                # NOTICE
                # ==================================================

                st.markdown(
                    """
<div class="notice">

<strong>🔐 Security Notice</strong>
<br><br>

CyberShield combines machine-learning analysis with URL-based
heuristics to estimate phishing risk. A "Legitimate" result
does not guarantee that a website is completely safe.

Always verify websites through trusted sources before entering
passwords, banking information or other sensitive credentials.

HTTPS availability is shown as an informational security
property and is not used by itself to determine whether a
website is legitimate or phishing.

</div>
""",
                    unsafe_allow_html=True
                )

            except Exception as e:

                st.error(
                    f"Error while analyzing URL: {e}"
                )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
<div class="footer">

🛡️ CyberShield
&nbsp;•&nbsp;
Phishing URL Detection
&nbsp;•&nbsp;
Machine Learning + Heuristic Analysis

<br><br>

B.Tech Cybersecurity Project

</div>
""",
    unsafe_allow_html=True
)