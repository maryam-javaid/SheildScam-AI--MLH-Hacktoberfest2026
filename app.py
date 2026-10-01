"""
app.py - ScamShield AI: "Think Before You Click."

Streamlit dashboard that combines:
  1. deterministic rule-based signals   (detector.py)
  2. URL structure intelligence         (url_analyzer.py)
  3. local open-weight AI reasoning     (ai_engine.py)

Run with:  streamlit run app.py
"""

import html

import streamlit as st

from ai_engine import MODEL_NAME, analyze_with_ai, check_ollama
from detector import analyze_message, apply_url_signals
from url_analyzer import analyze_urls

st.set_page_config(
    page_title="ScamShield AI - Think Before You Click",
    page_icon="\U0001F6E1",
    layout="wide",
)

# --------------------------------------------------------------------------
# Demo messages
# --------------------------------------------------------------------------
SAMPLES = {
    "Fake Bank": (
        "URGENT!\n\n"
        "Your bank account will be disabled tonight.\n\n"
        "Verify your identity immediately:\n\n"
        "http://192.168.1.50/secure-bank-verification/login\n\n"
        "Enter your CNIC, password and OTP to restore your account.\n\n"
        "Failure to verify immediately may result in permanent account suspension."
    ),
    "Prize Scam": (
        "CONGRATULATIONS! You have won a cash prize of Rs. 5,000,000 in the Mega Mobile Lottery.\n\n"
        "To claim your reward, pay a Rs. 15,000 processing fee within 24 hours:\n"
        "http://bit.ly/claim-mega-prize\n\n"
        "Do not tell anyone about this offer."
    ),
    "Delivery Scam": (
        "Your parcel could not be delivered because the address is incomplete.\n\n"
        "Update your address and pay a small redelivery fee of Rs. 120 within 24 hours "
        "or the package will be returned:\n"
        "http://tcs-redelivery-update.top/confirm"
    ),
    "Job Scam": (
        "Work from home! Earn Rs. 5,000 per day with no experience required. "
        "Guaranteed income.\n\n"
        "Pay a one-time registration fee of Rs. 2,000 today to secure your position:\n"
        "http://easy-earn-jobs.xyz/register"
    ),
    "Subtle Phish (AI)": (
        "Dear valued member, your banking access will cease at midnight unless "
        "validation is completed. Our compliance office needs you to re-authenticate "
        "your profile through the portal we have shared."
    ),
}

RISK_COLORS = {
    "HIGH RISK": "#ff4d6d",
    "SUSPICIOUS": "#ff9f43",
    "CAUTION": "#ffd43b",
    "NO OBVIOUS WARNING SIGNALS": "#2ee59d",
}

SEVERITY_CLASS = {
    "Critical": "sev-critical",
    "High": "sev-high",
    "Medium": "sev-medium",
    "Low": "sev-low",
}

# --------------------------------------------------------------------------
# Styling
# --------------------------------------------------------------------------
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
.stApp{background:radial-gradient(1100px 600px at 8% -10%,rgba(0,229,255,.13),transparent 60%),radial-gradient(900px 500px at 100% 0%,rgba(0,255,163,.09),transparent 55%),linear-gradient(180deg,#050b18 0%,#070d1c 100%);color:#e6edf7;font-family:'Inter','Segoe UI',system-ui,sans-serif;}
#MainMenu,footer{visibility:hidden;}
header[data-testid="stHeader"]{background:transparent;}
.block-container{max-width:1150px;padding-top:2rem;padding-bottom:4rem;}
.stApp p,.stApp li,.stApp label,.stApp span{color:inherit;}
.ss-hero{padding:1.2rem 0 .4rem 0;}
.ss-eyebrow{font-size:.72rem;letter-spacing:.22em;color:#00e5ff;font-weight:700;margin-bottom:.5rem;}
.ss-title{font-size:3.2rem;font-weight:800;margin:0;line-height:1.05;color:#fff;letter-spacing:-.02em;}
.ss-title span{background:linear-gradient(90deg,#00e5ff,#2ee59d);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.ss-tag{font-size:1.35rem;font-weight:600;color:#9fb3cf;margin:.35rem 0 .9rem 0;}
.ss-desc{max-width:780px;color:#aebbd0;font-size:1.02rem;line-height:1.65;}
.ss-badges{display:flex;flex-wrap:wrap;gap:.55rem;margin-top:1rem;}
.ss-badge{display:inline-flex;align-items:center;gap:.5rem;padding:.38rem .8rem;border-radius:999px;font-size:.72rem;font-weight:700;letter-spacing:.12em;color:#9fe9ff;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.28);}
.ss-badge.online{color:#2ee59d;background:rgba(46,229,157,.09);border-color:rgba(46,229,157,.35);}
.ss-badge.offline{color:#ff9f43;background:rgba(255,159,67,.09);border-color:rgba(255,159,67,.4);}
.ss-dot{width:8px;height:8px;border-radius:50%;background:#2ee59d;display:inline-block;animation:ssPulse 2s infinite;}
.offline .ss-dot{background:#ff9f43;animation:none;}
@keyframes ssPulse{0%{box-shadow:0 0 0 0 rgba(46,229,157,.6);}70%{box-shadow:0 0 0 9px rgba(46,229,157,0);}100%{box-shadow:0 0 0 0 rgba(46,229,157,0);}}
.ss-section{font-size:.78rem;letter-spacing:.2em;font-weight:700;color:#00e5ff;margin:2.2rem 0 .8rem 0;}
.ss-card{background:linear-gradient(145deg,rgba(255,255,255,.065),rgba(255,255,255,.025));border:1px solid rgba(255,255,255,.09);border-radius:18px;padding:1.15rem 1.25rem;backdrop-filter:blur(10px);box-shadow:0 10px 40px rgba(0,0,0,.35);}
.ss-grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;}
.ss-grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;}
@media(max-width:900px){.ss-grid4{grid-template-columns:repeat(2,1fr);}.ss-grid3{grid-template-columns:1fr;}.ss-title{font-size:2.4rem;}}
.ss-label{font-size:.7rem;letter-spacing:.18em;color:#8ea3c2;font-weight:700;}
.ss-value{font-size:2.1rem;font-weight:800;margin-top:.35rem;line-height:1.15;}
.ss-value.small{font-size:1.15rem;padding:.55rem 0;}
.ss-sub{font-size:.76rem;color:#8ea3c2;margin-top:.3rem;}
.ss-badge-sev{display:inline-block;font-size:.66rem;font-weight:800;letter-spacing:.12em;padding:.2rem .55rem;border-radius:6px;margin-right:.5rem;}
.sev-critical{background:rgba(255,77,109,.18);color:#ff7a93;}
.sev-high{background:rgba(255,159,67,.18);color:#ffb26b;}
.sev-medium{background:rgba(255,212,59,.15);color:#ffd43b;}
.sev-low{background:rgba(0,229,255,.12);color:#7fe9ff;}
.ss-url-head{font-family:'Consolas','Courier New',monospace;font-size:.92rem;color:#7fe9ff;word-break:break-all;}
.ss-url-meta{font-size:.82rem;color:#8ea3c2;margin:.3rem 0 .8rem 0;}
.ss-finding{margin:.55rem 0;font-size:.9rem;color:#c7d3e6;line-height:1.55;}
.ss-ai-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.6rem;}
.ss-ai-title{font-size:1.5rem;font-weight:800;color:#fff;}
.ss-ai-sub{font-size:.72rem;letter-spacing:.18em;font-weight:700;color:#2ee59d;margin-top:.2rem;}
.ss-ai-note{color:#9fb3cf;font-size:.93rem;line-height:1.6;margin-top:.8rem;}
.ss-block-title{font-size:.72rem;letter-spacing:.18em;font-weight:700;color:#00e5ff;margin-bottom:.55rem;}
.ss-block p{margin:0;color:#dbe5f4;line-height:1.7;font-size:.98rem;}
.ss-block ul{margin:0;padding-left:1.1rem;color:#dbe5f4;line-height:1.7;font-size:.96rem;}
.ss-simple{border-color:rgba(46,229,157,.35);background:linear-gradient(145deg,rgba(46,229,157,.10),rgba(255,255,255,.02));}
.ss-urdu p{direction:rtl;text-align:right;font-family:'Noto Nastaliq Urdu','Jameel Noori Nastaleeq','Segoe UI',Tahoma,sans-serif;font-size:1.2rem;line-height:2.2;}
.ss-privacy{border-color:rgba(0,229,255,.3);background:linear-gradient(145deg,rgba(0,229,255,.09),rgba(255,255,255,.02));}
.ss-action-title{font-weight:800;letter-spacing:.1em;font-size:.9rem;color:#fff;margin-bottom:.4rem;}
.ss-action-text{color:#aebbd0;font-size:.92rem;line-height:1.55;}
.ss-disclaimer{font-size:.82rem;color:#8ea3c2;text-align:center;margin-top:2rem;line-height:1.6;}
.stTextArea textarea{background:rgba(255,255,255,.04)!important;border:1px solid rgba(0,229,255,.28)!important;color:#e6edf7!important;border-radius:14px!important;font-size:1rem!important;line-height:1.55!important;}
.stTextArea textarea:focus{border-color:#00e5ff!important;box-shadow:0 0 0 2px rgba(0,229,255,.18)!important;}
.stButton>button{width:100%;border-radius:12px;font-weight:600;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#dbe5f4;padding:.55rem .6rem;transition:all .15s ease;}
.stButton>button:hover{border-color:#00e5ff;color:#00e5ff;background:rgba(0,229,255,.07);}
.stButton>button[kind="primary"],.stButton>button[data-testid="stBaseButton-primary"]{background:linear-gradient(90deg,#00e5ff,#2ee59d);color:#04121f;border:none;font-weight:800;letter-spacing:.12em;padding:.8rem 1rem;box-shadow:0 0 28px rgba(0,229,255,.28);}
.stButton>button[kind="primary"]:hover,.stButton>button[data-testid="stBaseButton-primary"]:hover{color:#04121f;box-shadow:0 0 40px rgba(46,229,157,.45);}
[data-testid="stExpander"]{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.09);border-radius:14px;}
[data-testid="stExpander"] summary{font-weight:600;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def esc(value) -> str:
    """Escape text before inserting it into HTML (messages/AI output are untrusted)."""
    return html.escape(str(value), quote=True)


def render_html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def section(title: str) -> None:
    render_html(f'<div class="ss-section">{esc(title)}</div>')


def sev_badge(severity: str) -> str:
    css = SEVERITY_CLASS.get(severity, "sev-low")
    return f'<span class="ss-badge-sev {css}">{esc(severity.upper())}</span>'


def metric_card(label: str, value: str, sub: str = "", color: str = "#00e5ff") -> str:
    size = " small" if len(value) > 12 else ""
    return (
        '<div class="ss-card">'
        f'<div class="ss-label">{esc(label)}</div>'
        f'<div class="ss-value{size}" style="color:{color}">{esc(value)}</div>'
        f'<div class="ss-sub">{esc(sub)}</div>'
        "</div>"
    )


def block_card(title: str, content, extra_class: str = "") -> str:
    if isinstance(content, list):
        body = "<ul>" + "".join(f"<li>{esc(item)}</li>" for item in content) + "</ul>"
    else:
        body = f"<p>{esc(content)}</p>"
    return (
        f'<div class="ss-card ss-block {extra_class}">'
        f'<div class="ss-block-title">{esc(title)}</div>{body}</div>'
    )


@st.cache_data(ttl=10, show_spinner=False)
def get_engine_status() -> dict:
    return check_ollama()


def load_sample(name: str) -> None:
    st.session_state["message_input"] = SAMPLES[name]
    st.session_state.pop("result", None)


# --------------------------------------------------------------------------
# Session state
# --------------------------------------------------------------------------
if "message_input" not in st.session_state:
    st.session_state["message_input"] = ""

# --------------------------------------------------------------------------
# Hero
# --------------------------------------------------------------------------
status = get_engine_status()
if status["online"] and status["model_ready"]:
    engine_badge = '<span class="ss-badge online"><i class="ss-dot"></i>AI ENGINE ONLINE</span>'
elif status["online"]:
    engine_badge = '<span class="ss-badge offline"><i class="ss-dot"></i>MODEL NOT INSTALLED</span>'
else:
    engine_badge = '<span class="ss-badge offline"><i class="ss-dot"></i>AI ENGINE OFFLINE</span>'

render_html(
    '<div class="ss-hero">'
    '<div class="ss-eyebrow">OPEN-SOURCE &bull; HUMAN-CENTERED CYBERSECURITY</div>'
    '<h1 class="ss-title">ScamShield <span>AI</span></h1>'
    '<div class="ss-tag">Think Before You Click.</div>'
    '<p class="ss-desc">Understand suspicious messages before you trust them. ScamShield combines '
    "deterministic security signals, URL intelligence and local AI reasoning to explain phishing "
    "and social-engineering tactics in language anyone can understand.</p>"
    f'<div class="ss-badges">{engine_badge}'
    '<span class="ss-badge">LOCAL AI</span>'
    '<span class="ss-badge">QWEN3 1.7B</span>'
    '<span class="ss-badge">EXPLAINABLE ANALYSIS</span></div></div>'
)

if not (status["online"] and status["model_ready"]):
    st.info(
        status["message"]
        + "  The rule-based and URL analysis still work without the AI engine."
    )

# --------------------------------------------------------------------------
# Quick demo attacks
# --------------------------------------------------------------------------
section("QUICK DEMO ATTACKS")
sample_cols = st.columns(len(SAMPLES))
for col, name in zip(sample_cols, SAMPLES):
    with col:
        st.button(name, key=f"sample_{name}", on_click=load_sample, args=(name,))

# --------------------------------------------------------------------------
# Message analyzer
# --------------------------------------------------------------------------
section("MESSAGE ANALYZER")
st.text_area(
    "Suspicious message",
    key="message_input",
    height=230,
    placeholder="Paste a suspicious SMS, email, WhatsApp message or any other text here...",
    label_visibility="collapsed",
)
analyze_clicked = st.button("ANALYZE THREAT", type="primary", key="analyze_btn")


def run_analysis(message: str) -> None:
    rule_result = analyze_message(message)
    url_results = analyze_urls(message)
    rule_result = apply_url_signals(rule_result, url_results)
    ai_result = analyze_with_ai(message, rule_result, url_results)
    st.session_state["result"] = {
        "rule": rule_result,
        "urls": url_results,
        "ai": ai_result,
    }


if analyze_clicked:
    current_message = st.session_state.get("message_input", "").strip()
    if not current_message:
        st.warning("Please paste a message to analyze, or click one of the demo attacks above.")
    else:
        try:
            with st.spinner("AI Security Analyst is examining manipulation tactics..."):
                run_analysis(current_message)
            get_engine_status.clear()
        except Exception as exc:  # never crash the dashboard
            st.error(f"Something went wrong while analyzing the message ({type(exc).__name__}). Please try again.")


# --------------------------------------------------------------------------
# Result dashboard
# --------------------------------------------------------------------------
def render_results(result: dict) -> None:
    rule = result["rule"]
    urls = result["urls"]
    ai = result["ai"]

    risk_color = RISK_COLORS.get(rule["risk"], "#00e5ff")
    ai_active = bool(ai.get("ok"))

    section("RESULT DASHBOARD")
    render_html(
        '<div class="ss-grid4">'
        + metric_card("RISK INDICATORS", f"{rule['score']}/100", "Rule-based signals, not a fraud probability", risk_color)
        + metric_card("THREAT LEVEL", rule["risk"], "Based on observable indicators", risk_color)
        + metric_card("LINKS FOUND", str(len(urls)), "Never opened by ScamShield", "#7fe9ff")
        + metric_card(
            "AI ENGINE",
            "ACTIVE" if ai_active else "UNAVAILABLE",
            "Local Qwen3 1.7B via Ollama" if ai_active else "See message below",
            "#2ee59d" if ai_active else "#ff9f43",
        )
        + "</div>"
    )

    # ---- Threat intelligence ----
    section("THREAT INTELLIGENCE")
    if rule["findings"]:
        for finding in rule["findings"]:
            with st.expander(f"{finding['severity'].upper()}  |  {finding['type']}", expanded=True):
                render_html(f'<div class="ss-finding">{sev_badge(finding["severity"])}{esc(finding["explanation"])}</div>')
                if finding.get("evidence"):
                    st.caption("Matched text: " + " / ".join(f'"{e}"' for e in finding["evidence"]))
    else:
        st.success("No rule-based warning indicators were found in the text. This does not prove the message is safe.")

    # ---- URL intelligence ----
    section("URL INTELLIGENCE")
    if urls:
        for item in urls:
            rows = "".join(
                f'<div class="ss-finding">{sev_badge(f["severity"])}<b>{esc(f["type"])}</b><br>{esc(f["explanation"])}</div>'
                for f in item["findings"]
            )
            if not rows:
                rows = (
                    '<div class="ss-finding">No warning signals were found in the link structure itself. '
                    "This does not prove the link is safe.</div>"
                )
            render_html(
                '<div class="ss-card" style="margin-bottom:.9rem">'
                '<div class="ss-label">DETECTED URL</div>'
                f'<div class="ss-url-head">{esc(item["url"])}</div>'
                f'<div class="ss-url-meta">Domain: <b>{esc(item["domain"])}</b> &nbsp;|&nbsp; '
                f'URL warning signals: {item["score"]}/100 &nbsp;|&nbsp; Link was not opened</div>'
                f"{rows}</div>"
            )
    else:
        st.info("No links were found in this message.")

    # ---- AI security analyst ----
    section("AI SECURITY ANALYST")
    render_html(
        '<div class="ss-card" style="margin-bottom:1rem">'
        '<div class="ss-ai-head"><div>'
        '<div class="ss-ai-title">AI Security Analyst</div>'
        '<div class="ss-ai-sub">QWEN3 1.7B &bull; OPEN-WEIGHT &bull; LOCAL INFERENCE</div></div></div>'
        '<div class="ss-ai-note">Keyword rules only catch exact phrases. The AI reads the meaning of the message, '
        "so it can notice pressure, fear, impersonation and manipulation even when the wording is different.</div></div>"
    )

    if not ai.get("ok"):
        st.warning(ai.get("error") or "The AI analysis is unavailable right now.")
        st.caption("The rule-based and URL results above are still valid and were produced without AI.")
    else:
        data = ai["data"]
        if not ai.get("parsed"):
            st.caption("The AI answered in an unexpected format, so its raw explanation is shown below.")
        if data["semantic_analysis"]:
            render_html(block_card("SEMANTIC ANALYSIS", data["semantic_analysis"]))
        left, right = st.columns(2)
        with left:
            if data["manipulation_tactics"]:
                render_html(block_card("MANIPULATION TACTICS", data["manipulation_tactics"]))
        with right:
            if data["why_suspicious"]:
                render_html(block_card("WHY IT IS SUSPICIOUS", data["why_suspicious"]))
        left2, right2 = st.columns(2)
        with left2:
            if data["safe_actions"]:
                render_html(block_card("RECOMMENDED ACTION", data["safe_actions"]))
        with right2:
            if data["simple_explanation"]:
                render_html(block_card("SIMPLE EXPLANATION", data["simple_explanation"], "ss-simple"))
        if data["urdu_explanation"]:
            render_html(block_card("URDU EXPLANATION  |  \u0627\u0631\u062f\u0648", data["urdu_explanation"], "ss-urdu"))
        st.caption("AI output can be wrong or incomplete. Treat it as an explanation, not a verdict.")


result_state = st.session_state.get("result")
if result_state:
    render_results(result_state)

# --------------------------------------------------------------------------
# Privacy
# --------------------------------------------------------------------------
section("LOCAL AI  |  PRIVACY FIRST")
render_html(
    '<div class="ss-card ss-privacy ss-block">'
    '<div class="ss-block-title">LOCAL AI &bull; PRIVACY FIRST</div>'
    "<p>AI analysis runs locally through Ollama. Messages do not need to be sent to a commercial cloud AI API. "
    "ScamShield also never opens the links it finds.</p></div>"
)

# --------------------------------------------------------------------------
# Safety actions
# --------------------------------------------------------------------------
section("WHAT TO DO NEXT")
render_html(
    '<div class="ss-grid3">'
    '<div class="ss-card"><div class="ss-action-title">DON\'T CLICK</div>'
    '<div class="ss-action-text">Avoid links supplied in unexpected or high-pressure messages.</div></div>'
    '<div class="ss-card"><div class="ss-action-title">PROTECT CREDENTIALS</div>'
    '<div class="ss-action-text">Never disclose OTPs, passwords, PINs or verification codes.</div></div>'
    '<div class="ss-card"><div class="ss-action-title">VERIFY INDEPENDENTLY</div>'
    '<div class="ss-action-text">Contact the organization using its official website, app or trusted phone number.</div></div>'
    "</div>"
)

render_html(
    '<div class="ss-disclaimer">ScamShield is a decision-support tool. Risk indicators and AI analysis do not '
    "prove that a message is fraudulent or legitimate.<br>"
    "Open-source (MIT) code &bull; Model: Qwen3 1.7B via Ollama, under its own license terms.</div>"
)
