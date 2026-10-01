# ScamShield AI

### *Think Before You Click.*

ScamShield AI is an open-source, human-centered cybersecurity assistant that helps ordinary people understand suspicious SMS messages, emails, WhatsApp messages, delivery notices, job offers, banking alerts and prize scams **before** they click a link, share credentials or send money.

> A scammer may understand technology. Their victim shouldn't have to.

Built for **Hacktoberfest Hack Day 2026**.

---

## Problem

Traditional security tools show technical warnings: *phishing, credential harvesting, domain spoofing, HTTP, IP-based URL*. A normal person receiving

> "URGENT! Your bank account will be disabled tonight. Verify immediately and enter your OTP."

does not need a lecture on terminology. Their real question is:

**"Should I trust this message, why is it dangerous, and what should I do?"**

## Solution

ScamShield answers that question in plain language. It is **not** a "ask an LLM if this is a scam" wrapper. It is a **hybrid, explainable security system**:

1. A **rule-based engine** finds transparent, observable indicators (urgency, threats, credential requests, payment requests, rewards, secrecy pressure...).
2. A **URL intelligence module** inspects links by structure only, **without ever opening them**.
3. A **local open-weight AI model** (Qwen3 1.7B via Ollama) reads the *meaning* of the message, identifies manipulation tactics that keyword rules miss, and explains everything in a simple English explanation and an Urdu explanation.

## Why it matters

- Phishing and social engineering target people, not computers.
- The people most at risk (parents, grandparents, first-time smartphone users) are the least likely to understand technical alerts.
- Explanations that people understand change behavior; scores alone do not.

## Features

- Risk Signal Score (0-100) built from transparent indicators, with the matched text shown as evidence
- Four risk levels: `HIGH RISK`, `SUSPICIOUS`, `CAUTION`, `NO OBVIOUS WARNING SIGNALS`
- URL analysis: HTTP, IP-address hosts, URL shorteners, suspicious words, many hyphens/subdomains, punycode, `@` trick, frequently abused endings
- AI Security Analyst: semantic analysis, manipulation tactics, why it is suspicious, recommended safe actions
- Simple explanation (understandable by parents and grandparents) and a short Urdu explanation
- One-click demo attacks: Fake Bank, Prize Scam, Delivery Scam, Job Scam, and a Subtle Phish that keyword rules miss but the AI reads
- Prompt-injection defence: the analysed message is treated as untrusted data
- Graceful handling of Ollama being offline, timeouts, empty input, no URLs and malformed AI output
- Modern dark security dashboard

## Architecture

```
                 USER MESSAGE
                      |
          +-----------+-----------+
          |                       |
          v                       v
  Rule-Based Engine        URL Intelligence
    (detector.py)         (url_analyzer.py)
          |                       |
          +-----------+-----------+
                      |
                      v
        Local Open-Weight AI (ai_engine.py)
        Qwen3 1.7B running in Ollama
                      |
                      v
            Explainable Analysis
         +------------+------------+
         |            |            |
       Risk        Reasons      Actions
     Indicators                    |
                         Simple Explanation
                                   |
                           Urdu Explanation
```

## How the hybrid detection works

| Step | Component | What it does | Why |
|------|-----------|--------------|-----|
| 1 | `detector.py` | Regex rules find urgency, fear, credential requests, payment requests, rewards, secrecy, too-good-to-be-true offers, delivery pretexts, authority impersonation | Transparent and repeatable; every finding shows its evidence |
| 2 | `url_analyzer.py` | Extracts links and inspects structure only | Safe: links are never opened |
| 3 | `ai_engine.py` | Sends the message + the findings to a local model | Understands meaning, tone and manipulation beyond exact words |
| 4 | `app.py` | Shows signals, URL warnings, AI analysis, simple and Urdu explanations | Turns security signals into guidance people can act on |

**About the score:** the "Risk Indicators" number (for example `85/100`) is a *Risk Signal Score*: an accumulation of observed warning signs. It is **not** a calibrated probability that a message is a scam.

## Why open-weight AI

- **Local inference:** the model runs on the user's own machine through Ollama.
- **Transparency:** weights can be inspected, tested and run without a commercial cloud AI API.
- **Practicality:** a small 1.7B-parameter model is enough for explanation tasks, because the deterministic engine supplies the evidence.
- **Reproducibility:** anyone can run the full project locally.

## Technology stack

- Python 3
- Streamlit
- Ollama (local model runtime)
- Qwen3 1.7B (`qwen3:1.7b`)
- `requests`, plus Python standard libraries (`re`, `urllib.parse`, `ipaddress`)

## Installation (Windows PowerShell)

### 1. Install Python dependencies

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks activation, run once in the same window:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### 2. Install and start Ollama

Download Ollama from <https://ollama.com/download> and install it. Make sure it is running (the Ollama app in the system tray, or `ollama serve`). Check with:

```powershell
ollama --version
```

### 3. Pull the model

```powershell
ollama pull qwen3:1.7b
ollama list
```

### 4. Run ScamShield

```powershell
streamlit run app.py
```

Then open <http://localhost:8501>.

> Tip: the first AI analysis loads the model into memory and can be slow. Run one analysis before a live demo to warm it up.

## Demo examples

Use the quick-demo buttons in the app, or paste this message:

```
URGENT!

Your bank account will be disabled tonight.

Verify your identity immediately:

http://192.168.1.50/secure-bank-verification/login

Enter your CNIC, password and OTP to restore your account.

Failure to verify immediately may result in permanent account suspension.
```

Expected signals: artificial urgency, fear/threat, credential request, HTTP, IP-address URL, suspicious URL language.

Also try **Subtle Phish (AI)**: it deliberately avoids obvious scam keywords, so the rule engine finds little while the AI can still point out pressure and impersonation language. This shows why the hybrid design matters.

## Project structure

```
ScamShield-AI/
|-- app.py                 # Streamlit dashboard
|-- detector.py            # Rule-based security engine
|-- url_analyzer.py        # URL intelligence (never opens links)
|-- ai_engine.py           # Local Ollama / Qwen3 integration
|-- requirements.txt
|-- README.md
|-- LICENSE                # MIT license (our source code only)
|-- .gitignore
`-- .streamlit/config.toml # Dark theme, usage statistics disabled
```

## Safety limitations

- ScamShield is a **decision-support tool**. Risk indicators and AI analysis do **not** prove that a message is fraudulent or legitimate.
- Rules are keyword/pattern based. Scammers can reword messages, and real organizations can also use urgent language, so both false positives and false negatives are possible.
- A 1.7B-parameter model can make mistakes, miss context or produce imperfect Urdu. Its output should be treated as an explanation, not a verdict.
- URL checks are structural only: no reputation databases, no WHOIS/domain age, no page content.
- Currently text-only: no screenshots, images, QR codes or voice.
- Always verify through the organization's official website, app or a trusted phone number.

## Privacy and local inference

- AI analysis runs locally through Ollama at `http://localhost:11434`. Messages do not need to be sent to a commercial cloud AI API.
- ScamShield never opens or fetches the links it finds.
- Streamlit usage statistics are disabled in `.streamlit/config.toml`.
- Downloading Ollama and the model requires an internet connection; analysis afterwards does not require sending your message to a cloud AI service.
- This project does not store messages in a database. We do not make guarantees beyond what this code does; review the code and your own system's configuration if you handle sensitive data.

## Future improvements

Screenshot/OCR analysis, QR-code scanning, voice-message analysis, browser extension, WhatsApp and email integration, more languages, domain-reputation APIs, WHOIS/domain-age intelligence, community threat reporting, and a fine-tuned phishing model.

## Team

| Name | Role | Contact |
|------|------|---------|
| _Your name_ | _Role_ | _GitHub / LinkedIn_ |
| _Teammate_ | _Role_ | _GitHub / LinkedIn_ |

## Hackathon

- **Event:** Hacktoberfest Hack Day 2026
- **Track / category:** _fill in_
- **Team name:** _fill in_
- **Demo video / slides:** _add link_

## Model attribution and licenses

There are **two separate licenses** in this project:

1. **ScamShield source code** (all files in this repository): released under the **MIT License**. See [`LICENSE`](LICENSE).
2. **The Qwen3 1.7B model**: *not* part of this repository and *not* covered by our MIT license. It is created by the Qwen team (Alibaba Cloud), is downloaded separately through Ollama, and is governed by **its own license and terms**. Please read them at the official sources:
   - Ollama model page: <https://ollama.com/library/qwen3>
   - Official model card: <https://huggingface.co/Qwen/Qwen3-1.7B>
   - Qwen project: <https://github.com/QwenLM/Qwen3>

Runtime: [Ollama](https://ollama.com) is a separate project with its own license. UI framework: [Streamlit](https://streamlit.io), also under its own license.

> **Before submission:** verify the current Qwen3 license and terms directly on the official model card above.

## Disclaimer

ScamShield is a decision-support tool. Risk indicators and AI analysis do not prove that a message is fraudulent or legitimate.
