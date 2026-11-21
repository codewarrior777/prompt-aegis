# 🛡️ Aegis Sentinel: AI Firewall & Prompt Injection Detector

[![Live Demo](https://img.shields.io/badge/demo-LIVE-brightgreen?style=for-the-badge&logo=streamlit)](https://aegis-sentinel-vsvrsi6khl6k5y3drut9wh.streamlit.app/)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Cybersecurity](https://img.shields.io/badge/Domain-AI%20Security%20%7C%20LLM-red.svg)]()
[![AI](https://img.shields.io/badge/AI-Groq%20LLM-orange.svg)]()
[![OWASP](https://img.shields.io/badge/OWASP-LLM01-critical.svg)]()

Did you know a Chevrolet dealership lost money in 2023 because a user tricked their AI chatbot into selling a car for $1? That wasn't a traditional hack; it was a **Prompt Injection** — currently the #1 vulnerability in LLM applications according to OWASP.

While everyone is rushing to build AI chatbots, **Aegis Sentinel** is the shield that protects them. It is an enterprise-grade AI Firewall & SOC Dashboard designed to intercept malicious prompts, Jailbreaks, System Prompt extraction attempts, obfuscated payloads, and canary leaks — before they reach the Large Language Model, and after it responds.

## 🌐 Try It Live

🔴 **[Open the Interactive SOC Dashboard Here](https://aegis-sentinel-vsvrsi6khl6k5y3drut9wh.streamlit.app/)**

No installation needed — just click, try to hack the AI, and watch the firewall log the attack in real-time.

## 📸 Dashboard Preview

![Aegis Sentinel Dashboard](assets/aegis_sentinel_hud.png)

## 🚨 Defense in Depth: Five-Layer Architecture

Aegis Sentinel uses five independent defense layers. A request must pass **every** layer before it reaches the target LLM, and the model's output is filtered again before it reaches the user.

1. **Layer 1 — Deterministic Regex Heuristics (Fast & Free):**
   Intercepts known attack vectors instantly using regular expressions (e.g., "Ignore previous instructions", "DAN mode", "reveal your system prompt"). Blocks the request before it even touches the API, saving tokens and reducing latency.

2. **Layer 2 — Encoding Detection:**
   Catches payloads smuggled through Base64 or hex-encoded blobs that would bypass keyword matching.

3. **Layer 3 — PII & Secret Scanner:**
   Flags emails, SSNs, credit card numbers, and API keys (`sk-...`), and redacts them before they land in the audit log.

4. **Layer 4 — Semantic Guardrail (LLM-as-a-Judge):**
   If a prompt bypasses the previous layers (e.g., using obfuscation or roleplay), a secondary LLM evaluates the *intent* using structured JSON output (`malicious`, `category`, `confidence`, `reason`). It also receives recent conversation context to catch multi-turn jailbreaks.

5. **Layer 5 — Output Filter (Canary Defense):**
   Even if a malicious prompt slips through, the model's response is scanned for a canary secret. Any response containing the protected value is blocked with `CRITICAL` severity.

Each guardrail can be toggled independently from the sidebar — useful for live demos to show what each layer catches.

## 🏗️ System Architecture

```mermaid
graph TD
    A[User Prompt] --> B{Layer 1: Regex Heuristics}
    B -->|Blocked| F[🚨 Access Denied & Logged]
    B -->|Pass| C{Layer 2: Encoding Detection}
    C -->|Blocked| F
    C -->|Pass| D{Layer 3: PII / Secrets}
    D -->|Flagged| F
    D -->|Pass| E{Layer 4: Semantic Judge - LLM}
    E -->|Malicious Intent| F
    E -->|Safe Intent| G[Main LLM - Groq API]
    G --> H{Layer 5: Output Filter}
    H -->|Canary Leak| F
    H -->|Clean| I[✅ Safe Response to User]

    style A fill:#00ff41,stroke:#001a33,stroke-width:2px,color:#001a33
    style F fill:#ff003c,stroke:#001a33,stroke-width:2px,color:#fff
    style E fill:#58a6ff,stroke:#001a33,stroke-width:2px,color:#001a33
    style G fill:#0d1117,stroke:#00ff41,stroke-width:2px,color:#00ff41
    style I fill:#003a0e,stroke:#00ff41,stroke-width:2px,color:#00ff41
```

## 📊 Telemetry & Risk Scoring

Every request is scored **0–100** and classified into a severity level:

| Score     | Severity   | Typical Trigger                          |
|-----------|------------|------------------------------------------|
| 0         | `SAFE`     | No signals                               |
| 1–25      | `LOW`      | Minor PII, unusual length                |
| 26–50     | `MEDIUM`   | Encoding tricks, weak jailbreak phrasing |
| 51–75     | `HIGH`     | Strong prompt injection or semantic flag |
| 76–100    | `CRITICAL` | Canary leak, system prompt extraction    |

Additional observability built into the dashboard:

- **Plotly analytics** — attack categories, severity distribution (donut), risk timeline.
- **Live threat feed** — last 6 events with severity badges.
- **SHA-256 fingerprint** per payload — correlate repeated attacks without storing raw text.
- **PII redaction** — emails, SSNs, cards, and API keys are masked in the audit log.
- **Latency tracking** — average guardrail overhead per request.
- **CSV audit export** — one-click download for downstream SIEM ingestion.
- **Fail-closed fallback** — if the semantic judge is unreachable, the request is treated as suspicious instead of being silently allowed.

## ⚖️ Legal & Compliance Framework

Aegis Sentinel is engineered to help organizations align with global AI security standards and emerging legal frameworks:

- **OWASP Top 10 for LLMs (LLM01):** Provides a robust defense against Prompt Injection, the most critical vulnerability in Large Language Models.
- **EU AI Act (Article 15):** Assists in fulfilling the requirement for high-risk AI systems to be resilient against adversarial manipulation and prompt manipulation.
- **NIST AI RMF:** Integrates directly into the *Measure* and *Manage* functions of the NIST AI Risk Management Framework, providing real-time telemetry and logging of adversarial inputs.
- **ISO/IEC 42001:** Supports the operational controls required for an AI Management System (AIMS) by enforcing input sanitization and safety boundaries.

## 🚀 How to Run Locally

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/codewarrior777/prompt-aegis.git
   cd prompt-aegis
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1  # Windows
   # source .venv/bin/activate   # Mac/Linux
   pip install -r requirements.txt
   ```

3. Create a `.env` file and add your Groq API key:
   ```env
   GROQ_API_KEY="gsk_your_api_key_here"
   ```

4. Run the dashboard:
   ```bash
   streamlit run app.py
   ```

### Try It Yourself

The sidebar includes one-click sample payloads:

- Prompt Injection
- System Prompt Extraction
- Jailbreak (`DAN mode`)
- Base64-encoded attack
- PII test (email + SSN)
- Benign question (control)

Toggle layers on/off to see which defense catches each attack.

## 🔒 Ethical Disclaimer

This tool is built for **educational and defensive cybersecurity purposes only**. It is designed to demonstrate how to protect Generative AI applications from Prompt Injection and Jailbreaking.

---
*Built as an AI Security Portfolio Project by Gustavo Ramos.*