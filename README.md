# 🛡️ Aegis Sentinel: AI Firewall & Prompt Injection Detector

[![Live Demo](https://img.shields.io/badge/demo-LIVE-brightgreen?style=for-the-badge&logo=streamlit)](https://aegis-sentinel-vsvrsi6khl6k5y3drut9wh.streamlit.app/)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Cybersecurity](https://img.shields.io/badge/Domain-AI%20Security%20%7C%20LLM-red.svg)]()
[![AI](https://img.shields.io/badge/AI-Groq%20LLM-orange.svg)]()

Did you know a Chevrolet dealership lost money in 2023 because a user tricked their AI chatbot into selling a car for $1? That wasn't a traditional hack; it was a **Prompt Injection** — currently the #1 vulnerability in LLM applications according to OWASP.

While everyone is rushing to build AI chatbots, **Aegis Sentinel** is the shield that protects them. It is an advanced AI Firewall designed to intercept malicious prompts, Jailbreaks, and System Prompt extraction attempts before they reach the Large Language Model.

## 🌐 Try It Live

🔴 **[Open the Interactive Dashboard Here](https://aegis-sentinel-vsvrsi6khl6k5y3drut9wh.streamlit.app/)**

No installation needed — just click and try to hack the AI. 

## 🚨 Defense in Depth: Dual-Layer Architecture

Aegis Sentinel uses a two-layer defense mechanism to ensure maximum security without sacrificing performance:

1. **Layer 1: Deterministic Regex Heuristics (Fast & Free):**
   Intercepts known attack vectors instantly using regular expressions (e.g., "Ignore previous instructions", "DAN mode"). It blocks the request before it even touches the API, saving tokens and reducing latency.

2. **Layer 2: Semantic Guardrails (LLM-as-a-Judge):**
   If a prompt bypasses the Regex layer (e.g., using obfuscation or roleplay), a secondary LLM evaluates the *intent* of the prompt. If it detects malicious intent, the request is blocked and logged.

Only if a prompt passes **both** layers is it routed to the main LLM to generate a response.

## 🏗️ System Architecture

```mermaid
graph TD
    A[User Prompt] --> B(Layer 1: Regex Guardrail)
    B -->|Blocked| F[🚨 Access Denied & Logged]
    B -->|Pass| C(Layer 2: Semantic Guardrail - LLM Judge)
    C -->|Malicious Intent| F
    C -->|Safe Intent| D(Main LLM - Groq API)
    D --> E[✅ Safe Response to User]
    
    style A fill:#00ff41,stroke:#001a33,stroke-width:2px,color:#001a33
    style F fill:#ff003c,stroke:#001a33,stroke-width:2px,color:#fff
    style C fill:#58a6ff,stroke:#001a33,stroke-width:2px,color:#001a33
    style D fill:#0d1117,stroke:#00ff41,stroke-width:2px,color:#00ff41
```

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

## 🔒 Ethical Disclaimer
This tool is built for **educational and defensive cybersecurity purposes only**. It is designed to demonstrate how to protect Generative AI applications from Prompt Injection and Jailbreaking. 

---
*Built as an AI Security Portfolio Project by Gustavo Ramos.*