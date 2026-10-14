# ScamShield — Complete Updated Project

**Tagline:** Pause before you pay. Check before you trust.

ScamShield is a student-focused, explainable warning tool for suspicious job offers, internship messages, webinar promotions, payment requests, and phishing-style messages. This version uses a high-contrast light UI intended to improve readability.

## Included files

- `app.py` — full Streamlit application and rule-based checker
- `requirements.txt` — Python dependency list
- `.streamlit/config.toml` — light theme defaults
- `run_windows.bat` — Windows quick-start helper
- `run_mac_linux.sh` — macOS/Linux quick-start helper
- `.gitignore` — excludes virtual environments and generated files

## Run on Windows (VS Code)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and enable **Add Python to PATH** during installation.
2. Extract this ZIP.
3. Open the extracted `ScamShield_Latest` folder in VS Code.
4. Select **Terminal → New Terminal**.
5. Run these commands from the project folder:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m streamlit run app.py
```

6. Open the Local URL printed in the terminal, usually `http://localhost:8501`.

Alternatively, double-click `run_windows.bat`. If Windows says Python was not found, install Python and restart VS Code.

## Run on macOS/Linux

Open a terminal in this folder and run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m streamlit run app.py
```

Or run `bash run_mac_linux.sh`.

## Deploy with Streamlit Community Cloud

1. Create a GitHub repository and upload the files from this folder (including `app.py`, `requirements.txt`, and `.streamlit/config.toml`).
2. In Streamlit Community Cloud, create a new app and select your repository and branch.
3. Set the main file path to `app.py` and deploy.
4. Test the included examples on the public URL.

No API key or secrets are required for this prototype.

## Important limitations

The current checker uses transparent Python text rules and weighted scoring. It is **not a trained machine-learning model**, does not query a live scam database, does not open submitted URLs, and cannot certify that an organization or offer is legitimate. The score is a heuristic warning-signal score, not a probability of fraud. False positives and false negatives are possible. A webinar, WhatsApp message, or fee by itself does not prove a scam; users should verify the company, recruiter, terms, and payment request independently.

## Privacy reminder

The app does not intentionally save submissions to a database or send them to an external AI API. Avoid entering real passwords, OTPs, UPI PINs, card details, or other sensitive personal information.


## General-purpose screening and AI Security Assistant

ScamShield screens pasted text for multiple warning-pattern categories: credential theft, suspicious payments, urgency/threats, prize and investment claims, job/placement offers, phishing links, impersonation, personal-data requests, and webinar/course upsells. It does **not** detect every scam, automatically monitor messaging apps, or certify that a message or URL is safe. The score is a warning-signal score, not a probability.

### Built-in assistant

Open **AI Security Assistant** in the sidebar. Without an API key, it provides basic built-in safety guidance and clearly labels that it is not a live AI model. To enable live AI answers, provide your own OpenAI API key in the assistant page, or configure `OPENAI_API_KEY` as an environment variable / Streamlit secret. The key is not written to project files. API usage may incur charges; never commit API keys to GitHub.

For Streamlit Community Cloud, add `OPENAI_API_KEY` under **App settings → Secrets** if you choose to enable the live assistant. Keep the key private.


## Easy Mode for elders and people who find typing difficult

The **Easy Mode — Speak or Show** page is designed around large, plain-language choices rather than requiring users to type. It includes:

- One-tap help for payment requests, OTP/PIN requests, suspicious links, job/prize offers, threats, and cases where money/details were already shared.
- Offline, prewritten quick guidance in **English, Telugu, and Hindi**.
- A trusted-helper prompt users can show to a family member or caregiver.
- User-activated browser text-to-speech, using the selected language where the device has a matching voice installed.
- Optional screenshot reading and recorded voice questions, answered by the AI service when an OpenAI API key is configured.
- Direct links to India's cybercrime reporting portal and a tap-to-call link for 1930.

The one-tap guidance does not require an API key. Screenshot reading and AI voice help require internet access, an OpenAI API key, and may incur API charges. Browser speech support and the availability/quality of Telugu and Hindi voices vary by device. Always check the answer with an official source before acting.

Privacy note: when AI screenshot/voice features are used, the uploaded image or recorded audio/transcription and question are sent to the configured AI provider for processing. Do not upload or say passwords, OTPs, full card numbers, UPI PINs, or other secrets. This is an educational prototype, not a guarantee that a message is safe or fraudulent.


## Gemini API setup (server-side; users never enter keys)

Install dependencies with `python -m pip install -r requirements.txt`. Configure `GEMINI_API_KEY` in the environment before starting Streamlit. On Windows PowerShell, use `$env:GEMINI_API_KEY = Read-Host "Enter Gemini API key"` and then `python -m streamlit run app.py`. On Streamlit Community Cloud, add `GEMINI_API_KEY = "your-key"` under App settings → Secrets. Never commit the key to source control or share it in chat. Revoke any key that has been exposed.

The app has a global language selector (English, Telugu, Hindi), uses Gemini for multilingual AI answers and screenshot/audio understanding, and provides browser text-to-speech for answers. Some static explanatory copy on non-assistant pages may remain English; review the UI before production use. Browser voice availability depends on the device.
