# 🛡️ ThreatLens
### See the Threat Before It Strikes.

A beginner-friendly cybersecurity web application that detects **SMS phishing (smishing)** and **suspicious URLs** in real time — built entirely in Python with Streamlit.

No paid APIs. No database. No machine learning. No data leaves your machine.

---

## 📸 What It Does

You paste a suspicious text message or URL, click **Scan for Threats**, and ThreatLens instantly returns:

- **Risk Score** — 0 to 100
- **Risk Category** — Low Risk 🟢 / Suspicious 🟡 / High Risk 🔴
- **Detection Reasons** — plain-English explanation of every flag raised
- **Safety Recommendations** — tailored action steps per risk level
- **Live Dashboard** — four cards tracking Total, Safe, High-Risk, and Suspicious scans

---

## 🚀 Quick Start (Windows)

### 1. Make sure Python is installed

Open PowerShell and run:

```powershell
python --version
```

You need **Python 3.9 or later**. Download from [python.org](https://www.python.org/downloads/) if needed.

---

### 2. Navigate to the project folder

```powershell
cd C:\Users\dell\Desktop\threatlen
```

---

### 3. Install Streamlit

```powershell
pip install streamlit
```

> ⏳ This takes 1–3 minutes the first time. Wait for the prompt to return.

---

### 4. Run the app

```powershell
streamlit run app.py
```

Your browser opens automatically at **http://localhost:8501**

---

### 5. Stop the app

Press **`Ctrl + C`** in PowerShell.

---

## 📁 Project Structure

```
threatlen/
│
├── app.py                        # The entire application (one file)
└── ThreatLens_Project_Report.docx  # Submitted project report
```

---

## 🔍 How the Detection Engine Works

All detection is rule-based — no internet connection needed at scan time.

### Text Analysis (max 75 points)

| Signal | Points | Example Keywords |
|---|---|---|
| Urgency Language | +15 | "urgent", "act now", "within 24 hours" |
| Credential / OTP Request | +25 | "otp", "password", "verification code" |
| Payment Demand | +20 | "pay now", "outstanding balance", "bitcoin" |
| Reward / Prize Lure | +20 | "you have won", "claim your prize" |
| Threat Language | +20 | "legal action", "arrested", "suspended" |
| Phone Number Present | +10 | Any phone number pattern in the message |
| Spoofed Brand Name | +10 | PayPal, Amazon, Netflix, Chase, FedEx, IRS… |
| ALL CAPS Words | +5 | URGENT, CLICK, LIMITED |
| Excessive Exclamation | +5 | 3 or more `!!!` |

### URL Analysis (max 50 points per URL)

| Signal | Points | What It Checks |
|---|---|---|
| URL Shortener | +20 | bit.ly, tinyurl.com, goo.gl, rb.gy and 10 more |
| Suspicious TLD | +15 | .xyz, .top, .tk, .ml, .club, .cf and more |
| IP Address URL | +25 | `http://192.168.x.x/…` instead of a domain |
| Unusually Long URL | +10 | Over 100 characters |
| Too Many Subdomains | +15 | `secure.paypal.login.evil.com` |
| Spoofed Brand in URL | +20 | Brand name in URL but not on official domain |

### Risk Classification

| Score | Category | Action |
|---|---|---|
| 0 – 24 | 🟢 Low Risk | Message appears safe |
| 25 – 59 | 🟡 Suspicious | Verify before acting |
| 60 – 100 | 🔴 High Risk | Very likely phishing — delete immediately |

> **Score caps:** Text capped at 75 · Each URL capped at 50 · Combined total capped at 100

---

## 🧪 Sample Messages (Built-In)

Use the dropdown in the app to load any of these pre-loaded examples:

| Sample | Expected Result |
|---|---|
| 🔴 Phishing (Bank OTP) | High Risk — Score: 90 |
| 🔴 Phishing (Prize Scam) | High Risk — Score: 80 |
| 🟡 Suspicious (Payment Demand) | Suspicious — Score: 45 |
| 🟢 Safe (Normal Bank Alert) | Low Risk — Score: 20 |
| 🟢 Safe (Appointment Reminder) | Low Risk — Score: 15 |

---

## 🏗️ Architecture

```
User Input (message + optional URL)
        │
        ▼
  analyse_text()          ← scores message text, returns seen_brands set
        │
        ▼
  extract_urls()          ← finds all URLs embedded in the message
        │
        ▼
  analyse_url()           ← scores each URL (skips brands already seen in text)
        │
        ▼
  run_scan()              ← combines scores, caps at 100, classifies risk
        │
        ▼
  Results Panel           ← score bar, badge, reasons, safety actions
        │
        ▼
  st.session_state        ← dashboard counters updated + st.rerun() called
```

---

## 🔒 Privacy

- **Zero network calls** at runtime — the app works fully offline after installation
- **Nothing is stored** — all analysis is in-memory; closing the browser tab clears everything
- **Nothing is transmitted** — your messages never leave your computer
- **No telemetry** — Streamlit's optional email prompt at first launch can be skipped by pressing Enter

---

## ⚙️ Requirements

| Requirement | Version |
|---|---|
| Python | 3.9 or later |
| streamlit | Any recent version (`pip install streamlit`) |

No other dependencies. The `re` and `datetime` modules used are part of Python's standard library.

---

## 🐛 Known Bug Fixed

During development, a **brand double-counting bug** was found and fixed.

**Problem:** If a brand like "fedex" appeared in both the message text and the URL, it was scored twice (+10 text + +20 URL), inflating scores by 20 points.

**Fix:** `analyse_text()` now returns a `seen_brands` set. `analyse_url()` skips any brand already flagged in the text analysis.

**Result:** The Payment Demand sample corrected from 65 (wrong: High Risk) → 45 (correct: Suspicious).

---

## ⚠️ Limitations

- Rule-based detection only — a carefully crafted message that avoids all keywords will score 0
- English-language keyword lists only
- URL scanning is structural only — it does not visit or fetch URLs
- Session data resets when the server restarts (no persistent storage)

---

## 🔭 Future Ideas

- [ ] Add a Naive Bayes ML classifier trained on a public SMS spam dataset
- [ ] Integrate VirusTotal or Google Safe Browsing API for live URL checks
- [ ] Store scan history in SQLite for persistence across sessions
- [ ] Add multi-language keyword support
- [ ] Build a browser extension version

---

## 📄 License

This project is for **educational purposes only**. It is not intended as a production security tool.

---

*Built with Python + Streamlit · No external APIs · No data collected*
