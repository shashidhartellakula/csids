# CSIDS — Command Sequence Intrusion Detection System

A Linux user behavior-based intrusion detection system that
analyzes bash command sequences to detect suspicious activity.

---

## Features

- Behavioral profiling per user from bash history
- Risk scoring engine (35+ commands, 0–10 scale)
- 4-rule anomaly detection logic
- Dark security dashboard with Chart.js charts
- Real-time terminal monitor (tails ~/.bash_history live)
- Live browser feed (auto-polls every 2s)
- PDF report download per user
- Email alerts via SMTP

---

## Quick Start
```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/csids.git
cd csids

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
# → Open http://localhost:5000
```

---

## Usage

### Train a profile
1. Export your history:
```bash
   cp ~/.bash_history history.txt
```
2. Go to **Analyze** → select **Train Profile**
3. Upload `history.txt` → Submit

### Detect intrusions
1. Go to **Analyze** → select **Detect Intrusion**
2. Upload a history file to analyze
3. View results + download PDF report

### Real-time monitoring
```bash
# Terminal 1 — run app
python app.py

# Terminal 2 — run monitor
python monitor.py --user YOUR_USERNAME

# Optional: quiet mode (alerts only)
python monitor.py --user YOUR_USERNAME --quiet
```

Open **http://localhost:5000/live** → click Start to see live feed.

---

## Email Alerts Setup

1. Go to **Settings** in the sidebar
2. Enter Gmail + App Password
   - Generate App Password: https://myaccount.google.com/apppasswords
3. In Analyze, check **"Send email alert"** and enter target email

---

## Detection Logic

| Rule | Condition | Action |
|------|-----------|--------|
| 1 | Never-seen sequence + risky command | Alert |
| 2 | Never-seen sequence + risk score ≥ 3 | Alert |
| 3 | Risk score ≥ 6 (even if seen before) | Alert |
| 4 | Seen ≤ 2x + risk score ≥ 3 | Alert |

Risk score is calculated from command severity weights,
sensitive path access, piping, encoded payloads, and more.

---

## Bug Fixes from v1.0

| Bug | Fix |
|-----|-----|
| Paths erased before detection | Sensitive paths preserved as features |
| Only 8 hardcoded risky commands | 35+ commands with severity weights |
| freq threshold=1 too loose | Raised to 2, added risk scoring |
| No user validation | Error shown if user not trained |
| Path traversal vulnerability | secure_filename() on all uploads |
| SELECT then INSERT/UPDATE | Single ON CONFLICT upsert |

---

## Project Structure
```
csids/
├── app.py                  # Flask routes
├── monitor.py              # Real-time CLI monitor
├── database.py             # SQLite schema
├── notifier.py             # Email alerts
├── pdf_report.py           # PDF generator
├── requirements.txt
├── README.md
├── detector/
│   ├── preprocess.py       # Command cleaning + risk scoring
│   ├── sequence_builder.py # Sliding window sequences
│   ├── profiler.py         # Train user profiles
│   └── detector.py        # Anomaly detection
└── templates/
    ├── base.html           # Dark layout + sidebar
    ├── dashboard.html      # Stats + charts
    ├── analyze.html        # Upload form
    ├── results.html        # Detection results
    ├── alerts.html         # Alert log
    ├── live.html           # Live feed
    └── settings.html      # SMTP config
```

---

## Requirements

- Python 3.10+
- Flask
- reportlab