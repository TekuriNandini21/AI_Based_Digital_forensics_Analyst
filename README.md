# 🔎 AI-Powered Digital Forensics Assistant

A full-stack, AI-augmented **Digital Forensics** platform built as a B.Tech major project. It ingests digital evidence (logs, exports, metadata), applies a rule-based forensic detection engine, scores investigations for risk, generates an AI-written analyst report via **Google Gemini**, and produces a downloadable **PDF forensic report** — all through a SOC-style web dashboard.

---

## 📌 Project Description

Digital forensic investigators are often overwhelmed by huge volumes of raw log data (Windows Event Logs, Linux `auth.log`, SSH/Apache/Nginx logs, firewall logs, browser history, file metadata, network logs). This project automates the **first pass** of forensic triage:

1. Upload evidence (CSV / JSON / TXT).
2. A rule-based detection engine scans for 20+ suspicious activity patterns (brute force, privilege escalation, malware indicators, PowerShell abuse, port scanning, DNS tunneling, USB activity, etc.).
3. A quantitative **AI Risk Score (0–100)** is computed from the severity mix of findings.
4. The aggregated findings are sent to **Google Gemini** to generate an analyst-grade written report (Executive Summary, MITRE ATT&CK mapping, recommendations, etc.).
5. Everything is visualized on a SOC dashboard and exportable as a professional PDF report.

## 🎯 Objectives

- Combine **AI** and **Cybersecurity / Digital Forensics** in one practical system.
- Demonstrate rule-based + AI-assisted log analysis and incident classification.
- Provide investigators with a visual, explorable timeline of suspicious events.
- Produce court/board-ready PDF forensic reports automatically.
- Showcase full-stack engineering: Flask backend, SQLite persistence, Plotly visual analytics, and a modern dark SOC-themed UI.

## 🏗️ Architecture Diagram

```
                    ┌────────────────────┐
                    │      Browser        │
                    │ (Bootstrap + Plotly) │
                    └─────────▲───────────┘
                              │ HTTP (Flask routes / Jinja2)
                    ┌─────────┴───────────┐
                    │       app.py         │
                    │  (Flask controller)  │
                    └───┬───────┬─────────┬┘
                        │       │         │
          ┌─────────────▼┐ ┌────▼─────┐ ┌─▼───────────────┐
          │ analyzer.py   │ │database.py│ │ ai_analyzer.py   │
          │ (detection    │ │ (SQLite   │ │ (Google Gemini   │
          │  engine)      │ │  storage) │ │  integration)    │
          └───────┬───────┘ └───────────┘ └──────┬───────────┘
                  │                               │
                  │        ┌──────────────────────▼───┐
                  └───────►│   report_generator.py     │
                           │   (ReportLab PDF builder) │
                           └───────────────────────────┘
```

## 🧰 Technology Stack

| Layer      | Technology |
|------------|------------|
| Backend    | Python 3.12+, Flask |
| Frontend   | HTML5, Bootstrap 5, CSS3, JavaScript, Plotly.js |
| AI         | Google Gemini API (`google-generativeai`) |
| Database   | SQLite |
| Reporting  | ReportLab (PDF generation) |
| Data       | Pandas, native csv/json parsing |
| Config     | python-dotenv |

## 📁 Folder Structure

```
AI_Digital_Forensics_Assistant/
│
├── app.py                 # Flask app & routes
├── analyzer.py             # Rule-based forensic detection engine
├── ai_analyzer.py          # Gemini API integration + offline fallback
├── database.py              # SQLite schema & query helpers
├── report_generator.py     # PDF report builder (ReportLab)
├── requirements.txt
├── README.md
├── .env.example
│
├── templates/
│   ├── index.html          # Login page
│   ├── dashboard.html      # SOC dashboard
│   └── report.html         # Investigation report view
│
├── static/
│   ├── style.css           # Dark SOC theme
│   └── script.js           # Plotly chart rendering
│
└── uploads/                 # Uploaded evidence + generated PDFs
```

## ⚙️ Installation

```bash
# 1. Clone / extract the project
cd AI_Digital_Forensics_Assistant

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# then edit .env and add your GEMINI_API_KEY
```

> **Note:** If no `GEMINI_API_KEY` is configured, the app automatically falls back to a deterministic offline report generator so the project still runs end-to-end for demos/grading without internet access.

## ▶️ Running the Application

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

**Default login credentials:**
```
Username: admin
Password: admin123
```
(Configurable via `APP_ADMIN_USERNAME` / `APP_ADMIN_PASSWORD` in `.env`.)

## 🖥️ Usage Flow

1. Log in with the admin credentials.
2. Click **New Investigation**, name the case, and upload one or more evidence files (CSV/JSON/TXT).
3. The analyzer runs automatically and redirects you to the **Investigation Report**.
4. Review the risk score, timeline, detected incidents, and the AI-generated forensic narrative.
5. Click **Download PDF** to export a formal report.
6. Return to the **Dashboard** to see aggregated SOC-style statistics across all cases.

## 🖼️ Screenshots

> _Add screenshots here after running the app locally:_
- `screenshots/login.png`
- `screenshots/dashboard.png`
- `screenshots/report.png`
- `screenshots/pdf-report.png`

## 🔬 Detected Activity Categories

Failed Login Attempts · Brute Force Attacks · Successful Login After Multiple Failures · Privilege Escalation · Unauthorized User Creation · Suspicious Commands · PowerShell Abuse · Deleted/Hidden Files · Malware Indicators · Suspicious File Extensions · Registry Modification · USB Device Activity · Remote Desktop Logins · SSH Login Activity · Unknown Processes · Network/Port Scanning · DNS Tunneling Indicators · Large File Transfers · Suspicious IP Addresses.

## 🚀 Future Scope

- Integrate real-time log streaming (Syslog / Filebeat) for live monitoring.
- Add machine-learning based anomaly detection to complement rule-based heuristics.
- Multi-user role-based access control (Investigator / Reviewer / Admin).
- Chain-of-custody digital signing for generated reports.
- Support additional evidence types (PCAP, memory dumps, disk images).
- Case collaboration and comment threads for investigation teams.

## 📄 License

This project is released under the **MIT License** for academic and educational use.

---

*Built as a B.Tech Major Project combining Artificial Intelligence and Digital Forensics / Cybersecurity.*
