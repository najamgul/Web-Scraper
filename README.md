# Web Scraper Threat Intel Platform

Modern Flask application that aggregates threat intelligence across multiple sources (VirusTotal, Shodan, AbuseIPDB, AlienVault OTX, Google OSINT) and presents the results in an interactive dashboard with exportable reports.

## Features

- **Multi-Source Enrichment**: Scan IPs, domains, URLs, hashes, or keywords and pull correlated data from VT, Shodan, AbuseIPDB, OTX, and Google CSE in parallel.
- **AI-Assisted Classification**: Enhanced Random Forest model plus contextual heuristics to label IOCs as Malicious, Suspicious, Benign, Informational, or Unknown.
- **Real-Time Dashboard**: Live feed of recent detections, threat timelines, top malicious (or fallback) IPs/domains, geographic distribution, tag analytics, and classification breakdowns.
- **On-Demand Exports**: Generate JSON, CSV, Excel, or PDF reports that include every enrichment source with AbuseIPDB category breakdowns and Google OSINT sections.
- **User Experience Enhancements**: Responsive UI, dedicated login/signup styling, keyboard-friendly navigation, and history view with desktop/mobile layouts.

## Tech Stack

- Python 3.11, Flask, MongoEngine (MongoDB)
- Threaded API aggregation, background-safe enrichment
timeouts, caching helpers
- Random Forest ML pipeline (`ml_model_improved.py`) with TF-IDF for keyword context
- Chart.js visualization, custom responsive CSS, ReportLab/OpenPyXL export stack

## Getting Started

### 1. Clone & Install

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file (or set environment variables) with:

```text
FLASK_APP=run.py
FLASK_ENV=development
MONGODB_URI=mongodb://localhost:27017/webscraper
VIRUSTOTAL_API_KEY=...
SHODAN_API_KEY=...
ABUSEIPDB_API_KEY=...
OTX_API_KEY=...
GOOGLE_CSE_ID=...
GOOGLE_CSE_API_KEY=...
SECRET_KEY=change-me
```

### 3. Run the App

```powershell
python run.py
```

### 4. Optional

Retrain models or populate fixtures via scripts in `app/ml_model.py` or the migrations folder.

## Project Structure Highlights

- `app/routes.py` – unified scan orchestration, export endpoints, dashboard controller.
- `app/analytics.py` – aggregation helpers for timelines, top offenders, geolocation, live feed.
- `app/templates/` – Jinja templates for dashboard, results, history, auth pages.
- `app/static/` – responsive CSS, component styling, assets.
- `migrations/` – Alembic setup for MongoEngine-backed schema evolution.

## Current Roadmap Ideas

- Automated background rescans and notification hooks
- Extensible scraping modules for new OSINT feeds
- CI-ready unit and integration tests
- Accessibility and internationalization improvements

---

_Maintained as a final-year project evolving into a full-stack threat intelligence research platform._
