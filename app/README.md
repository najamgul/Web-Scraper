# Web Scraper - Threat Intelligence Dashboard

A Flask-based app to scrape, analyze, and classify threat intelligence using:
- 🔍 Google Dorking
- 🦠 VirusTotal API
- 🛰 Shodan API
- 🤖 Random Forest ML model

## How to Run
1. Create virtualenv & activate
2. Install: `pip install -r requirements.txt`
3. Train model: `python train_model.py`
4. Add `.env` with API keys
5. Start: `flask run`
