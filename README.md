

# Email Detector (backend)

Lightweight backend service that analyzes email content (text, .eml, PDF/TXT attachments), extracts Indicators of Compromise (IOCs), checks reputations (VirusTotal / AbuseIPDB / URLScan), runs an AI classification step and produces a PDF report.

Quickstart (local)
------------------
1. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

2. Install project (uses pyproject.toml):

```bash
pip install -e .
```

3. Copy environment template and fill keys:

```bash
cp .env.example .env
# edit .env and add API keys: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY, AI_API_KEY, SECRET_KEY
```

4. Apply migrations and create superuser:

```bash
python manage.py migrate
python manage.py createsuperuser
```

5. Ensure media folder exists:

```bash
mkdir -p media/reports
```

6. Run development server:

```bash
python manage.py runserver
```

Background worker (optional but recommended)
------------------------------------------
Start a Celery worker to process long-running analysis tasks:

```bash
celery -A settings worker -l info
```

Important environment variables
-------------------------------
- `SECRET_KEY` — Django secret.
- `FERNET_KEY` — key used for DB encryption (optional).
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY` — reputation services.
- AI keys used by `apps/detector/services/ai_service.py` (OpenAI / Google GenAI).
- `MEDIA_ROOT`, `MEDIA_URL` — where generated PDFs are stored and served.
- `ALLOW_GUEST_REPORTS` — enable direct PDF links for unauthenticated scans (default: false).
- `MASK_PII_IN_REPORTS` — mask emails/URLs/IPs in generated reports (default: false).
- `RETENTION_DAYS` — days to keep results before purge (default: 0 disables purge).
- `ENABLE_VT_URL_REPORT` — fetch VirusTotal URL reports after submit (default: false).
- `ENABLE_RDAP_ENRICHMENT` — enrich domain reputation with RDAP data (default: false).

API (examples)
--------------
- POST /api/detector/scan — accepts form-data or JSON with `input_type` (text|url|file) and `input_data` or `file`.
	- Returns JSON with classification, score, explanation, and `report_url` when a PDF report was generated.
- GET /api/detector/<id>/result — retrieve stored scan result (owner only).
- GET /api/detector/<id>/report/download/ — download PDF report (owner only).

Frontend usage
--------------
- The simple frontend (Django templates) posts to the same pipeline and will show a "Download PDF Report" link when a report was created.

How reports are produced and downloaded
--------------------------------------
- The analysis pipeline: parse input → extract IOCs → check reputations (VirusTotal/AbuseIPDB/URLScan) → aggregate → call AI (`analyze_parsed`) → compute final score → generate PDF via ReportLab.

  The final score is a weighted combination of AI confidence, reputation results, header
  anomalies (SPF/DKIM/DMARC), structural signals, and optional rule hits. You can tweak the
  relative importance by setting `SCORE_AI_WEIGHT`, `SCORE_REPUTATION_WEIGHT`,
  `SCORE_HEADER_WEIGHT`, `SCORE_STRUCTURAL_WEIGHT`, and `SCORE_RULES_WEIGHT` in your
  Django settings (defaults are 0.45/0.2/0.2/0.15/0.0 respectively).
- Generated PDFs are saved to `MEDIA_ROOT/reports/` and attached to `DetectorResult.report_file`.
- Download via the API endpoint `GET /api/detector/<id>/report/download/` which streams the PDF with `Content-Disposition: attachment`.
- For unauthenticated scans, `report_url` is returned only when `ALLOW_GUEST_REPORTS=true`.

Notes & deployment
------------------
- In production set a persistent `MEDIA_ROOT` and configure your web server (Nginx) to serve media files, or use object storage (S3) and store report URLs.
- Configure a production database (Postgres) and a message broker (Redis/RabbitMQ) for Celery.
- Keep all API keys and secrets out of version control (use `.env` or secret manager).

Testing
-------
Run unit tests with:

```bash
python manage.py test
```

Troubleshooting
---------------
- If PDF links are missing, ensure `MEDIA_URL` is set and `media/reports` contains files and permissions allow Django to read them.
- If reputation APIs return rate-limit errors, add retries or throttle requests and ensure API keys are valid.

Contact / Contribution
----------------------
Open issues or PRs; include tests for new logic.


