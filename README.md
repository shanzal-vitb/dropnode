<p align="center">
  <img src="/static/readme/dropnode.svg" alt="DropNode Logo" width="180" />
</p>

<h1 align="center">DropNode — Secure File Upload Portal</h1>

<p align="center">
  <img src="/static/readme/0neHackers.svg" alt="OneHackers Logo" width="120" />
  <br/><br/>
  Built by <strong>OneHackers</strong> for Cyber Carnival 2K26 | VIT-B<br/>
  Team: <a href="https://github.com/shanzal-vitb/" target="_blank"><img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="20" style="vertical-align: middle;" /></a> Shanzal Firoz (Lead), <a href="https://github.com/navni25bey10011-sys" target="_blank"><img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="20" style="vertical-align: middle;" /></a> Navni Danwani, <a href="https://github.com/Sinflin" target="_blank"><img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="20" style="vertical-align: middle;" /></a> Aditya Vishwakarma
</p>

---

## Overview

DropNode is a self-hosted, browser-based file upload portal that scans every uploaded file against the VirusTotal multi-engine API before making it available for download. Safe files are moved to permanent storage; unsafe files are quarantined and automatically deleted after three minutes. Every scan is persisted to a local SQLite database and can be retrieved at any time via a unique Drop ID.

---

## Project Structure

```
dropnode/
├── app.py                  # Flask backend — routes, scanning logic, DB, deletion scheduler
├── index.html              # Single-page frontend (Tailwind CSS + vanilla JS)
├── requirements.txt        # Python dependencies
├── dropnode.db             # SQLite database (auto-created on first run)
├── static/
│   ├── assets/             # Static assets
│   └── fonts/              # Custom font files
├── cache/                  # Temporary file storage (pre-scan, auto-created)
├── uploads/                # Permanent safe file storage (post-scan, auto-created)
└── venv/                   # Python virtual environment (not committed to version control)
```

---

## Requirements

- Python 3.10 or later
- A VirusTotal API key (free tier available at https://www.virustotal.com)
- Internet access (for VirusTotal API calls)

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/shanzal-vitb/dropnode.git
cd dropnode
```

### 2. Create and activate a virtual environment

It is strongly recommended to run DropNode inside a Python virtual environment to avoid dependency conflicts.

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**Windows (PowerShell):**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

You should see `(venv)` prefixed in your terminal prompt once the environment is active.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set your VirusTotal API key

Get a free API key from https://www.virustotal.com/gui/my-apikey after registering.

**Option A — Environment variable (recommended):**

Linux / macOS:
```bash
export VT_API_KEY="your_api_key_here"
```

Windows (Command Prompt):
```cmd
set VT_API_KEY=your_api_key_here
```

Windows (PowerShell):
```powershell
$env:VT_API_KEY="your_api_key_here"
```

**Option B — Edit `app.py` directly:**

Open `app.py` and replace the placeholder on line 20:
```python
VIRUSTOTAL_API_KEY = 'your_api_key_here'
```

### 5. Run the application

```bash
python app.py
```

The server starts on http://localhost:5000 in debug mode. Open that URL in your browser.

To deactivate the virtual environment when done:
```bash
deactivate
```

---

## How It Works

### Upload

The file is sent to the `/upload` endpoint via an XHR request with real-time progress tracking. It is saved to the `cache/` directory and its SHA-256 and MD5 hashes are computed immediately. File metadata (name, size, type, hashes) is displayed to the user before scanning begins.

### Scan

On user confirmation, the file is submitted to the VirusTotal API v3 (`/files` endpoint). The backend polls the analysis endpoint until a result is ready, then aggregates the engine verdicts into a single result object containing:

- Threat status (Clean / Suspicious / Malicious)
- Risk score (0–100) and risk badge (Low / Medium / High)
- Detection ratio (flagged engines / total engines)
- Malware signature name and threat category
- List of flagging engines
- Full file metadata from VirusTotal (MIME type, file type, publisher, certificate validity)

A unique 20-character uppercase alphanumeric Drop ID is generated for each scan and stored in the database.

### Result Disposition

| Verdict | Action |
|---------|--------|
| Safe | File is moved from `cache/` to `uploads/`. Download becomes available. |
| Unsafe | File remains in `cache/` and is scheduled for deletion after **3 minutes**. Download is disabled. |

The deletion is handled by a background daemon thread. The timer starts at the moment of the first scan and is never reset, even if the file is re-scanned. The frontend chip updates in real-time from "File will be deleted in 3 minutes" to "File has been deleted" once the timer expires.

### Search

Past scans can be retrieved by Drop ID or filename via the search bar. Results are fetched from the SQLite database and persist across server restarts.

### Report

A full HTML scan report can be downloaded at any time for any scan result, referenced by Drop ID or filename. The report includes all scan metadata, engine results, and file hashes.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serves the main web UI |
| POST | `/upload` | Receives a file, saves it to `cache/`, returns hashes and metadata |
| POST | `/scan` | Submits cached file to VirusTotal, returns full scan result |
| GET | `/file-status?filename=<name>` | Returns real-time deletion status for a cached file (`pending`, `seconds_remaining`, `exists`) |
| GET | `/search?q=<query>` | Searches scan history by Drop ID or filename (up to 20 results) |
| GET | `/download/<filename>` | Downloads a safe file from `uploads/` |
| GET | `/report/<upload_id>` | Downloads a full HTML scan report by Drop ID or filename |

---

## Database Schema

Scan results are stored in `dropnode.db` (SQLite). The `scan_results` table schema:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incremented primary key |
| `upload_id` | TEXT | Unique 20-character Drop ID |
| `filename` | TEXT | Sanitized filename |
| `is_safe` | INTEGER | 1 = safe, 0 = unsafe |
| `threat_status` | TEXT | Clean / Suspicious / Malicious |
| `risk_score` | INTEGER | 0–100 |
| `risk_badge` | TEXT | Low / Medium / High |
| `detection_ratio` | TEXT | e.g. "3/72" |
| `engines_scanned` | INTEGER | Total AV engines queried |
| `malware_signature` | TEXT | Signature name from flagging engine |
| `threat_category` | TEXT | Detection method / category |
| `flagged_engines` | TEXT | JSON array of engine names |
| `file_type` | TEXT | Human-readable file type |
| `file_size` | INTEGER | Size in bytes |
| `mime_type` | TEXT | MIME / type tag from VirusTotal |
| `sha256` | TEXT | SHA-256 hash |
| `md5` | TEXT | MD5 hash |
| `digital_signature` | TEXT | Signature validity status |
| `publisher` | TEXT | Publisher subject from cert info |
| `cert_validity` | TEXT | Valid / Not Signed / Unverified |
| `file_created` | TEXT | File creation timestamp |
| `last_modified` | TEXT | File modification timestamp |
| `scan_timestamp` | TEXT | UTC timestamp of scan |
| `created_at` | TEXT | DB row creation timestamp |

---

## Limits and Constraints

- Maximum file size: **650 MB**
- VirusTotal free tier: **4 requests per minute**, **500 per day**
- Large files may take up to 5 minutes to finish scanning (VirusTotal queues them server-side)
- Unsafe files are deleted from `cache/` **3 minutes** after the first scan completes
- The deletion timer is non-resettable — re-scanning an unsafe file does not extend the window
- Scan history persists across restarts (SQLite-backed)
- The `cache/` and `uploads/` directories are created automatically on first run

---

## Security Notes

- Filenames are sanitized using `werkzeug.utils.secure_filename` before being written to disk
- SHA-256 and MD5 hashes are computed locally with Python's `hashlib` before any VirusTotal submission
- Unsafe files are isolated in `cache/` and never moved to `uploads/`; they are deleted by a daemon thread after 3 minutes
- Downloads are gated: the `/download/<filename>` endpoint verifies the file's `is_safe` status in the database before serving it
- VirusTotal API v3 is used for multi-engine scanning across 70+ antivirus engines

---

## Screenshots

<p align="center">
  <img src="/static/readme/landing.png" alt="Screenshot 1 — Landing Page" width="100%" />
  <br/><em>Landing Page</em>
</p>

<p align="center">
  <img src="/static/readme/scan-area.png" alt="Screenshot 2 — Drop area" width="100%" />
  <br/><em>Drop area</em>
</p>

<p align="center">
  <img src="/static/readme/file-upload.png" alt="Screenshot 3 — File Uploaded" width="100%" />
  <br/><em>File Uploaded</em>
</p>

<p align="center">
  <img src="/static/readme/scan-progress.png" alt="Screenshot 4 — Scanning in Progress" width="100%" />
  <br/><em>Scanning in Progress</em>
</p>

<p align="center">
  <img src="/static/readme/safe.png" alt="Screenshot 5 — Safe File Result" width="100%" />
  <br/><em>Safe File Result</em>
</p>

<p align="center">
  <img src="/static/readme/unsafe.png" alt="Screenshot 6 — Unsafe Or Malicious File Result" width="100%" />
  <br/><em>Unsafe Or Malicious File Result</em>
</p>

<p align="center">
  <img src="/static/readme/search.png" alt="Screenshot 7 — Search & Drop ID Lookup" width="100%" />
  <br/><em>Search and Drop ID Lookup</em>
</p>

<p align="center">
  <img src="/static/readme/footer.png" alt="Screenshot 8 — Footer" width="100%" />
  <br/><em>Footer</em>
</p>

---

## Development Notes

- The app runs with Flask's built-in development server (`debug=True`) on port 5000. For production deployment, use a WSGI server such as Gunicorn behind a reverse proxy (Nginx or Caddy).
- Scan results use `INSERT OR REPLACE` so re-scanning a file with the same Drop ID updates the existing row.
- The deletion registry (`_pending_deletions`) is in-memory. If the server is restarted while a deletion is pending, the timer is lost and the file will remain in `cache/` until manually removed.
- The Drop ID is generated independently of VirusTotal's `analysis_id` — it is a local 20-character alphanumeric identifier unique within the local database.
