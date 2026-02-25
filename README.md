<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/dropnode.svg" alt="DropNode Logo" width="180" />
</p>

<h1 align="center">DropNode — Secure File Upload Portal</h1>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/0neHackers.svg" alt="OneHackers Logo" width="120" />
  <br/><br/>
  Built by <strong>OneHackers</strong> for Cyber Carnival 2K26 | VIT-B<br/>
  Team: <a href="https://github.com/shanzal-vitb/" target="_blank"><img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="20" style="vertical-align: middle;" /></a> Shanzal Firoz (Lead), <a href="https://github.com/navni25bey10011-sys" target="_blank"><img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="20" style="vertical-align: middle;" /></a> Navni Danwani, <a href="https://github.com/Sinflin" target="_blank"><img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="20" style="vertical-align: middle;" /></a> Aditya Vishwakarma
</p>

---

> [!WARNING]
> **Do Not `git clone` This Repository.**
> The GitHub repository (`github.com/shanzal-vitb/dropnode`) is connected to the **live web demo** and may contain dev artifacts or demo-specific changes not intended for self-hosted use. Always download source from the **[Releases](https://github.com/shanzal-vitb/dropnode/releases)** page instead.

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
├── .api_key                # Persisted VT API key (chmod 600, auto-created by Set API modal)
├── dropnode.db             # SQLite database (auto-created on first run)
├── static/
│   ├── assets/             # SVG icons and logos (file-based / CDN URL references)
│   └── fonts/              # Custom font files (SamsungSharpSans, PPSupplySans)
├── cache/                  # Temporary file storage (pre-scan, auto-created)
├── uploads/                # Permanent safe file storage (post-scan, auto-created)
├── demo/                   # Demo build — same codebase + warning banner [V1.1]
└── venv/                   # Python virtual environment (not committed to version control)
```

---

## Requirements

- Python 3.10 or later
- A VirusTotal API key (free tier available at https://www.virustotal.com)
- Internet access (for VirusTotal API calls)

---

## Setup

### 1. Download from Releases

> [!IMPORTANT]
> Do **not** `git clone` this repository. Download the latest source archive from the **[Releases](https://github.com/shanzal-vitb/dropnode/releases)** page.

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

**Option B — In-browser via "Set API" modal (V1.1):**

Start the app, then click **"Set API"** in the header nav. Enter your key in the popup — it is saved to `.api_key` (chmod 600) and persists across server restarts. No restart required.

**Option C — Edit `app.py` directly:**

Open `app.py` and replace the placeholder on the relevant line:
```python
VIRUSTOTAL_API_KEY = 'your_api_key_here'
```

Key resolution order: `.api_key` file → `VT_API_KEY` env var → hardcoded value in `app.py`.

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

A full HTML scan report can be downloaded at any time for any scan result, referenced by Drop ID or filename. The report includes all scan metadata, engine results, and file hashes — styled with the same custom fonts as the main webapp.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serves the main web UI |
| POST | `/upload` | Receives a file, saves it to `cache/`, returns hashes and metadata |
| POST | `/scan` | Submits cached file to VirusTotal, returns full scan result |
| GET | `/file-status?filename=<name>` | Returns real-time deletion status for a cached file (`pending`, `seconds_remaining`, `exists`) |
| GET | `/search?q=<query>` | Searches scan history by Drop ID or filename (up to 20 results) |
| GET | `/download/<filename>` | Downloads a safe file from `uploads/`; returns **410 Gone** if `file_deleted=1` |
| GET | `/report/<upload_id>` | Downloads a full HTML scan report by Drop ID or filename |
| POST | `/set-api-key` | **[V1.1]** Accepts VT API key at runtime; persists to `.api_key` (chmod 600) |
| POST | `/delete-file` | **[V1.1]** Removes physical file, sets `file_deleted=1`; preserves scan history |
| POST | `/delete-result` | **[V1.1]** Hard-purges: removes file AND DB row |
| POST | `/cleanup-cache` | **[V1.1]** Beacon endpoint; cleans orphaned `cache/` files on page unload |

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
| `file_deleted` | INTEGER | **[V1.1]** 1 if file manually deleted; 0 otherwise |

---

## Limits and Constraints

| Constraint | Value |
|------------|-------|
| Maximum file size | 650 MB |
| VirusTotal free tier rate limit | 4 req/min, 500/day |
| Unsafe file auto-deletion | 180 seconds after first scan |
| Large file scan time | Up to 5 minutes (VirusTotal queue) |
| Search results returned | Up to 20 per query |
| Drop ID length | 20 chars, uppercase alphanumeric |

---

## Security Notes

- Filenames are sanitized using `werkzeug.utils.secure_filename` before being written to disk — applied at all endpoints including the new V1.1 deletion endpoints.
- SHA-256 and MD5 hashes are computed locally with Python's `hashlib` before any VirusTotal submission.
- The `.api_key` file is written with `chmod 0o600` (owner-read-only) — no world-readable API key exposure.
- Unsafe files are isolated in `cache/` and never moved to `uploads/`; they are deleted by a daemon thread after 3 minutes.
- `/download/<filename>` checks both `is_safe` and `file_deleted` before serving; returns **410 Gone** for manually deleted files.
- VirusTotal API v3 provides multi-engine scanning across 70+ antivirus engines.
- `/cleanup-cache` refuses to delete files already on the auto-delete timer — prevents timer bypass via the beacon endpoint.

---

## V1.1 Changelog

### Backend (`app.py`)

- `[NEW]` **#1** — `/set-api-key` POST endpoint: accepts VirusTotal API key at runtime, no restart required.
- `[NEW]` `_load_api_key()` — three-tier cascade: `.api_key` file → `VT_API_KEY` env var → hardcoded fallback.
- `[SEC]` API key persisted to `.api_key` with `chmod 0o600` (owner-read-only).
- `[NEW]` **#4** — `/delete-file`: removes physical file from `uploads/`, sets `file_deleted=1` in DB, preserves scan history.
- `[NEW]` **#4** — `/delete-result`: hard-purges file from `uploads/` or `cache/` AND deletes the DB row.
- `[NEW]` **#16** — `/cleanup-cache`: `sendBeacon` endpoint; cleans orphaned `cache/` files on page unload; skips files already on the auto-delete timer.
- `[NEW]` **#16** — `_startup_cache_sweep()`: runs at import time; clears all orphaned `cache/` files from crashed or reloaded sessions.
- `[NEW]` `file_deleted` column (`INTEGER DEFAULT 0`) added to `scan_results` table.
- `[UPD]` Zero-downtime DB migration: `ALTER TABLE ADD COLUMN file_deleted` runs automatically on existing DBs.
- `[UPD]` `save_result()` and `row_to_dict()` read/write `file_deleted`; exposed as boolean in all API JSON responses.
- `[FIX]` **#7** — `/download/<filename>` returns HTTP **410 Gone** when `file_deleted=1`.
- `[FIX]` `schedule_delete()` is idempotent — re-scan cannot reset an already-running deletion timer.
- `[UPD]` DB connections use Flask `g` context via `get_db()`/`close_db()`, preventing connection leaks.
- `[SEC]` `secure_filename` (werkzeug) applied at all new deletion endpoints.

### Frontend — New Features (`index.html`)

- `[NEW]` **#1** — "Set API" item added to desktop header nav (right of About) and mobile hamburger menu.
- `[NEW]` **#1** — Clicking "Set API" opens a blurred-background popup with smooth fade+scale animation.
- `[NEW]` **#1** — Password-type input with eye-toggle; tick-button in `--accent` colour submits via `submitApiKey()`.
- `[NEW]` **#1** — On success: modal closes with reverse animation; success snackbar: "API key has been saved & Applied."
- `[NEW]` **#1** — Modal dismisses on backdrop click and Escape key; input cleared after successful submission.
- `[NEW]` **#4** — Delete button added right of Re-Scan in the results area.
- `[NEW]` **#4** — Delete confirmation popup: "Delete File & Result" and "Delete File Only" for SAFE files.
- `[NEW]` **#4** — UNSAFE delete popup: shows "Delete Result" only + note "File will be deleted in 3 mins automatically."
- `[NEW]` **#5** — Download File button repositioned to immediately right of the Delete button.
- `[NEW]` **#21** — Demo build warning banner for `demo/` build.
- `[NEW]` **#4 / #30** — Re-Scan button disabled with hover/tap tooltip when file manually deleted: "The file has been deleted by the user, re-upload it to re-scan."
- `[NEW]` `crossDissolvePanel(data)` — fade-out/update/fade-in animation for smooth in-place re-scan panel updates.
- `[NEW]` `sendBeacon /cleanup-cache` fires on `beforeunload`, preventing orphaned temp files in `cache/`.
- `[NEW]` Dedicated Search modal overlay with scoped clickable result cards.
- `[NEW]` `showSnack({type, message, buttonLabel, onButton, duration})` — unified toast system with stacking, auto-dismiss, and action buttons.

### Frontend — Bug Fixes (`index.html`)

- `[FIX]` **#8** — System status pill no longer flashes "Checking..." every 10 s during keep-alive ping. "Checking" (yellow) only shown during genuine online ↔ offline transition.
- `[FIX]` **#7** — Download button on search result cards no longer triggers the active scan result's download; scoped to each card's own Drop ID.
- `[FIX]` **#29** — "Delete File Only" button disabled immediately after use; prevents repeated snackbar loop.
- `[FIX]` **#10** — Unsafe delete popup note updates from "File will be deleted in 3 mins" → "File has been deleted automatically." in real-time when the timer fires.
- `[FIX]` **#16** — Files in `cache/` after a mid-scan page reload are cleaned up on page unload via `sendBeacon`.
- `[FIX]` Module-level `scanIntervalId` and `deleteTimer` prevent duplicate polling loops across re-scan attempts.
- `[FIX]` `resetAll()` correctly clears all timers, intervals, XHR refs, and UI state on new upload.
- `[FIX]` **#28** — Drop ID search box now centred correctly in the nav header.

### UI / UX Updates

- `[UPD]` **#2** — Tagline: "The node that protects" → "The node that protects." (full stop added).
- `[UPD]` **#17** — Upload area heading: "Secure File Portal" → "Secure File Upload Portal".
- `[UPD]` **#13** — Nav label and popup heading: "Settings" → "Set API" throughout.
- `[UPD]` **#13** — GitHub profile URLs for all three team members confirmed and updated in the footer.
- `[UPD]` **#13** — Build chip: `Build: Beta, V1.1 - 250226`.
- `[UPD]` **#3** — Mobile brand logo `clamp()` minimum value increased for better small-screen legibility.
- `[UPD]` **#6** — System status pill: yellow colour while in "Checking..." state.
- `[UPD]` **#13** — Status pill text and size slightly reduced for a cleaner footer.
- `[UPD]` **#9** — Delete confirmation popup buttons sized relative to text content for uniform appearance.
- `[UPD]` **#11** — Buttons in the upload/scanning area wrap to left-aligned on narrow screens.
- `[UPD]` **#12** — Buttons in the results area wrap to left-aligned on narrow screens.
- `[UPD]` **#15** — Inline SVGs reverted to file-based / CDN URL references for easier maintenance.
- `[UPD]` **#18** — HTML scan report: custom fonts (SamsungSharpSans / PPSupplySans via CDN) match main webapp.
- `[UPD]` **#19** — HTML report generator updated to include the live DropNode webapp link.
- `[UPD]` **#30** — After file-only deletion (safe file): "Delete File & Result" relabels to "Result Only".
- `[UPD]` **#30** — Note "The file has been deleted by the user." appears below action description after file-only deletion.

### Demo Build

- `[NEW]` **#14** — Separate `demo/` folder created inside the V1.1 production directory:
  - **#21** — Warning banner about demo usage and public file exposure risk.
  - **#22** — Build chip: `Build: Beta, V1.1 - 250226_demo`
- `[UPD]` Demo warning committed to the `dropnode` main branch alongside all V1.1 changes.

---

## Demo Video

<video src="https://raw.githubusercontent.com/shanzal-vitb/dropnode/main/static/readme/Dropnode_V1.1_Demo.mp4" controls width="100%" style="border-radius:10px;"></video>

---

## Screenshots

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/landing.png" alt="Screenshot 1 — Landing Page" width="100%" />
  <br/><em>Landing Page</em>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/drop-area.png" alt="Screenshot 2 — Drop area" width="100%" />
  <br/><em>Drop area</em>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/set-api.png" alt="Screenshot 2 — User API Key" width="100%" />
  <br/><em>User API Key</em>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/file-uploading.png" alt="Screenshot 2 — File Uploading" width="100%" />
  <br/><em>File Uploading</em>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/uploaded-file.png" alt="Screenshot 3 — File Uploaded" width="100%" />
  <br/><em>File Uploaded</em>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/readme/scanning-file.png" alt="Screenshot 4 — File Scanning" width="100%" />
  <br/><em>File Scanning</em>
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

- The app runs with Flask's built-in development server (`debug=True`) on port 5000. For production, use Gunicorn behind a reverse proxy (Nginx or Caddy).
- Scan results use `INSERT OR REPLACE` so re-scanning a file with the same Drop ID updates the existing row.
- The deletion registry (`_pending_deletions`) is in-memory. If the server restarts mid-timer, the timer is lost — the file will remain in `cache/` until the next startup sweep (`_startup_cache_sweep()`) clears it.
- The `.api_key` file takes precedence over the `VT_API_KEY` environment variable, which in turn takes precedence over the hardcoded value in `app.py`.
- The Drop ID is generated independently of VirusTotal's `analysis_id` — it is a local 20-character alphanumeric identifier unique within the local database.
