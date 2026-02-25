import os
import hashlib
import json
import threading
import time
import sqlite3
import random
import string
import shutil
import requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_file, Response, g
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB

CACHE_FOLDER  = 'cache'
UPLOAD_FOLDER = 'uploads'
DB_PATH       = 'dropnode.db'
_API_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.api_key')

def _load_api_key() -> str:
    """Load API key: disk file → env var → hardcoded default."""
    if os.path.exists(_API_KEY_FILE):
        try:
            key = open(_API_KEY_FILE).read().strip()
            if key:
                return key
        except OSError:
            pass
    return os.environ.get('VIRUSTOTAL_API_KEY')

VIRUSTOTAL_API_KEY = _load_api_key()
VT_API_URL    = 'https://www.virustotal.com/api/v3'

os.makedirs(CACHE_FOLDER,  exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── DELETION REGISTRY ─────────────────────────────────────────────────────────
# Maps absolute cache filepath → unix timestamp when schedule_delete was first called.
# Thread-safe via _del_lock. Single source of truth for pending deletions.
_pending_deletions: dict = {}   # { filepath: scheduled_at_float }
_del_lock = threading.Lock()


# ── SCAN ID GENERATOR ─────────────────────────────────────────────────────────

def generate_drop_id() -> str:
    """Generate a unique 20-character uppercase alphanumeric Drop ID."""
    alphabet = string.ascii_uppercase + string.digits  # A-Z + 0-9
    return ''.join(random.choices(alphabet, k=20))


def unique_drop_id(db_con) -> str:
    """Keep generating until we get one that doesn't already exist in DB."""
    while True:
        did = generate_drop_id()
        row = db_con.execute(
            'SELECT 1 FROM scan_results WHERE upload_id = ?', (did,)
        ).fetchone()
        if not row:
            return did


# ── DATABASE ──────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_id         TEXT    UNIQUE NOT NULL,
                filename          TEXT    NOT NULL,
                is_safe           INTEGER NOT NULL,
                threat_status     TEXT,
                risk_score        INTEGER,
                risk_badge        TEXT,
                detection_ratio   TEXT,
                engines_scanned   INTEGER,
                malware_signature TEXT,
                threat_category   TEXT,
                flagged_engines   TEXT,
                file_type         TEXT,
                file_size         INTEGER,
                mime_type         TEXT,
                sha256            TEXT,
                md5               TEXT,
                digital_signature TEXT,
                publisher         TEXT,
                cert_validity     TEXT,
                file_created      TEXT,
                last_modified     TEXT,
                scan_timestamp    TEXT,
                file_deleted      INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT DEFAULT (datetime('now'))
            )
        ''')
        # Migrate existing DBs that don't yet have file_deleted column
        try:
            con.execute('ALTER TABLE scan_results ADD COLUMN file_deleted INTEGER NOT NULL DEFAULT 0')
        except Exception:
            pass
        con.commit()

init_db()


# ── STARTUP CACHE SWEEP ───────────────────────────────────────────────────────
# On server start, delete any orphaned files left in cache/ that are NOT
# part of an active pending-deletion timer (e.g. files stranded by a page
# reload while a scan was still running, or by a previous crash).
def _startup_cache_sweep():
    """Delete cache files that have no associated pending-deletion entry."""
    try:
        for fname in os.listdir(CACHE_FOLDER):
            fpath = os.path.abspath(os.path.join(CACHE_FOLDER, fname))
            with _del_lock:
                is_registered = fpath in _pending_deletions
            if not is_registered:
                try:
                    os.remove(fpath)
                except OSError:
                    pass
    except OSError:
        pass

_startup_cache_sweep()


def save_result(result: dict):
    with sqlite3.connect(DB_PATH) as con:
        con.execute('''
            INSERT OR REPLACE INTO scan_results (
                upload_id, filename, is_safe, threat_status, risk_score,
                risk_badge, detection_ratio, engines_scanned, malware_signature,
                threat_category, flagged_engines, file_type, file_size, mime_type,
                sha256, md5, digital_signature, publisher, cert_validity,
                file_created, last_modified, scan_timestamp, file_deleted
            ) VALUES (
                :upload_id, :filename, :is_safe, :threat_status, :risk_score,
                :risk_badge, :detection_ratio, :engines_scanned, :malware_signature,
                :threat_category, :flagged_engines, :file_type, :file_size, :mime_type,
                :sha256, :md5, :digital_signature, :publisher, :cert_validity,
                :file_created, :last_modified, :scan_timestamp, :file_deleted
            )
        ''', {**result, 'flagged_engines': json.dumps(result.get('flagged_engines', [])),
               'file_deleted': result.get('file_deleted', 0)})
        con.commit()


def row_to_dict(row):
    d = dict(row)
    d['is_safe']      = bool(d['is_safe'])
    d['file_deleted'] = bool(d.get('file_deleted', 0))
    try:
        d['flagged_engines'] = json.loads(d.get('flagged_engines') or '[]')
    except Exception:
        d['flagged_engines'] = []
    return d


# ── FILE MOVE HELPERS ─────────────────────────────────────────────────────────

def move_to_uploads(cache_path: str, filename: str) -> bool:
    """
    Move a verified-safe file from cache/ to uploads/ immediately.
    Returns True on success, False if something went wrong.
    """
    dest = os.path.join(UPLOAD_FOLDER, filename)
    try:
        os.rename(cache_path, dest)
        return True
    except OSError:
        # Fallback: copy then delete (handles cross-device moves)
        try:
            shutil.copy2(cache_path, dest)
            os.remove(cache_path)
            return True
        except Exception:
            return False


def schedule_delete(filepath: str, delay: int = 180) -> bool:
    """Schedule an unsafe cached file for deletion after `delay` seconds.
    Idempotent: if already scheduled, returns False immediately — timer is NOT reset.
    Returns True only the first time a deletion thread is actually spawned.
    """
    abs_path = os.path.abspath(filepath)
    with _del_lock:
        if abs_path in _pending_deletions:
            return False                        # already scheduled — do not touch timer
        _pending_deletions[abs_path] = time.time()

    def _worker():
        time.sleep(delay)
        try:
            if os.path.exists(abs_path):
                os.remove(abs_path)
        except OSError:
            pass
        finally:
            with _del_lock:
                _pending_deletions.pop(abs_path, None)

    t = threading.Thread(target=_worker, daemon=True, name=f'del:{os.path.basename(abs_path)}')
    t.start()
    return True


def get_deletion_status(filepath: str):
    """Return (is_pending: bool, seconds_remaining: int|None) for a file."""
    abs_path = os.path.abspath(filepath)
    with _del_lock:
        scheduled_at = _pending_deletions.get(abs_path)
    if scheduled_at is None:
        return False, None
    elapsed   = time.time() - scheduled_at
    remaining = max(0, int(180 - elapsed))
    return True, remaining


# ── REPORT BUILDER ────────────────────────────────────────────────────────────

def build_report_html(result: dict) -> str:
    safe_color = '#16a34a' if result['is_safe'] else '#dc2626'
    safe_text  = 'SAFE — Uploaded to Server' if result['is_safe'] else 'UNSAFE — File Not Uploaded'
    flagged    = result.get('flagged_engines', [])
    flagged_html = ''.join(f'<li>{e}</li>' for e in flagged) if flagged else '<li>None</li>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DropNode Drop Report — {result['filename']}</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Google+Sans+Flex:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
<style>
  /* ── CUSTOM FONTS (matching main webapp) ── */
  @font-face{{font-family:'SamsungSharpSans';src:url('https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/fonts/SamsungSharpSans-Bold.otf') format('opentype');font-weight:700;font-display:swap}}
  @font-face{{font-family:'PPSupplySans';src:url('https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/fonts/PPSupplySans-Ultralight.otf') format('opentype');font-weight:200;font-display:swap}}
  @font-face{{font-family:'PPSupplySans';src:url('https://cdn.jsdelivr.net/gh/shanzal-vitb/dropnode@master/static/fonts/PPSupplySans-Regular.otf') format('opentype');font-weight:400;font-display:swap}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Google Sans Flex',system-ui,sans-serif;font-weight:400;background:#0f0f0f;color:#e5e5e5;padding:40px}}
  .container{{max-width:860px;margin:0 auto}}
  .header{{border-bottom:2px solid #222;padding-bottom:28px;margin-bottom:32px}}
  .header-brand{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:28px}}
  .brand-dropnode{{font-family:'SamsungSharpSans','Arial Black',system-ui,sans-serif;font-weight:700;font-size:28px;letter-spacing:-0.5px;color:#00e5b0;line-height:1}}
  .brand-dot{{color:#fff;margin:0 6px;font-size:24px}}
  .brand-onehackers{{font-family:'PPSupplySans',system-ui,sans-serif;font-size:26px;font-weight:200;background:linear-gradient(90deg,#38BDF8,#818CF8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1}}
  .brand-onehackers strong{{font-weight:400}}
  .header-file{{margin-top:4px}}
  .filename{{font-family:'Google Sans Flex',system-ui,sans-serif;font-size:36px;font-weight:700;letter-spacing:-0.5px;color:#f0f0f0;line-height:1.15;word-break:break-all;margin-bottom:12px}}
  .badge{{display:inline-block;padding:6px 14px;border-radius:999px;font-size:13px;font-weight:600;background:{safe_color}22;color:{safe_color};border:1px solid {safe_color}44}}
  .section{{margin-bottom:28px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:24px}}
  h2{{font-family:'Google Sans Flex',system-ui,sans-serif;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:2px;color:#888;margin-bottom:16px}}
  .row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #2a2a2a;font-size:14px}}
  .row:last-child{{border-bottom:none}}
  .label{{color:#888;font-weight:400}}
  .value{{color:#e5e5e5;font-weight:400;max-width:60%;text-align:right;word-break:break-all}}
  .drop-id{{font-family:'Space Mono',monospace;font-size:15px;font-weight:700;letter-spacing:0.12em;color:#00e5b0}}
  .copy-btn{{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:4px;border:1px solid rgba(0,229,176,0.3);background:rgba(0,229,176,0.08);color:#00e5b0;cursor:pointer;transition:background 0.15s,border-color 0.15s;vertical-align:middle;margin-right:8px;flex-shrink:0}}
  .copy-btn:hover{{background:rgba(0,229,176,0.2);border-color:rgba(0,229,176,0.6)}}
  #snack{{position:fixed;bottom:24px;right:24px;background:#001a0e;border:1px solid rgba(34,197,94,0.35);color:#4ade80;padding:12px 18px;border-radius:10px;font-size:13px;font-family:'Google Sans Flex',system-ui,sans-serif;box-shadow:0 8px 32px rgba(0,0,0,0.5);opacity:0;transform:translateY(8px);transition:opacity 0.25s ease,transform 0.25s ease;pointer-events:none;max-width:360px;line-height:1.5}}
  .flagged{{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;padding:12px;margin-top:8px}}
  .flagged li{{font-size:13px;color:#f87171;padding:3px 0;list-style:none;padding-left:12px}}
  .footer{{text-align:center;color:#555;font-size:12px;margin-top:40px;padding-top:20px;border-top:1px solid #2a2a2a;font-family:'Google Sans Flex',system-ui,sans-serif}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <!-- Top row: dropnode left, OneHackers right -->
    <div class="header-brand">
      <a href="https://dropnode.up.railway.app/" target="_blank" style="text-decoration:none;" class="brand-dropnode">dropnode</a>
      <span class="brand-onehackers"><span style="font-weight:200;">0ne</span><strong>Hackers</strong></span>
    </div>
    <!-- Filename + badge below both logos -->
    <div class="header-file">
      <p class="filename">{result['filename']}</p>
      <span class="badge">{safe_text}</span>
    </div>
  </div>

  <div class="section">
    <h2>Overall Summary</h2>
    <div class="row"><span class="label">Threat Status</span><span class="value">{result['threat_status']}</span></div>
    <div class="row"><span class="label">Overall Risk Score</span><span class="value">{result['risk_score']}/100</span></div>
    <div class="row"><span class="label">Risk Badge</span><span class="value">{result['risk_badge']}</span></div>
  </div>

  <div class="section">
    <h2>Threat &amp; Detection</h2>
    <div class="row"><span class="label">Detection Ratio</span><span class="value">{result['detection_ratio']} flagged</span></div>
    <div class="row"><span class="label">Engines Scanned</span><span class="value">{result['engines_scanned']}</span></div>
    <div class="row"><span class="label">Malware Signature</span><span class="value">{result['malware_signature']}</span></div>
    <div class="row"><span class="label">Threat Category</span><span class="value">{result['threat_category']}</span></div>
    <div class="row" style="flex-direction:column">
      <span class="label" style="margin-bottom:8px">Flagged Engines</span>
      <ul class="flagged">{flagged_html}</ul>
    </div>
  </div>

  <div class="section">
    <h2>File Info</h2>
    <div class="row"><span class="label">File Type</span><span class="value">{result['file_type']}</span></div>
    <div class="row"><span class="label">File Size</span><span class="value">{result['file_size']:,} bytes</span></div>
    <div class="row"><span class="label">MIME Type</span><span class="value">{result['mime_type']}</span></div>
  </div>

  <div class="section">
    <h2>File Integrity</h2>
    <div class="row"><span class="label">SHA-256</span><span class="value" style="font-size:11px;font-family:monospace">{result['sha256']}</span></div>
    <div class="row"><span class="label">MD5</span><span class="value" style="font-size:11px;font-family:monospace">{result['md5']}</span></div>
    <div class="row"><span class="label">Digital Signature</span><span class="value">{result['digital_signature']}</span></div>
    <div class="row"><span class="label">Publisher</span><span class="value">{result['publisher']}</span></div>
    <div class="row"><span class="label">Certificate Validity</span><span class="value">{result['cert_validity']}</span></div>
  </div>

  <div class="section">
    <h2>File Metadata</h2>
    <div class="row"><span class="label">File Creation Date</span><span class="value">{result['file_created']}</span></div>
    <div class="row"><span class="label">Last Modified Date</span><span class="value">{result['last_modified']}</span></div>
  </div>

  <div class="section">
    <h2>Scan Info</h2>
    <div class="row"><span class="label">Scan Timestamp</span><span class="value">{result['scan_timestamp']}</span></div>
    <div class="row" style="align-items:center;"><span class="label">Drop ID</span><span class="value" style="display:flex;align-items:center;justify-content:flex-end;gap:0;"><button class="copy-btn" onclick="copyId()" title="Copy Drop ID" id="copy-btn"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button><span class="drop-id" id="drop-id-val">{result['upload_id']}</span></span></div>
  </div>

  <div class="footer">
    <p>Generated by <a href="https://dropnode.up.railway.app/" target="_blank" style="color:#00e5b0;text-decoration:none;">dropnode</a> · OneHackers &nbsp;|&nbsp; Made for Cyber Carnival 2K26 | VIT-B</p>
    <p style="margin-top:4px">Copyright © 2026, <a href="https://dropnode.up.railway.app/" target="_blank" style="color:#555;text-decoration:none;">dropnode</a>, All Rights Reserved</p>
  </div>
</div>

<div id="snack"></div>
<script>
  function copyId() {{
    var id = document.getElementById('drop-id-val').textContent.trim();
    var btn = document.getElementById('copy-btn');
    navigator.clipboard.writeText(id).then(function() {{
      var snack = document.getElementById('snack');
      snack.innerHTML = '<strong>Copied!</strong><br>Drop ID: <span style="font-family:monospace;letter-spacing:0.08em;">' + id + '</span>';
      snack.style.opacity = '1';
      snack.style.transform = 'translateY(0)';
      btn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
      btn.style.background = 'rgba(0,229,176,0.25)';
      btn.style.borderColor = 'rgba(0,229,176,0.7)';
      setTimeout(function() {{
        snack.style.opacity = '0';
        snack.style.transform = 'translateY(8px)';
        btn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
        btn.style.background = 'rgba(0,229,176,0.08)';
        btn.style.borderColor = 'rgba(0,229,176,0.3)';
      }}, 3000);
    }}).catch(function() {{
      alert('Failed to copy Drop ID.');
    }});
  }}
</script>
</body>
</html>"""


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    # Serve index.html from the project root (same directory as app.py),
    # not from the templates/ subfolder.
    here = os.path.dirname(os.path.abspath(__file__))
    return send_file(os.path.join(here, 'index.html'))


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    filename   = secure_filename(file.filename)
    cache_path = os.path.join(CACHE_FOLDER, filename)

    # Security: refuse to overwrite a file already scheduled for deletion
    is_pending, seconds_left = get_deletion_status(cache_path)
    if is_pending:
        return jsonify({
            'error': 'pending_deletion',
            'seconds_remaining': seconds_left
        }), 403

    file.save(cache_path)

    sha256, md5 = compute_hashes(cache_path)
    file_size   = os.path.getsize(cache_path)
    stat        = os.stat(cache_path)

    return jsonify({
        'success':  True,
        'filename': filename,
        'sha256':   sha256,
        'md5':      md5,
        'size':     file_size,
        'created':  datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
    })


@app.route('/scan', methods=['POST'])
def scan_file():
    data     = request.json or {}
    filename = data.get('filename')
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400

    cache_path    = os.path.join(CACHE_FOLDER,  secure_filename(filename))
    uploads_path  = os.path.join(UPLOAD_FOLDER, secure_filename(filename))
    from_uploads  = False   # tracks whether we copied FROM uploads/ for this scan

    # If the file is in uploads/ (previously scanned safe), COPY it to cache/ for re-scan.
    # We keep the uploads/ copy intact until we know the result:
    #   - safe again  → delete cache/ copy (uploads/ is the source of truth)
    #   - now unsafe  → delete uploads/ copy, schedule_delete on cache/ copy
    if not os.path.exists(cache_path) and os.path.exists(uploads_path):
        try:
            shutil.copy2(uploads_path, cache_path)
            from_uploads = True
        except Exception as e:
            return jsonify({'error': f'Could not copy file to cache for re-scan: {e}'}), 500

    if not os.path.exists(cache_path):
        return jsonify({'error': 'file_not_found'}), 404

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        with open(cache_path, 'rb') as f:
            vt_resp = requests.post(f'{VT_API_URL}/files', headers=headers,
                                    files={'file': (filename, f)}, timeout=60)

        # ── ConflictError: file already known to VT, fetch by hash ────────────
        if vt_resp.status_code != 200:
            if 'ConflictError' in vt_resp.text:
                sha256_tmp, _ = compute_hashes(cache_path)
                existing = requests.get(f'{VT_API_URL}/files/{sha256_tmp}',
                                        headers=headers, timeout=30)
                if existing.status_code == 200:
                    file_attrs   = existing.json().get('data', {}).get('attributes', {})
                    last_stats   = file_attrs.get('last_analysis_stats', {})
                    last_results = file_attrs.get('last_analysis_results', {})
                    stats        = last_stats
                    results      = last_results

                    malicious  = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total      = sum(stats.values())

                    flagged    = []
                    sig_name   = ''
                    threat_cat = ''
                    for engine, res in results.items():
                        if res.get('category') in ('malicious', 'suspicious'):
                            flagged.append(engine)
                            if res.get('result') and not sig_name:
                                sig_name = res['result']
                            if res.get('method') and not threat_cat:
                                threat_cat = res['method']

                    if malicious > 0:
                        threat_status = 'Malicious'
                        risk_score    = min(100, int((malicious / total) * 100) + 40) if total else 0
                        risk_badge    = 'High'
                        is_safe       = False
                    elif suspicious > 0:
                        threat_status = 'Suspicious'
                        risk_score    = min(60, int((suspicious / total) * 100) + 20) if total else 0
                        risk_badge    = 'Medium'
                        is_safe       = False
                    else:
                        threat_status = 'Clean'
                        risk_score    = 0
                        risk_badge    = 'Low'
                        is_safe       = True

                    sha256, md5 = compute_hashes(cache_path)
                    file_size   = os.path.getsize(cache_path)
                    stat        = os.stat(cache_path)
                    mime_type   = file_attrs.get('type_tag', 'unknown')
                    file_type   = file_attrs.get('type_description',
                                    filename.rsplit('.', 1)[-1].upper() if '.' in filename else 'Unknown')
                    sig_info    = file_attrs.get('signature_info', {})
                    publisher   = sig_info.get('subject', 'N/A')
                    cert_valid  = 'Valid' if sig_info.get('verified') == 'Signed' else 'Not Signed / Unverified'

                    # Generate our own Drop ID
                    with sqlite3.connect(DB_PATH) as tmp_con:
                        tmp_con.row_factory = sqlite3.Row
                        drop_id = unique_drop_id(tmp_con)

                    result = {
                        'upload_id':          drop_id,
                        'filename':           filename,
                        'is_safe':            is_safe,
                        'threat_status':      threat_status,
                        'risk_score':         risk_score,
                        'risk_badge':         risk_badge,
                        'detection_ratio':    f'{malicious + suspicious}/{total}',
                        'engines_scanned':    total,
                        'malware_signature':  sig_name   or 'None Detected',
                        'threat_category':    threat_cat or 'N/A',
                        'flagged_engines':    flagged,
                        'file_type':          file_type,
                        'file_size':          file_size,
                        'mime_type':          mime_type,
                        'sha256':             sha256,
                        'md5':                md5,
                        'digital_signature':  cert_valid,
                        'publisher':          publisher,
                        'cert_validity':      cert_valid,
                        'file_created':       datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                        'last_modified':      datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'scan_timestamp':     datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    }
                    save_result(result)

                    # Disposition based on result and where the file came from
                    if is_safe:
                        if from_uploads:
                            # File stays in uploads/; remove the cache/ copy we made
                            try: os.remove(cache_path)
                            except OSError: pass
                        else:
                            move_to_uploads(cache_path, filename)
                    else:
                        if from_uploads:
                            # Unsafe: delete the uploads/ original, schedule cache/ copy for deletion
                            try: os.remove(uploads_path)
                            except OSError: pass
                        schedule_delete(cache_path, 180)

                    return jsonify(result)

            return jsonify({'error': f'VirusTotal upload failed: {vt_resp.text}'}), 500

        # ── Normal flow: poll for analysis completion ─────────────────────────
        analysis_id = vt_resp.json()['data']['id']

        analysis_data = {}
        for _ in range(30):
            time.sleep(10)
            try:
                ar = requests.get(f'{VT_API_URL}/analyses/{analysis_id}',
                                  headers=headers, timeout=30)
                analysis_data = ar.json()
            except Exception:
                continue   # transient network error — keep polling
            status = analysis_data.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                break

        # Guard: if analysis never completed, return a clean timeout error
        attrs = analysis_data.get('data', {}).get('attributes', {})
        if attrs.get('status') != 'completed':
            return jsonify({'error': 'Scan timed out — VirusTotal did not complete analysis in time. Please try again.'}), 504
        stats      = attrs.get('stats', {})
        results    = attrs.get('results', {})
        malicious  = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total      = sum(stats.values())

        flagged    = []
        sig_name   = ''
        threat_cat = ''
        for engine, res in results.items():
            if res.get('category') in ('malicious', 'suspicious'):
                flagged.append(engine)
                if res.get('result') and not sig_name:
                    sig_name = res['result']
                if res.get('method') and not threat_cat:
                    threat_cat = res['method']

        if malicious > 0:
            threat_status = 'Malicious'
            risk_score    = min(100, int((malicious / total) * 100) + 40) if total else 0
            risk_badge    = 'High'
            is_safe       = False
        elif suspicious > 0:
            threat_status = 'Suspicious'
            risk_score    = min(60, int((suspicious / total) * 100) + 20) if total else 0
            risk_badge    = 'Medium'
            is_safe       = False
        else:
            threat_status = 'Clean'
            risk_score    = 0
            risk_badge    = 'Low'
            is_safe       = True

        sha256, md5 = compute_hashes(cache_path)
        file_size   = os.path.getsize(cache_path)
        stat        = os.stat(cache_path)

        file_report = {}
        try:
            fr = requests.get(f'{VT_API_URL}/files/{sha256}', headers=headers, timeout=30)
            if fr.status_code == 200:
                file_report = fr.json().get('data', {}).get('attributes', {})
        except Exception:
            pass

        mime_type  = file_report.get('type_tag', 'unknown')
        file_type  = file_report.get('type_description',
                       filename.rsplit('.', 1)[-1].upper() if '.' in filename else 'Unknown')
        sig_info   = file_report.get('signature_info', {})
        publisher  = sig_info.get('subject', 'N/A')
        cert_valid = 'Valid' if sig_info.get('verified') == 'Signed' else 'Not Signed / Unverified'

        # Generate our own Drop ID (ignore VT's analysis_id)
        with sqlite3.connect(DB_PATH) as tmp_con:
            tmp_con.row_factory = sqlite3.Row
            drop_id = unique_drop_id(tmp_con)

        result = {
            'upload_id':          drop_id,
            'filename':           filename,
            'is_safe':            is_safe,
            'threat_status':      threat_status,
            'risk_score':         risk_score,
            'risk_badge':         risk_badge,
            'detection_ratio':    f'{malicious + suspicious}/{total}',
            'engines_scanned':    total,
            'malware_signature':  sig_name   or 'None Detected',
            'threat_category':    threat_cat or 'N/A',
            'flagged_engines':    flagged,
            'file_type':          file_type,
            'file_size':          file_size,
            'mime_type':          mime_type,
            'sha256':             sha256,
            'md5':                md5,
            'digital_signature':  cert_valid,
            'publisher':          publisher,
            'cert_validity':      cert_valid,
            'file_created':       datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'last_modified':      datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'scan_timestamp':     datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        }

        save_result(result)

        # Disposition based on result and where the file came from
        if is_safe:
            if from_uploads:
                # File stays in uploads/; remove the cache/ copy we made
                try: os.remove(cache_path)
                except OSError: pass
            else:
                move_to_uploads(cache_path, filename)
        else:
            if from_uploads:
                # Unsafe: delete the uploads/ original, schedule cache/ copy for deletion
                try: os.remove(uploads_path)
                except OSError: pass
            schedule_delete(cache_path, 180)

        return jsonify(result)

    except requests.exceptions.Timeout:
        return jsonify({'error': 'VirusTotal scan timed out. Please try again.'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── HELPERS (kept here so upload route can call compute_hashes) ───────────────

def compute_hashes(filepath):
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


# ── FILE STATUS ───────────────────────────────────────────────────────────────

@app.route('/file-status')
def file_status():
    """Return real-time deletion status for a cached file.
    Used by the frontend to show accurate 'will be deleted' vs 'has been deleted' state.
    Response: { pending: bool, seconds_remaining: int|null, exists: bool }
    """
    filename = secure_filename(request.args.get('filename', ''))
    if not filename:
        return jsonify({'error': 'No filename'}), 400

    cache_path = os.path.join(CACHE_FOLDER, filename)
    is_pending, seconds_left = get_deletion_status(cache_path)
    return jsonify({
        'pending':           is_pending,
        'seconds_remaining': seconds_left,
        'exists':            os.path.exists(cache_path),
    })


# ── SEARCH ────────────────────────────────────────────────────────────────────

@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'results': []})

    db   = get_db()
    rows = db.execute(
        '''SELECT * FROM scan_results
           WHERE upload_id LIKE ?
              OR filename   LIKE ?
           ORDER BY created_at DESC
           LIMIT 20''',
        (f'%{q}%', f'%{q}%')
    ).fetchall()

    return jsonify({'results': [row_to_dict(r) for r in rows]})


# ── DOWNLOAD ──────────────────────────────────────────────────────────────────

@app.route('/download/<filename>')
def download_file(filename):
    filename = secure_filename(filename)
    db  = get_db()
    row = db.execute(
        'SELECT is_safe, file_deleted FROM scan_results WHERE filename = ? ORDER BY created_at DESC LIMIT 1',
        (filename,)
    ).fetchone()

    if not row or not row['is_safe']:
        return jsonify({'error': 'File not available for download'}), 403

    if row['file_deleted']:
        return jsonify({'error': 'file_deleted'}), 410

    # Safe files live in uploads/ after the immediate move on scan completion
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'file_not_found'}), 404

    return send_file(filepath, as_attachment=True, download_name=filename)


# ── REPORT ────────────────────────────────────────────────────────────────────

@app.route('/report/<path:upload_id>')
def download_report(upload_id):
    db  = get_db()
    row = db.execute('SELECT * FROM scan_results WHERE upload_id = ?', (upload_id,)).fetchone()

    if not row:
        row = db.execute(
            'SELECT * FROM scan_results WHERE filename = ? ORDER BY created_at DESC LIMIT 1',
            (secure_filename(upload_id),)
        ).fetchone()

    if not row:
        return jsonify({'error': 'No scan result found'}), 404

    result     = row_to_dict(row)
    html       = build_report_html(result)
    safe_fname = result['filename'].replace(' ', '_')

    return Response(
        html,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename="dropnode-report-{safe_fname}.html"'}
    )



# ── SET API KEY (persisted to .api_key file on disk) ─────────────────────────

@app.route('/set-api-key', methods=['POST'])
def set_api_key():
    global VIRUSTOTAL_API_KEY
    data = request.json or {}
    key  = (data.get('api_key') or '').strip()
    if not key:
        return jsonify({'error': 'No API key provided'}), 400
    VIRUSTOTAL_API_KEY = key
    # Persist to disk so it survives server restarts
    try:
        with open(_API_KEY_FILE, 'w') as f:
            f.write(key)
        os.chmod(_API_KEY_FILE, 0o600)  # owner-read-only; prevents world-readable API key
    except OSError:
        pass  # memory-only fallback if disk write fails
    return jsonify({'success': True})


# ── DELETE FILE ONLY (keep DB record, mark file_deleted=1) ───────────────────

@app.route('/delete-file', methods=['POST'])
def delete_file_only():
    data     = request.json or {}
    filename = secure_filename(data.get('filename', ''))
    if not filename:
        return jsonify({'error': 'No filename'}), 400

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except OSError as e:
            return jsonify({'error': str(e)}), 500

    with sqlite3.connect(DB_PATH) as con:
        con.execute('UPDATE scan_results SET file_deleted=1 WHERE filename=?', (filename,))
        con.commit()

    return jsonify({'success': True})


# ── DELETE FILE + RESULT (wipe everything) ────────────────────────────────────

@app.route('/delete-result', methods=['POST'])
def delete_result():
    data     = request.json or {}
    filename = secure_filename(data.get('filename', ''))
    if not filename:
        return jsonify({'error': 'No filename'}), 400

    for folder in [UPLOAD_FOLDER, CACHE_FOLDER]:
        fp = os.path.join(folder, filename)
        if os.path.exists(fp):
            try: os.remove(fp)
            except OSError: pass

    with sqlite3.connect(DB_PATH) as con:
        con.execute('DELETE FROM scan_results WHERE filename=?', (filename,))
        con.commit()

    return jsonify({'success': True})



# ── CLEANUP CACHE (called by frontend on page unload via sendBeacon) ─────────

@app.route('/cleanup-cache', methods=['POST'])
def cleanup_cache():
    """
    Delete a specific file from cache/ when the user navigates away or
    reloads mid-scan. The frontend calls this with sendBeacon on beforeunload.
    Only removes files that are NOT already in _pending_deletions (those are
    unsafe files on the 180s auto-delete timer and must not be touched).
    """
    data     = request.json or {}
    filename = secure_filename(data.get('filename', ''))
    if not filename:
        return jsonify({'error': 'No filename'}), 400

    cache_path = os.path.abspath(os.path.join(CACHE_FOLDER, filename))

    # Safety: never delete a file already on the auto-delete timer
    with _del_lock:
        is_pending = cache_path in _pending_deletions
    if is_pending:
        return jsonify({'skipped': 'pending_deletion'}), 200

    if os.path.exists(cache_path):
        try:
            os.remove(cache_path)
        except OSError as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=False, port=5000)
