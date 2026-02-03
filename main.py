#!/usr/bin/env python
# coding: utf-8

# In[ ]:





# In[ ]:





# In[ ]:





# In[12]:


# main.py
# OHIP alarms
# Baseline snapshot on first run
# Change detection: new dated filename, hash change, missing or invalid
# Writes changed-only RSS per alarm for Lovable
# Two Discord webhooks: no-change heartbeat, change alerts
# RESET_BASELINE_ON_CHANGE rolls baseline forward after a real change
# IGNORE_EVENT_TYPES suppresses alert noise by event_type

import os
import re
import io
import json
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

try:
    import pdfplumber
except Exception:
    pdfplumber = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except Exception:
    letter = None
    canvas = None


# -------------------------
# ENV
# -------------------------
SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
SUPABASE_BUCKET = (os.getenv("SUPABASE_BUCKET") or "alarms").strip()

DISCORD_WEBHOOK_URL = (os.getenv("DISCORD_WEBHOOK_URL") or "").strip()
DISCORD_WEBHOOK_NO_CHANGE_URL = (os.getenv("DISCORD_WEBHOOK_NO_CHANGE_URL") or "").strip()
DISCORD_WEBHOOK_CHANGE_URL = (os.getenv("DISCORD_WEBHOOK_CHANGE_URL") or "").strip()

OPENAI_API_KEY = (os.getenv("OPENAI_API_KEY") or "").strip()
OPENAI_MODEL = (os.getenv("OPENAI_MODEL") or "gpt-4o-mini").strip()

HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "60"))
DEBUG = (os.getenv("DEBUG") or "1").strip() == "1"

RESET_BASELINE_ON_CHANGE = (os.getenv("RESET_BASELINE_ON_CHANGE") or "0").strip() == "1"
FORCE_RESET_BASELINE = (os.getenv("FORCE_RESET_BASELINE") or "0").strip() == "1"

IGNORE_EVENT_TYPES_RAW = (os.getenv("IGNORE_EVENT_TYPES") or "").strip()
IGNORE_EVENT_TYPES = set([x.strip() for x in IGNORE_EVENT_TYPES_RAW.split(",") if x.strip()])


# -------------------------
# URLS
# -------------------------
OHIP_PAGE_URL = "https://www.ontario.ca/page/ohip-schedule-benefits-and-fees"

SOB_LAB_SERV_PDF = "https://www.ontario.ca/files/2024-01/moh-ohip-schedule-of-benefits-optometry-services-2024-01-24.pdf"

PHS_MASTER_TXT = "https://www.ontario.ca/files/2025-10/moh-ohip-fee-schedule-master-text-2025-10-03.txt"
PHS_LAYOUT_PDF = "https://wayback.archive-it.org/16312/20220505184913/https://health.gov.on.ca/en/pro/programs/ohip/sob/schedule_master/fsm_layout.pdf"

SOB_PHY_SER_PDF_1 = "https://www.ontario.ca/files/2026-01/moh-schedule-benefit-2025-01-02.pdf"
SOB_PHY_SER_PDF_2 = "https://www.ontario.ca/files/2025-04/moh-method-implementation-2025-26-ffs-compensation-increases-en-2025-04-17.pdf"
SOB_PHY_SER_PDF_3 = "https://wayback.archive-it.org/16312/20220505184900/https://health.gov.on.ca/en/pro/programs/ohip/sob/physserv/pdf/amendments_diagnostics.pdf"


# -------------------------
# ALARM DEFINITIONS
# -------------------------
ALARM_DEFS = {
    "SOB_LAB_SERV": {
        "page_url": OHIP_PAGE_URL,
        "watch_files": [
            {"key": "optometry_pdf", "url": SOB_LAB_SERV_PDF, "type": "pdf"},
        ],
        "discover": [
            {
                "key": "optometry_pdf",
                "type": "pdf",
                "prefix": "moh-ohip-schedule-of-benefits-optometry-services-",
                "ext": ".pdf",
                "source": "page",
            }
        ],
        "ai_reports": True,
        "report_title": "OHIP Schedule of Benefits. Laboratory Services. Change Detection Report",
    },
    "OHIP_PHS_Fee_Sche_Master": {
        "page_url": None,
        "watch_files": [
            {"key": "fee_master_txt", "url": PHS_MASTER_TXT, "type": "txt"},
            {"key": "fee_master_layout_pdf", "url": PHS_LAYOUT_PDF, "type": "pdf", "reference_only": True},
        ],
        "discover": [],
        "ai_reports": False,
        "report_title": "OHIP Physician Fee Schedule Master. Change Detection Report",
    },
    "SOB_PHY_SER": {
        "page_url": None,
        "watch_files": [
            {"key": "phys_services_pdf", "url": SOB_PHY_SER_PDF_1, "type": "pdf"},
            {"key": "comp_increases_pdf", "url": SOB_PHY_SER_PDF_2, "type": "pdf"},
            {"key": "amendments_diagnostics_pdf", "url": SOB_PHY_SER_PDF_3, "type": "pdf"},
        ],
        "discover": [],
        "ai_reports": True,
        "report_title": "Schedule of Benefits for Physician Services. Change Detection Report",
    },
}


# -------------------------
# TIME + LOG
# -------------------------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rfc2822_now() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def log(msg: str) -> None:
    if DEBUG:
        print(f"[{now_utc_iso()}] {msg}", flush=True)


# -------------------------
# HASH + SAFE STRINGS
# -------------------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def xml_escape(s: str) -> str:
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("\"", "&quot;")
    s = s.replace("'", "&apos;")
    return s


def safe_filename_from_url(url: str) -> str:
    base = url.split("?")[0].rstrip("/")
    name = base.split("/")[-1] or "index"
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name


# -------------------------
# HTTP
# -------------------------
def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "OntarioAlarmMonitor/1.0", "Accept": "*/*"})
    return s


SESSION = make_session()


def http_get(url: str) -> Tuple[int, Dict[str, str], bytes, str]:
    r = SESSION.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
    status = r.status_code
    final_url = str(r.url)
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    body = r.content or b""
    return status, hdrs, body, final_url


def pick_discord_url(is_change: bool) -> str:
    if is_change:
        return DISCORD_WEBHOOK_CHANGE_URL or DISCORD_WEBHOOK_URL
    return DISCORD_WEBHOOK_NO_CHANGE_URL or DISCORD_WEBHOOK_URL


def post_discord(msg: str, is_change: bool) -> None:
    url = pick_discord_url(is_change)
    if not url:
        return
    try:
        SESSION.post(url, json={"content": msg}, timeout=30)
    except Exception as e:
        log(f"Discord post failed: {e}")


# -------------------------
# RSS
# -------------------------
def build_rss(channel_title: str, channel_desc: str, channel_link: str, items: List[Dict[str, str]]) -> str:
    parts: List[str] = []
    parts.append('<?xml version="1.0" encoding="UTF-8"?>')
    parts.append('<rss version="2.0">')
    parts.append("<channel>")
    parts.append(f"<title>{xml_escape(channel_title)}</title>")
    parts.append(f"<description>{xml_escape(channel_desc)}</description>")
    parts.append(f"<link>{xml_escape(channel_link)}</link>")
    parts.append(f"<lastBuildDate>{xml_escape(rfc2822_now())}</lastBuildDate>")
    for it in items[:50]:
        parts.append("<item>")
        parts.append(f"<title>{xml_escape(it.get('title',''))}</title>")
        parts.append(f"<description>{xml_escape(it.get('description',''))}</description>")
        parts.append(f"<link>{xml_escape(it.get('link',''))}</link>")
        parts.append(f"<guid isPermaLink=\"false\">{xml_escape(it.get('guid',''))}</guid>")
        parts.append(f"<pubDate>{xml_escape(it.get('pubDate',''))}</pubDate>")
        parts.append("</item>")
    parts.append("</channel>")
    parts.append("</rss>")
    return "\n".join(parts)


# -------------------------
# PDF RENDER
# -------------------------
def render_pdf(title: str, body_text: str) -> bytes:
    if letter is None or canvas is None:
        return (title + "\n\n" + body_text).encode("utf-8", errors="ignore")

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    x = 40
    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, title)

    c.setFont("Helvetica", 10)
    y -= 22

    for line in body_text.splitlines():
        while len(line) > 110:
            chunk = line[:110]
            line = line[110:]
            if y < 60:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 50
            c.drawString(x, y, chunk)
            y -= 12
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 50
        c.drawString(x, y, line)
        y -= 12

    c.save()
    return buf.getvalue()


def extract_pdf_text(pdf_bytes: bytes) -> str:
    if pdfplumber is None:
        return ""
    out: List[str] = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text() or ""
            t = t.replace("\r", "\n")
            out.append(t)
    return "\n".join(out)


# -------------------------
# PAGE DISCOVERY
# -------------------------
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def date_token_from_filename(name: str) -> str:
    m = DATE_RE.search(name)
    return m.group(1) if m else ""


def normalize_page_signal(html_bytes: bytes) -> str:
    s = html_bytes.decode("utf-8", errors="ignore")
    anchors = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', s, flags=re.I | re.S)
    lines: List[str] = []
    for href, text in anchors:
        href = href.strip()
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()

        if not href:
            continue

        if href.startswith("/"):
            href_full = "https://www.ontario.ca" + href
        else:
            href_full = href

        low = href_full.lower()
        if (low.endswith(".pdf") or low.endswith(".txt")) and (
            "ontario.ca" in low or "health.gov.on.ca" in low or "archive-it.org" in low
        ):
            lines.append(f"{href_full} | {text}")

    lines = sorted(list(set(lines)))
    return "\n".join(lines)


def discover_new_file_from_page(page_signal: str, prefix: str, ext: str) -> Optional[str]:
    candidates: List[Tuple[str, str]] = []
    for line in page_signal.splitlines():
        href = line.split("|", 1)[0].strip()
        fname = href.split("?")[0].split("/")[-1]
        if fname.startswith(prefix) and fname.lower().endswith(ext.lower()):
            token = date_token_from_filename(fname)
            candidates.append((href, token))

    if not candidates:
        return None

    dated = [c for c in candidates if c[1]]
    if dated:
        dated.sort(key=lambda x: x[1])
        return dated[-1][0]

    return candidates[-1][0]


# -------------------------
# SUPABASE STORAGE VIA REST
# -------------------------
class SupabaseStorage:
    def __init__(self, url: str, key: str, bucket: str):
        if not url or not key:
            raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")
        self.url = url.rstrip("/")
        self.key = key
        self.bucket = bucket

    def _headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        h = {"Authorization": f"Bearer {self.key}", "apikey": self.key}
        if content_type:
            h["Content-Type"] = content_type
        return h

    def upload_bytes(self, path: str, data: bytes, content_type: str) -> None:
        url = f"{self.url}/storage/v1/object/{self.bucket}/{path.lstrip('/')}"
        params = {"upsert": "true"}
        r = SESSION.post(url, params=params, headers=self._headers(content_type), data=data, timeout=60)
        if r.status_code >= 300:
            raise RuntimeError(f"Supabase upload failed {r.status_code}: {r.text}")

    def download_bytes(self, path: str) -> Optional[bytes]:
        url = f"{self.url}/storage/v1/object/{self.bucket}/{path.lstrip('/')}"
        r = SESSION.get(url, headers=self._headers(), timeout=60)
        if r.status_code == 404:
            return None
        if r.status_code >= 300:
            raise RuntimeError(f"Supabase download failed {r.status_code}: {r.text}")
        return r.content

    def public_url(self, path: str) -> str:
        return f"{self.url}/storage/v1/object/public/{self.bucket}/{path.lstrip('/')}"


# -------------------------
# OPENAI REPORT
# -------------------------
def openai_pdf_report(alarm_name: str, old_pdf: bytes, new_pdf: bytes, before_name: str, after_name: str) -> str:
    if not OPENAI_API_KEY:
        return "OpenAI key missing. Skipped AI report."

    old_text = extract_pdf_text(old_pdf)
    new_text = extract_pdf_text(new_pdf)

    system_spec = """
Compare two PDFs. Old PDF is baseline. New PDF is candidate update.

OUTPUT FORMAT. STRICT.
Title
OHIP Schedule of Benefits. Laboratory Services. Change Detection Report

SECTION A. EXECUTIVE RESULT. ONE SCREEN.
Fee changes detected: YES or NO
L-codes added or removed: YES or NO
Ordering or eligibility rule changes: YES or NO
Signature or requisition rule changes: YES or NO
Administrative or wording only changes: YES or NO
If every answer equals NO except administrative, say:
No laboratory billing or operational impact.

SECTION B. FEE TABLE. MACHINE CHECK.
Method
Extract every L-code and dollar value from both PDFs.
Sort by L-code.
Compare old vs new.
Output rules
If zero changes, output exactly:
No L-code or dollar value changes detected. Fee table identical.
If changes exist, output table rows only for differences:
Before
L123 $12.34
After
L123 $14.56
Impact
Increase of $2.22
No filler.

SECTION C. NON-FEE SECTIONS THAT CHANGED. EXACT.
For each changed section only:
Section identifier
Before exact paragraph text from old.
After exact paragraph text from new.
Change summary short sentence with real effect on a laboratory.

SECTION D. LAB IMPACT FILTER.
Explicitly classify each change:
Financial impact: Yes or No
Workflow impact: Yes or No
Compliance or audit impact: Yes or No

SECTION E. DATE AND FILE METADATA.
Before PDF file name and file date.
After PDF file name and file date.
Change statement document updated on [date].

SECTION F. FINAL LAB STATEMENT.
One sentence. Mandatory.

ALERT SEVERITY LOGIC.
Dollar value change high.
L-code change high.
Ordering or requisition rule change medium.
Wording only low.
""".strip()

    payload = {
        "alarm_name": alarm_name,
        "before_file": before_name,
        "after_file": after_name,
        "before_text": old_text[:120000],
        "after_text": new_text[:120000],
    }

    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_spec},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            temperature=0,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        return f"OpenAI call failed: {e}"


# -------------------------
# IGNORE RULES
# -------------------------
def load_ignore_rules(s: SupabaseStorage) -> Dict:
    path = "alarms/config/ignore_rules.json"
    b = s.download_bytes(path)
    if b is None:
        default = {"rules": []}
        s.upload_bytes(path, json.dumps(default, indent=2).encode("utf-8"), "application/json")
        return default
    return json.loads(b.decode("utf-8", errors="ignore"))


def ignore_match(ignore_rules: Dict, alarm: str, event: Dict) -> bool:
    if event.get("event_type") in IGNORE_EVENT_TYPES:
        return True

    rules = ignore_rules.get("rules") or []
    for r in rules:
        if (r.get("alarm") or "") != alarm:
            continue

        url_contains = r.get("ignore_url_contains")
        if url_contains and url_contains not in (event.get("url") or ""):
            continue

        fname_re = r.get("ignore_filename_regex")
        if fname_re:
            try:
                if re.search(fname_re, event.get("file") or "") is None:
                    continue
            except Exception:
                continue

        text_contains = r.get("ignore_text_contains")
        if text_contains:
            text = event.get("details_text") or ""
            if text_contains not in text:
                continue

        return True

    return False


# -------------------------
# FETCH MODEL
# -------------------------
@dataclass
class FetchResult:
    url: str
    status: int
    final_url: str
    etag: str
    last_modified: str
    content_type: str
    body: bytes
    sha: str


def expected_content_ok(file_type: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if file_type == "pdf":
        return "pdf" in ct
    if file_type == "txt":
        return ("text" in ct) or ("octet-stream" in ct) or ("plain" in ct)
    if file_type == "html":
        return ("html" in ct) or ("text" in ct)
    return True


def fetch(url: str) -> FetchResult:
    status, hdrs, body, final_url = http_get(url)
    etag = hdrs.get("etag", "")
    last_modified = hdrs.get("last-modified", "")
    content_type = hdrs.get("content-type", "")
    sha = sha256_bytes(body)
    return FetchResult(
        url=url,
        status=status,
        final_url=final_url,
        etag=etag,
        last_modified=last_modified,
        content_type=content_type,
        body=body,
        sha=sha,
    )


def meta(fr: FetchResult) -> Dict[str, str]:
    return {
        "url": fr.url,
        "final_url": fr.final_url,
        "status": str(fr.status),
        "etag": fr.etag,
        "last_modified": fr.last_modified,
        "content_type": fr.content_type,
        "sha256": fr.sha,
        "fetched_at": now_utc_iso(),
    }


# -------------------------
# STATE + PATHS
# -------------------------
def p_alarm(alarm: str, suffix: str) -> str:
    return f"alarms/{alarm}/{suffix.lstrip('/')}"


def read_json(s: SupabaseStorage, path: str) -> Optional[Dict]:
    b = s.download_bytes(path)
    if b is None:
        return None
    return json.loads(b.decode("utf-8", errors="ignore"))


def write_json(s: SupabaseStorage, path: str, obj: Dict) -> None:
    s.upload_bytes(path, json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8"), "application/json")


def stable_blob_name(key: str, ftype: str) -> str:
    ext = "bin"
    if ftype == "pdf":
        ext = "pdf"
    if ftype == "txt":
        ext = "txt"
    return f"{key}.{ext}"


def write_bytes_evidence(s: SupabaseStorage, alarm: str, folder: str, name: str, data: bytes, content_type: str) -> str:
    path = p_alarm(alarm, f"{folder}/{name}")
    s.upload_bytes(path, data, content_type)
    return s.public_url(path)


def ensure_state(s: SupabaseStorage, alarm: str, alarm_def: Dict) -> Dict:
    state_path = p_alarm(alarm, "state.json")
    st = read_json(s, state_path)
    if st is not None:
        return st

    st = {
        "alarm": alarm,
        "created_at": now_utc_iso(),
        "page_url": alarm_def.get("page_url"),
        "active_urls": {},
        "baseline": {},
        "last_run_at": "",
        "last_no_change_at": "",
        "last_change_at": "",
    }

    for wf in alarm_def.get("watch_files", []):
        st["active_urls"][wf["key"]] = wf["url"]

    write_json(s, state_path, st)
    return st


# -------------------------
# RSS (CHANGED ONLY)
# -------------------------
def append_changed_feed_item(
    s: SupabaseStorage,
    alarm: str,
    title: str,
    description: str,
    severity: str,
    event_types: List[str],
) -> str:
    feed_path = p_alarm(alarm, "feeds/changed.xml")
    existing = s.download_bytes(feed_path)
    items: List[Dict[str, str]] = []

    if existing:
        try:
            xml = existing.decode("utf-8", errors="ignore")
            for m in re.findall(r"<item>(.*?)</item>", xml, flags=re.S):
                t = re.search(r"<title>(.*?)</title>", m, flags=re.S)
                d = re.search(r"<description>(.*?)</description>", m, flags=re.S)
                g = re.search(r"<guid.*?>(.*?)</guid>", m, flags=re.S)
                p = re.search(r"<pubDate>(.*?)</pubDate>", m, flags=re.S)
                l = re.search(r"<link>(.*?)</link>", m, flags=re.S)
                items.append(
                    {
                        "title": (t.group(1) if t else ""),
                        "description": (d.group(1) if d else ""),
                        "guid": (g.group(1) if g else ""),
                        "pubDate": (p.group(1) if p else ""),
                        "link": (l.group(1) if l else ""),
                    }
                )
        except Exception:
            items = []

    guid = f"{alarm}:changed:{now_utc_iso()}:{sha256_bytes((title + description).encode('utf-8'))[:12]}"
    pub = rfc2822_now()
    base_link = s.public_url(p_alarm(alarm, ""))

    et = ",".join(sorted(list(set(event_types)))) if event_types else "unknown"
    full_title = f"{alarm} {severity} {title} types={et}"

    new_item = {
        "title": full_title,
        "description": description,
        "guid": guid,
        "pubDate": pub,
        "link": base_link,
    }
    items = [new_item] + items

    rss = build_rss(
        channel_title=f"{alarm} changed",
        channel_desc=f"{alarm} change feed",
        channel_link=base_link,
        items=items,
    )
    s.upload_bytes(feed_path, rss.encode("utf-8"), "application/rss+xml")
    return s.public_url(feed_path)


# -------------------------
# EVENTS
# -------------------------
def record_event(s: SupabaseStorage, alarm: str, event: Dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    name = f"{ts}_{event.get('event_type','event')}.json"
    path = p_alarm(alarm, f"events/{name}")
    s.upload_bytes(path, json.dumps(event, indent=2, ensure_ascii=False).encode("utf-8"), "application/json")
    return s.public_url(path)


# -------------------------
# TXT DIFF
# -------------------------
def diff_lines(old: str, new: str) -> Dict[str, List[str]]:
    old_set = set(old.splitlines())
    new_set = set(new.splitlines())
    added = sorted(list(new_set - old_set))
    removed = sorted(list(old_set - new_set))
    return {"added": added, "removed": removed}


def summarize_txt_diff(old_txt: str, new_txt: str, max_lines: int = 30) -> str:
    d = diff_lines(old_txt, new_txt)
    added = d["added"][:max_lines]
    removed = d["removed"][:max_lines]
    parts: List[str] = []
    parts.append(f"Added lines: {len(d['added'])}")
    parts.append(f"Removed lines: {len(d['removed'])}")
    if added:
        parts.append("Sample added")
        parts.extend(added)
    if removed:
        parts.append("Sample removed")
        parts.extend(removed)
    return "\n".join(parts)


# -------------------------
# BASELINE RESET HELPERS
# -------------------------
def reset_baseline_for_key(
    s: SupabaseStorage,
    alarm: str,
    st: Dict,
    key: str,
    ftype: str,
    curr_bytes: bytes,
    curr_meta: Dict,
) -> None:
    ct = "application/octet-stream"
    if ftype == "pdf":
        ct = "application/pdf"
    if ftype == "txt":
        ct = "text/plain"

    base_blob = stable_blob_name(key, ftype)
    s.upload_bytes(p_alarm(alarm, f"baseline/{base_blob}"), curr_bytes, ct)
    write_json(s, p_alarm(alarm, f"baseline/{key}.meta.json"), curr_meta)

    st["baseline"][f"{key}_sha256"] = sha256_bytes(curr_bytes)
    st["baseline"][f"{key}_baseline_meta"] = curr_meta
    st["baseline"][f"{key}_baseline_filename"] = curr_meta.get("source_filename") or base_blob


# -------------------------
# RUN ONE ALARM
# -------------------------
def run_alarm(s: SupabaseStorage, ignore_rules: Dict, alarm: str, alarm_def: Dict) -> None:
    st = ensure_state(s, alarm, alarm_def)
    state_path = p_alarm(alarm, "state.json")

    run_at = now_utc_iso()
    st["last_run_at"] = run_at

    page_signal = ""
    if alarm_def.get("page_url"):
        page_url = alarm_def["page_url"]
        fr_page = fetch(page_url)

        if fr_page.status >= 400 or expected_content_ok("html", fr_page.content_type) is False:
            ev = {
                "alarm": alarm,
                "event_type": "page_error",
                "severity": "HIGH",
                "when": run_at,
                "url": page_url,
                "status": fr_page.status,
                "content_type": fr_page.content_type,
                "etag": fr_page.etag,
                "last_modified": fr_page.last_modified,
                "sha256": fr_page.sha,
            }
            record_event(s, alarm, ev)
        else:
            page_signal = normalize_page_signal(fr_page.body)
            write_bytes_evidence(s, alarm, "current", "page_signal.txt", page_signal.encode("utf-8"), "text/plain")
            if "page_signal_sha" not in st["baseline"]:
                st["baseline"]["page_signal_sha"] = sha256_bytes(page_signal.encode("utf-8"))
                write_bytes_evidence(s, alarm, "baseline", "page_signal.txt", page_signal.encode("utf-8"), "text/plain")

    discovery_events: List[Dict] = []
    for d in alarm_def.get("discover", []):
        if d.get("source") != "page":
            continue
        if page_signal == "":
            continue

        new_url = discover_new_file_from_page(page_signal, d["prefix"], d["ext"])
        if new_url is None:
            continue

        key = d["key"]
        old_url = st["active_urls"].get(key) or ""

        if old_url == "":
            st["active_urls"][key] = new_url
            discovery_events.append(
                {
                    "alarm": alarm,
                    "event_type": "discovered_url",
                    "severity": "HIGH",
                    "when": run_at,
                    "key": key,
                    "old_url": "",
                    "new_url": new_url,
                    "file": safe_filename_from_url(new_url),
                }
            )
            continue

        old_fn = safe_filename_from_url(old_url)
        new_fn = safe_filename_from_url(new_url)
        old_token = date_token_from_filename(old_fn)
        new_token = date_token_from_filename(new_fn)

        if new_url != old_url and ((new_token != "" and new_token != old_token) or (new_fn != old_fn)):
            st["active_urls"][key] = new_url
            discovery_events.append(
                {
                    "alarm": alarm,
                    "event_type": "new_dated_filename",
                    "severity": "HIGH",
                    "when": run_at,
                    "key": key,
                    "old_url": old_url,
                    "new_url": new_url,
                    "old_file": old_fn,
                    "new_file": new_fn,
                    "old_date_token": old_token,
                    "new_date_token": new_token,
                    "file": new_fn,
                }
            )

    file_events: List[Dict] = []
    for wf in alarm_def.get("watch_files", []):
        key = wf["key"]
        ftype = wf["type"]
        url = st["active_urls"].get(key) or wf["url"]
        st["active_urls"][key] = url

        fr = fetch(url)
        fname = safe_filename_from_url(url)

        ct = fr.content_type or "application/octet-stream"
        if ftype == "pdf":
            ct = "application/pdf"
        if ftype == "txt":
            ct = "text/plain"

        # Save current evidence by filename
        write_bytes_evidence(s, alarm, "current", fname, fr.body, ct)
        write_json(s, p_alarm(alarm, f"current/{fname}.meta.json"), meta(fr))

        # Save stable current by key
        stable_curr = stable_blob_name(key, ftype)
        s.upload_bytes(p_alarm(alarm, f"current/{stable_curr}"), fr.body, ct)
        curr_meta = meta(fr)
        curr_meta["source_filename"] = fname
        write_json(s, p_alarm(alarm, f"current/{key}.meta.json"), curr_meta)

        base_sha_key = f"{key}_sha256"
        base_meta_key = f"{key}_baseline_meta"
        base_file_key = f"{key}_baseline_filename"

        # Baseline create or forced reset
        if (base_sha_key not in st["baseline"]) or FORCE_RESET_BASELINE:
            st["baseline"][base_sha_key] = fr.sha
            st["baseline"][base_meta_key] = curr_meta
            st["baseline"][base_file_key] = fname

            stable_base = stable_blob_name(key, ftype)
            s.upload_bytes(p_alarm(alarm, f"baseline/{stable_base}"), fr.body, ct)
            write_json(s, p_alarm(alarm, f"baseline/{key}.meta.json"), curr_meta)

            write_bytes_evidence(s, alarm, "baseline", fname, fr.body, ct)
            write_json(s, p_alarm(alarm, f"baseline/{fname}.meta.json"), curr_meta)

            if FORCE_RESET_BASELINE:
                file_events.append(
                    {
                        "alarm": alarm,
                        "event_type": "baseline_forced_reset",
                        "severity": "LOW",
                        "when": run_at,
                        "key": key,
                        "url": url,
                        "file": fname,
                        "new_sha256": fr.sha,
                    }
                )
            continue

        baseline_sha = st["baseline"].get(base_sha_key) or ""
        baseline_meta = st["baseline"].get(base_meta_key) or {}
        baseline_fname = st["baseline"].get(base_file_key) or ""

        content_ok = expected_content_ok(ftype, fr.content_type)
        if fr.status >= 400 or content_ok is False:
            file_events.append(
                {
                    "alarm": alarm,
                    "event_type": "file_missing_or_invalid",
                    "severity": "HIGH",
                    "when": run_at,
                    "key": key,
                    "url": url,
                    "file": fname,
                    "status": fr.status,
                    "content_type": fr.content_type,
                    "baseline_file": baseline_fname,
                    "baseline_status": baseline_meta.get("status"),
                    "baseline_content_type": baseline_meta.get("content_type"),
                    "baseline_sha256": baseline_sha,
                    "new_sha256": fr.sha,
                }
            )
            continue

        if fr.sha != baseline_sha:
            file_events.append(
                {
                    "alarm": alarm,
                    "event_type": "file_hash_changed",
                    "severity": "HIGH" if ftype in ["pdf", "txt"] else "LOW",
                    "when": run_at,
                    "key": key,
                    "url": url,
                    "file": fname,
                    "baseline_file": baseline_fname,
                    "baseline_sha256": baseline_sha,
                    "new_sha256": fr.sha,
                    "baseline_etag": baseline_meta.get("etag"),
                    "new_etag": fr.etag,
                    "baseline_last_modified": baseline_meta.get("last_modified"),
                    "new_last_modified": fr.last_modified,
                }
            )

    # Persist state after discovery updates
    write_json(s, state_path, st)

    all_events = discovery_events + file_events

    filtered_events: List[Dict] = []
    for ev in all_events:
        if ignore_match(ignore_rules, alarm, ev):
            ev["suppressed"] = True
            ev["suppressed_reason"] = "ignore"
            record_event(s, alarm, ev)
        else:
            filtered_events.append(ev)

    if len(filtered_events) == 0:
        st["last_no_change_at"] = run_at
        write_json(s, state_path, st)
        post_discord(f"{alarm} LOW No change. Checked {run_at}", is_change=False)
        return

    st["last_change_at"] = run_at
    write_json(s, state_path, st)

    event_urls: List[str] = []
    desc_lines: List[str] = []
    severity = "HIGH"
    event_types: List[str] = []

    for ev in filtered_events:
        event_types.append(ev.get("event_type") or "unknown")
        event_urls.append(record_event(s, alarm, ev))

        et = ev.get("event_type") or ""
        if et == "new_dated_filename":
            desc_lines.append(
                f"type={et} key={ev.get('key','')} old={ev.get('old_file','')} new={ev.get('new_file','')} date={ev.get('old_date_token','')} to {ev.get('new_date_token','')}"
            )
        elif et == "file_missing_or_invalid":
            desc_lines.append(
                f"type={et} key={ev.get('key','')} file={ev.get('file','')} status={ev.get('status','')} content_type={ev.get('content_type','')}"
            )
        elif et == "file_hash_changed":
            desc_lines.append(
                f"type={et} key={ev.get('key','')} file={ev.get('file','')} sha={str(ev.get('baseline_sha256',''))[:10]} to {str(ev.get('new_sha256',''))[:10]}"
            )
        elif et == "discovered_url":
            desc_lines.append(f"type={et} key={ev.get('key','')} url={ev.get('new_url','')}")
        elif et == "baseline_forced_reset":
            desc_lines.append(f"type={et} key={ev.get('key','')} file={ev.get('file','')}")
        else:
            desc_lines.append(f"type={et} file={ev.get('file','')}")

    report_urls: List[str] = []

    # AI PDF reports
    if alarm_def.get("ai_reports"):
        for wf in alarm_def.get("watch_files", []):
            if wf.get("reference_only"):
                continue
            if wf["type"] != "pdf":
                continue

            key = wf["key"]
            relevant = False
            for ev in filtered_events:
                if ev.get("key") == key and ev.get("event_type") in ["new_dated_filename", "file_hash_changed"]:
                    relevant = True
            if relevant is False:
                continue

            missing = False
            for ev in filtered_events:
                if ev.get("key") == key and ev.get("event_type") == "file_missing_or_invalid":
                    missing = True
            if missing:
                continue

            base_blob = stable_blob_name(key, "pdf")
            curr_blob = stable_blob_name(key, "pdf")
            base_bytes = s.download_bytes(p_alarm(alarm, f"baseline/{base_blob}"))
            curr_bytes = s.download_bytes(p_alarm(alarm, f"current/{curr_blob}"))
            if base_bytes is None or curr_bytes is None:
                continue

            baseline_fname = st["baseline"].get(f"{key}_baseline_filename") or base_blob
            current_meta = read_json(s, p_alarm(alarm, f"current/{key}.meta.json")) or {}
            current_fname = current_meta.get("source_filename") or curr_blob

            report_text = openai_pdf_report(
                alarm_name=alarm,
                old_pdf=base_bytes,
                new_pdf=curr_bytes,
                before_name=str(baseline_fname),
                after_name=str(current_fname),
            )
            pdf_bytes = render_pdf(alarm_def.get("report_title") or "Change Detection Report", report_text)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
            rep_name = f"{ts}_{key}_change_report.pdf"
            rep_url = write_bytes_evidence(s, alarm, "reports", rep_name, pdf_bytes, "application/pdf")
            report_urls.append(rep_url)

    # TXT report for master fee schedule
    if alarm == "OHIP_PHS_Fee_Sche_Master":
        wf = None
        for x in alarm_def.get("watch_files", []):
            if x.get("type") == "txt":
                wf = x
        if wf:
            key = wf["key"]
            relevant = False
            for ev in filtered_events:
                if ev.get("key") == key and ev.get("event_type") == "file_hash_changed":
                    relevant = True
            if relevant:
                base_blob = stable_blob_name(key, "txt")
                curr_blob = stable_blob_name(key, "txt")
                base_bytes = s.download_bytes(p_alarm(alarm, f"baseline/{base_blob}"))
                curr_bytes = s.download_bytes(p_alarm(alarm, f"current/{curr_blob}"))
                if base_bytes and curr_bytes:
                    old_txt = base_bytes.decode("utf-8", errors="ignore")
                    new_txt = curr_bytes.decode("utf-8", errors="ignore")
                    summary = summarize_txt_diff(old_txt, new_txt, max_lines=30)
                    pdf_bytes = render_pdf(alarm_def.get("report_title") or "TXT Change Report", summary)
                    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
                    rep_name = f"{ts}_{key}_txt_change_report.pdf"
                    rep_url = write_bytes_evidence(s, alarm, "reports", rep_name, pdf_bytes, "application/pdf")
                    report_urls.append(rep_url)

    desc = " | ".join(desc_lines)
    if len(report_urls) > 0:
        desc = desc + " | Reports " + " ".join(report_urls)
    if len(event_urls) > 0:
        desc = desc + " | Events " + " ".join(event_urls)

    feed_url = append_changed_feed_item(
        s,
        alarm,
        "Change detected",
        desc,
        severity=severity,
        event_types=event_types,
    )

    post_discord(f"{alarm} {severity} Change detected. {feed_url}", is_change=True)

    # Baseline roll forward after change
    if RESET_BASELINE_ON_CHANGE:
        changed_keys: List[str] = []
        for ev in filtered_events:
            if ev.get("event_type") in ["new_dated_filename", "file_hash_changed"] and ev.get("key"):
                changed_keys.append(ev.get("key"))
        changed_keys = sorted(list(set(changed_keys)))

        for wf in alarm_def.get("watch_files", []):
            key = wf["key"]
            if key not in changed_keys:
                continue
            if wf.get("reference_only"):
                continue

            missing = False
            for ev in filtered_events:
                if ev.get("key") == key and ev.get("event_type") == "file_missing_or_invalid":
                    missing = True
            if missing:
                continue

            ftype = wf["type"]
            curr_blob = stable_blob_name(key, ftype)
            curr_bytes = s.download_bytes(p_alarm(alarm, f"current/{curr_blob}"))
            curr_meta = read_json(s, p_alarm(alarm, f"current/{key}.meta.json")) or {}

            if curr_bytes is None:
                continue

            reset_baseline_for_key(s, alarm, st, key, ftype, curr_bytes, curr_meta)

        write_json(s, state_path, st)
        post_discord(f"{alarm} LOW Baseline reset after change. Keys {','.join(changed_keys)}", is_change=True)


def main() -> None:
    log("BOOT main() reached")

    if SUPABASE_URL == "" or SUPABASE_SERVICE_ROLE_KEY == "":
        raise RuntimeError("Missing Supabase env vars")

    s = SupabaseStorage(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_BUCKET)
    ignore_rules = load_ignore_rules(s)

    for alarm, alarm_def in ALARM_DEFS.items():
        try:
            run_alarm(s, ignore_rules, alarm, alarm_def)
        except Exception as e:
            msg = f"{alarm} HIGH Runtime error {e}"
            log(msg)
            post_discord(msg, is_change=True)

    log("Done")


if __name__ == "__main__":
    main()


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




