#!/usr/bin/env python
# coding: utf-8

# In[ ]:





# In[ ]:





# In[ ]:





# In[12]:


# main.py
# OHIP alarms runner
# Local baseline + change detection + Lovable feed post + Discord alerts
# No Supabase keys needed.
#
# Required Railway vars:
#   FEED_POST_URL=https://tcgdugdhwtbyeygdqdob.supabase.co/functions/v1/feed
#   FEED_FUNCTION_KEY=...
#
# Optional vars:
#   DATA_DIR=/data
#   DISCORD_WEBHOOK_URL=...
#   DISCORD_WEBHOOK_NO_CHANGE_URL=...
#   DISCORD_WEBHOOK_CHANGE_URL=...
#   OPENAI_API_KEY=...
#   OPENAI_MODEL=gpt-4o-mini
#   HTTP_TIMEOUT=60
#   DEBUG=1
#   RESET_BASELINE_ON_CHANGE=0
#   FORCE_RESET_BASELINE=0
#   IGNORE_EVENT_TYPES=page_error,baseline_forced_reset

import os
import re
import io
import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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
# CONSTANT URLS
# -------------------------
OHIP_PAGE_URL = "https://www.ontario.ca/page/ohip-schedule-benefits-and-fees"

SOB_LAB_SERV_PDF = "https://www.ontario.ca/files/2024-01/moh-ohip-schedule-of-benefits-optometry-services-2024-01-24.pdf"

PHS_MASTER_TXT = "https://www.ontario.ca/files/2025-10/moh-ohip-fee-schedule-master-text-2025-10-03.txt"
PHS_LAYOUT_PDF = "https://wayback.archive-it.org/16312/20220505184913/https://health.gov.on.ca/en/pro/programs/ohip/sob/schedule_master/fsm_layout.pdf"

SOB_PHY_SER_PDF_1 = "https://www.ontario.ca/files/2026-01/moh-schedule-benefit-2025-01-02.pdf"
SOB_PHY_SER_PDF_2 = "https://www.ontario.ca/files/2025-04/moh-method-implementation-2025-26-ffs-compensation-increases-en-2025-04-17.pdf"
SOB_PHY_SER_PDF_3 = "https://wayback.archive-it.org/16312/20220505184900/https://health.gov.on.ca/en/pro/programs/ohip/sob/physserv/pdf/amendments_diagnostics.pdf"


# -------------------------
# ALARMS
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
# ENV
# -------------------------
DATA_DIR = (os.getenv("DATA_DIR") or "/data").strip()

FEED_POST_URL = (os.getenv("FEED_POST_URL") or "").strip()
FEED_FUNCTION_KEY = (os.getenv("FEED_FUNCTION_KEY") or "").strip()

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
# HELPERS
# -------------------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def xml_escape(s: str) -> str:
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&apos;")
    return s


def safe_filename_from_url(url: str) -> str:
    base = url.split("?")[0].rstrip("/")
    name = base.split("/")[-1] or "index"
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_file_bytes(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return None


def write_file_bytes(path: str, b: bytes) -> None:
    folder = os.path.dirname(path)
    if folder:
        ensure_dir(folder)
    with open(path, "wb") as f:
        f.write(b)


def read_file_json(path: str) -> Optional[Dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_file_json(path: str, obj: Dict) -> None:
    folder = os.path.dirname(path)
    if folder:
        ensure_dir(folder)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


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


# -------------------------
# DISCORD
# -------------------------
def pick_discord_url(is_change: bool) -> str:
    if is_change:
        return DISCORD_WEBHOOK_CHANGE_URL or DISCORD_WEBHOOK_URL
    return DISCORD_WEBHOOK_NO_CHANGE_URL or DISCORD_WEBHOOK_URL


def post_discord(msg: str, is_change: bool) -> None:
    url = pick_discord_url(is_change)
    if url == "":
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
# PDF TEXT + PDF REPORT RENDER
# -------------------------
def render_pdf(title: str, body_text: str) -> bytes:
    if letter is None or canvas is None:
        return (title + "\n\n" + body_text).encode("utf-8", errors="ignore")

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    _, height = letter

    x = 40
    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, title)

    c.setFont("Helvetica", 10)
    y -= 22

    for line in body_text.splitlines():
        work = line
        while len(work) > 110:
            chunk = work[:110]
            work = work[110:]
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
        c.drawString(x, y, work)
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
        href = (href or "").strip()
        txt = re.sub(r"<[^>]+>", " ", text or "")
        txt = re.sub(r"\s+", " ", txt).strip()
        if href == "":
            continue

        if href.startswith("/"):
            href_full = "https://www.ontario.ca" + href
        else:
            href_full = href

        low = href_full.lower()
        ok_ext = low.endswith(".pdf") or low.endswith(".txt")
        ok_host = ("ontario.ca" in low) or ("health.gov.on.ca" in low) or ("archive-it.org" in low)
        if ok_ext and ok_host:
            lines.append(f"{href_full} | {txt}")

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

    if len(candidates) == 0:
        return None

    dated = [c for c in candidates if c[1] != ""]
    if len(dated) > 0:
        dated.sort(key=lambda x: x[1])
        return dated[-1][0]

    return candidates[-1][0]


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
# IGNORE RULES
# -------------------------
def ignore_match(ignore_rules: Dict, alarm: str, event: Dict) -> bool:
    et = event.get("event_type") or ""
    if et in IGNORE_EVENT_TYPES:
        return True

    rules = ignore_rules.get("rules") or []
    for r in rules:
        if (r.get("alarm") or "") != alarm:
            continue

        url_contains = r.get("ignore_url_contains")
        if (url_contains or "") != "":
            if url_contains not in (event.get("url") or ""):
                continue

        fname_re = r.get("ignore_filename_regex")
        if (fname_re or "") != "":
            try:
                if re.search(fname_re, event.get("file") or "") is None:
                    continue
            except Exception:
                continue

        text_contains = r.get("ignore_text_contains")
        if (text_contains or "") != "":
            text = event.get("details_text") or ""
            if text_contains not in text:
                continue

        return True

    return False


def load_ignore_rules_local() -> Dict:
    path = os.path.join(DATA_DIR, "alarms_config", "ignore_rules.json")
    obj = read_file_json(path)
    if obj is None:
        obj = {"rules": []}
        write_file_json(path, obj)
    return obj


# -------------------------
# LOCAL PATHS
# -------------------------
def alarm_dir(alarm: str) -> str:
    return os.path.join(DATA_DIR, "alarms", alarm)


def state_path(alarm: str) -> str:
    return os.path.join(alarm_dir(alarm), "state.json")


def bytes_path(alarm: str, which: str, name: str) -> str:
    return os.path.join(alarm_dir(alarm), which, name)


def stable_blob_name(key: str, ftype: str) -> str:
    ext = "bin"
    if ftype == "pdf":
        ext = "pdf"
    if ftype == "txt":
        ext = "txt"
    return f"{key}.{ext}"


# -------------------------
# STATE
# -------------------------
def ensure_state_local(alarm: str, alarm_def: Dict) -> Dict:
    p = state_path(alarm)
    st = read_file_json(p)
    if st is not None:
        st.setdefault("active_urls", {})
        st.setdefault("baseline", {})
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

    write_file_json(p, st)
    return st


def save_event_local(alarm: str, event: Dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    folder = os.path.join(alarm_dir(alarm), "events")
    ensure_dir(folder)
    name = f"{ts}_{event.get('event_type','event')}.json"
    path = os.path.join(folder, name)
    write_file_json(path, event)
    return path


# -------------------------
# LOVABLE FEED POST
# -------------------------
def post_to_lovable_feed(items: List[Dict]) -> bool:
    if FEED_POST_URL == "" or FEED_FUNCTION_KEY == "":
        return False

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {FEED_FUNCTION_KEY}",
        "apikey": FEED_FUNCTION_KEY,
        "X-Feed-Function-Key": FEED_FUNCTION_KEY,
    }

    try:
        r1 = SESSION.post(FEED_POST_URL, headers=headers, json=items, timeout=60)
        if r1.status_code < 300:
            return True
        log(f"Feed post status {r1.status_code}: {r1.text[:400]}")
    except Exception as e:
        log(f"Feed post failed: {e}")

    return False


# -------------------------
# OPENAI PDF REPORT
# -------------------------
def openai_pdf_report(alarm_name: str, old_pdf: bytes, new_pdf: bytes, before_name: str, after_name: str) -> str:
    if OPENAI_API_KEY == "":
        return "OpenAI key missing. AI report skipped."

    old_text = extract_pdf_text(old_pdf)
    new_text = extract_pdf_text(new_pdf)

    system_spec = (
        "Compare two PDFs. Old PDF is baseline. New PDF is candidate update.\n\n"
        "OUTPUT FORMAT. STRICT.\n"
        "Title\n"
        "Change Detection Report\n\n"
        "SECTION A. EXECUTIVE RESULT.\n"
        "Fee changes detected: YES or NO\n"
        "L-codes added or removed: YES or NO\n"
        "Ordering or eligibility rule changes: YES or NO\n"
        "Signature or requisition rule changes: YES or NO\n"
        "Administrative or wording only changes: YES or NO\n\n"
        "SECTION B. FEE TABLE.\n"
        "If no changes: No L-code or dollar value changes detected. Fee table identical.\n"
        "If changes exist, list differences only with Before, After, Impact.\n\n"
        "SECTION C. OTHER CHANGES.\n"
        "Show Before paragraph then After paragraph for each changed section.\n\n"
        "SECTION D. IMPACT FLAGS.\n"
        "Financial impact Yes or No.\n"
        "Workflow impact Yes or No.\n"
        "Compliance impact Yes or No.\n\n"
        "SECTION E. FILE METADATA.\n"
        "Before file name and date token.\n"
        "After file name and date token.\n\n"
        "SECTION F. FINAL STATEMENT.\n"
        "One sentence.\n"
    )

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
        txt = (resp.choices[0].message.content or "").strip()
        return txt if txt else "AI output empty."
    except Exception as e:
        return f"OpenAI call failed: {e}"


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
    parts: List[str] = []
    parts.append(f"Added lines: {len(d['added'])}")
    parts.append(f"Removed lines: {len(d['removed'])}")

    if d["added"]:
        parts.append("Sample added")
        parts.extend(d["added"][:max_lines])

    if d["removed"]:
        parts.append("Sample removed")
        parts.extend(d["removed"][:max_lines])

    return "\n".join(parts)


# -------------------------
# RUN ONE ALARM
# -------------------------
def run_alarm(ignore_rules: Dict, alarm: str, alarm_def: Dict) -> None:
    st = ensure_state_local(alarm, alarm_def)
    run_at = now_utc_iso()
    st["last_run_at"] = run_at

    # ---- page signal and discovery ----
    page_signal = ""
    page_url = alarm_def.get("page_url") or ""
    if page_url != "":
        fr_page = fetch(page_url)
        if fr_page.status >= 400 or expected_content_ok("html", fr_page.content_type) is False:
            save_event_local(
                alarm,
                {
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
                },
            )
        else:
            page_signal = normalize_page_signal(fr_page.body)
            write_file_bytes(bytes_path(alarm, "current", "page_signal.txt"), page_signal.encode("utf-8"))
            if st.get("baseline", {}).get("page_signal_sha") is None:
                st["baseline"]["page_signal_sha"] = sha256_bytes(page_signal.encode("utf-8"))
                write_file_bytes(bytes_path(alarm, "baseline", "page_signal.txt"), page_signal.encode("utf-8"))

    discovery_events: List[Dict] = []
    for d in alarm_def.get("discover", []):
        if (d.get("source") or "") != "page":
            continue
        if page_signal == "":
            continue

        new_url = discover_new_file_from_page(page_signal, d["prefix"], d["ext"])
        if new_url is None:
            continue

        key = d["key"]
        old_url = st.get("active_urls", {}).get(key) or ""

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

        changed_name = new_fn != old_fn
        changed_date = (new_token != "") and (new_token != old_token)

        if new_url != old_url and (changed_date or changed_name):
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

    # ---- file checks ----
    file_events: List[Dict] = []
    for wf in alarm_def.get("watch_files", []):
        key = wf["key"]
        ftype = wf["type"]
        url = st.get("active_urls", {}).get(key) or wf["url"]
        st["active_urls"][key] = url

        fr = fetch(url)
        fname = safe_filename_from_url(url)

        # Save current evidence
        write_file_bytes(bytes_path(alarm, "current", fname), fr.body)
        write_file_json(bytes_path(alarm, "current", f"{fname}.meta.json"), meta(fr))

        stable_curr = stable_blob_name(key, ftype)
        write_file_bytes(bytes_path(alarm, "current", stable_curr), fr.body)

        curr_meta = meta(fr)
        curr_meta["source_filename"] = fname
        write_file_json(bytes_path(alarm, "current", f"{key}.meta.json"), curr_meta)

        base_sha_key = f"{key}_sha256"
        base_meta_key = f"{key}_baseline_meta"
        base_file_key = f"{key}_baseline_filename"

        baseline_has = st.get("baseline", {}).get(base_sha_key) is not None

        # Baseline init or forced reset
        if baseline_has is False or FORCE_RESET_BASELINE:
            st["baseline"][base_sha_key] = fr.sha
            st["baseline"][base_meta_key] = curr_meta
            st["baseline"][base_file_key] = fname

            stable_base = stable_blob_name(key, ftype)
            write_file_bytes(bytes_path(alarm, "baseline", stable_base), fr.body)
            write_file_json(bytes_path(alarm, "baseline", f"{key}.meta.json"), curr_meta)

            write_file_bytes(bytes_path(alarm, "baseline", fname), fr.body)
            write_file_json(bytes_path(alarm, "baseline", f"{fname}.meta.json"), curr_meta)

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

    # Persist state after discovery + current fetch
    write_file_json(state_path(alarm), st)

    # ---- suppression ----
    all_events = discovery_events + file_events
    filtered_events: List[Dict] = []

    for ev in all_events:
        if ignore_match(ignore_rules, alarm, ev):
            ev["suppressed"] = True
            ev["suppressed_reason"] = "ignore"
            save_event_local(alarm, ev)
        else:
            filtered_events.append(ev)

    # ---- no change ----
    if len(filtered_events) == 0:
        st["last_no_change_at"] = run_at
        write_file_json(state_path(alarm), st)
        post_discord(f"{alarm} LOW No change. Checked {run_at}", is_change=False)
        return

    # ---- change detected ----
    st["last_change_at"] = run_at
    write_file_json(state_path(alarm), st)

    desc_lines: List[str] = []
    event_types: List[str] = []

    for ev in filtered_events:
        event_types.append(ev.get("event_type") or "unknown")
        save_event_local(alarm, ev)

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
            b1 = str(ev.get("baseline_sha256", ""))[:10]
            b2 = str(ev.get("new_sha256", ""))[:10]
            desc_lines.append(f"type={et} key={ev.get('key','')} file={ev.get('file','')} sha={b1} to {b2}")
        elif et == "discovered_url":
            desc_lines.append(f"type={et} key={ev.get('key','')} url={ev.get('new_url','')}")
        else:
            desc_lines.append(f"type={et} file={ev.get('file','')}")

    # ---- reports ----
    report_texts: List[str] = []

    if alarm_def.get("ai_reports"):
        for wf in alarm_def.get("watch_files", []):
            if wf.get("reference_only"):
                continue
            if wf.get("type") != "pdf":
                continue

            key = wf["key"]

            relevant = any(
                (ev.get("key") == key and ev.get("event_type") in ["new_dated_filename", "file_hash_changed"])
                for ev in filtered_events
            )
            missing = any(
                (ev.get("key") == key and ev.get("event_type") == "file_missing_or_invalid") for ev in filtered_events
            )
            if not relevant or missing:
                continue

            base_blob = stable_blob_name(key, "pdf")
            curr_blob = stable_blob_name(key, "pdf")

            base_bytes = read_file_bytes(bytes_path(alarm, "baseline", base_blob))
            curr_bytes = read_file_bytes(bytes_path(alarm, "current", curr_blob))
            if base_bytes is None or curr_bytes is None:
                continue

            baseline_fname = st["baseline"].get(f"{key}_baseline_filename") or base_blob
            curr_meta = read_file_json(bytes_path(alarm, "current", f"{key}.meta.json")) or {}
            current_fname = curr_meta.get("source_filename") or curr_blob

            txt = openai_pdf_report(alarm, base_bytes, curr_bytes, str(baseline_fname), str(current_fname))
            report_texts.append(txt)

            pdf_bytes = render_pdf(alarm_def.get("report_title") or "Change Detection Report", txt)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
            rep_name = f"{ts}_{key}_change_report.pdf"
            write_file_bytes(bytes_path(alarm, "reports", rep_name), pdf_bytes)

    if alarm == "OHIP_PHS_Fee_Sche_Master":
        wf_txt = next((x for x in alarm_def.get("watch_files", []) if x.get("type") == "txt"), None)
        if wf_txt is not None:
            key = wf_txt["key"]
            relevant = any(
                (ev.get("key") == key and ev.get("event_type") == "file_hash_changed") for ev in filtered_events
            )
            if relevant:
                base_blob = stable_blob_name(key, "txt")
                curr_blob = stable_blob_name(key, "txt")
                base_bytes = read_file_bytes(bytes_path(alarm, "baseline", base_blob))
                curr_bytes = read_file_bytes(bytes_path(alarm, "current", curr_blob))
                if base_bytes is not None and curr_bytes is not None:
                    old_txt = base_bytes.decode("utf-8", errors="ignore")
                    new_txt = curr_bytes.decode("utf-8", errors="ignore")
                    summary = summarize_txt_diff(old_txt, new_txt, max_lines=30)
                    report_texts.append(summary)

                    pdf_bytes = render_pdf(alarm_def.get("report_title") or "TXT Change Report", summary)
                    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
                    rep_name = f"{ts}_{key}_txt_change_report.pdf"
                    write_file_bytes(bytes_path(alarm, "reports", rep_name), pdf_bytes)

    # ---- rss + feed payload ----
    desc = " | ".join(desc_lines)
    if report_texts:
        desc = desc + " | AI " + " ".join([t[:600] for t in report_texts])

    guid = f"{alarm}:changed:{now_utc_iso()}:{sha256_bytes(desc.encode('utf-8'))[:12]}"
    pub = rfc2822_now()

    rss_item = {
        "title": f"{alarm} HIGH Change detected",
        "description": desc,
        "link": OHIP_PAGE_URL,
        "guid": guid,
        "pubDate": pub,
    }

    rss_xml = build_rss(
        channel_title=f"{alarm} changed",
        channel_desc=f"{alarm} change feed",
        channel_link=OHIP_PAGE_URL,
        items=[rss_item],
    )
    write_file_bytes(bytes_path(alarm, "feeds", "changed.xml"), rss_xml.encode("utf-8"))

    feed_payload_item = {
        "title": rss_item["title"],
        "url": rss_item["link"],
        "published_at": run_at,
        "source": "OHIP Alarm",
        "type": "Alarm",
        "summary": rss_item["description"][:4000],
        "guid": rss_item["guid"],
        "alarm": alarm,
        "event_types": list(sorted(set(event_types))),
    }

    posted = post_to_lovable_feed([feed_payload_item])
    post_discord(f"{alarm} HIGH Change detected. Feed post ok={posted}", is_change=True)

    # ---- baseline roll forward ----
    if RESET_BASELINE_ON_CHANGE:
        changed_keys = sorted(
            list(
                set(
                    [
                        ev.get("key")
                        for ev in filtered_events
                        if ev.get("key") and ev.get("event_type") in ["new_dated_filename", "file_hash_changed"]
                    ]
                )
            )
        )

        for wf in alarm_def.get("watch_files", []):
            key = wf["key"]
            if key not in changed_keys:
                continue
            if wf.get("reference_only"):
                continue

            missing = any(
                (ev.get("key") == key and ev.get("event_type") == "file_missing_or_invalid") for ev in filtered_events
            )
            if missing:
                continue

            ftype = wf["type"]
            curr_blob = stable_blob_name(key, ftype)
            curr_bytes = read_file_bytes(bytes_path(alarm, "current", curr_blob))
            curr_meta = read_file_json(bytes_path(alarm, "current", f"{key}.meta.json")) or {}

            if curr_bytes is None:
                continue

            base_blob = stable_blob_name(key, ftype)
            write_file_bytes(bytes_path(alarm, "baseline", base_blob), curr_bytes)
            write_file_json(bytes_path(alarm, "baseline", f"{key}.meta.json"), curr_meta)

            st["baseline"][f"{key}_sha256"] = sha256_bytes(curr_bytes)
            st["baseline"][f"{key}_baseline_meta"] = curr_meta
            st["baseline"][f"{key}_baseline_filename"] = curr_meta.get("source_filename") or base_blob

        write_file_json(state_path(alarm), st)
        post_discord(f"{alarm} LOW Baseline reset after change. Keys {','.join(changed_keys)}", is_change=True)


# -------------------------
# MAIN
# -------------------------
def main() -> None:
    log("BOOT main reached")
    ensure_dir(DATA_DIR)

    ignore_rules = load_ignore_rules_local()

    if FEED_POST_URL == "" or FEED_FUNCTION_KEY == "":
        log("Feed vars missing. Set FEED_POST_URL and FEED_FUNCTION_KEY.")
        post_discord("Alarm runner started. Feed vars missing.", is_change=False)

    for alarm, alarm_def in ALARM_DEFS.items():
        try:
            run_alarm(ignore_rules, alarm, alarm_def)
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




