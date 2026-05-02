"""
run.py  — LLM Artifact Forensic Tool (Unified)
═══════════════════════════════════════════════════════════════════════
All logic in one file. Run:
    python run.py

Steps performed:
  1. App selection menu (ChatGPT / Claude)
  2. Directory scanning & path detection
  3. Data extraction + merge with historical recovered data
  4. Single readable report in reports/ root (Markdown)
     • reports/CHATGPT_FORENSIC_REPORT.md  — or —
     • reports/CLAUDE_FORENSIC_REPORT.md
"""

import sys
import io
import os
import re
import json
import glob
import struct
import shutil
import hashlib
import gzip
import time
from datetime import datetime, timezone
import unicodedata
from pathlib import Path

BASE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(BASE, "reports")
os.makedirs(REPORTS, exist_ok=True)

LOCAL = os.getenv("LOCALAPPDATA", "")
APPDATA = os.getenv("APPDATA", "")
IST = 5.5 * 3600   # seconds offset for IST


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def ts_ist(ts: float) -> str:
    if not ts or ts < 1e9:
        return "Unknown"
    return datetime.fromtimestamp(ts + IST, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S IST")


def _safe_read(path: str) -> bytes:
    try:
        tmp = path + f"._r{os.getpid()}"
        shutil.copy2(path, tmp)
        with open(tmp, "rb") as f:
            data = f.read()
        os.remove(tmp)
        return data
    except Exception:
        return b""


def _snappy_sliding(raw: bytes):
    try:
        import cramjam
        CHUNK = 65536
        out = []
        for i in range(0, min(len(raw), 4*1024*1024), CHUNK//4):
            try:
                d = bytes(cramjam.snappy.decompress(raw[i:i+CHUNK]))
                if len(d) > 64:
                    out.append(d)
            except Exception:
                pass
        return out
    except ImportError:
        return []


def _sep(c="─", w=62):
    print(c * w)


def _header(title: str):
    _sep("═")
    print(f"  {title}")
    _sep("═")

# ═══════════════════════════════════════════════════════════════════════════════
# Noise Filtering
# ═══════════════════════════════════════════════════════════════════════════════


_NOISE = [
    "[No cached content]", '{"conversation_id"', "}},",
    '"title":', '"is_archived"', '"mapping"', "current_node_id",
    "accountUserId", 'id"$', "client-created-root",
    '"kind":"message"', '"snippet":', "created=20", "updated=20",
    "og:url", "og:title", "<meta ", "and be more productive",
    "chatgpt.com_0", '"model":', '"is_do_not', "webRTC",
    "CERTIFICATE", "-----BEGIN",
]
_JSON_RE = re.compile(r'\{["\w]+:')
_HTML_RE = re.compile(r'<[a-zA-Z][^>]{0,30}>')


def _trim_glued_forensic_snippet(s: str) -> str:
    """Strip trailing JSON accidentally concatenated onto message snippets."""
    if not s:
        return s
    markers = (
        '"}},{"conversation_id"',
        '\\"}},{\\"conversation_id\\"',
        '"},{"conversation_id"',
        '}},{\"conversation_id\"',
        '\\"}},{\\"current_node_id\\"',
    )
    cut = len(s)
    for m in markers:
        i = s.find(m)
        if i >= 0:
            cut = min(cut, i)
    s = s[:cut].rstrip().rstrip('"').rstrip("\\")
    return s.strip()


def is_real(s: str) -> bool:
    s = s.strip()
    if not s or len(s) < 2:
        return False
    for n in _NOISE:
        if n in s:
            return False
    if _JSON_RE.search(s[:80]) or _HTML_RE.search(s[:120]):
        return False
    if s.startswith("<"):
        return False
    # Unicode letters (not just ASCII) — avoids dropping Indic/CJK/etc.
    letters = sum(
        1 for c in s if c.isalpha() or unicodedata.category(c).startswith("L")
    )
    return letters >= len(s) * 0.28


# ═══════════════════════════════════════════════════════════════════════════════
# PATH DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

def discover_chatgpt_paths() -> dict:
    """Find ChatGPT Desktop app data directories."""
    pat = os.path.join(LOCAL, "Packages", "OpenAI.ChatGPT-Desktop_*",
                       "LocalCache", "Roaming", "ChatGPT")
    roots = glob.glob(pat)
    if not roots:
        return {}
    root = roots[0]
    idb = os.path.join(root, "IndexedDB")
    return {
        "app_root": root,
        "idb_ldb":  os.path.join(idb, "https_chatgpt.com_0.indexeddb.leveldb"),
        "idb_blob": os.path.join(idb, "https_chatgpt.com_0.indexeddb.blob"),
        "ls_ldb":   os.path.join(root, "Local Storage", "leveldb"),
        "cache":    os.path.join(root, "Cache", "Cache_Data"),
    }


def discover_claude_paths() -> dict:
    """Find Claude Desktop app data directories."""
    candidates = [
        os.path.join(LOCAL, "Packages", "AnthropicPBC.ClaudeAI_*",
                     "LocalCache", "Roaming", "Claude"),
        os.path.join(APPDATA, "Claude"),
        os.path.join(LOCAL,   "Claude"),
    ]
    for cand in candidates:
        roots = glob.glob(
            cand) if "*" in cand else ([cand] if os.path.isdir(cand) else [])
        if roots:
            root = roots[0]
            return {
                "app_root": root,
                "cache":    os.path.join(root, "Cache", "Cache_Data"),
                "ls_ldb":   os.path.join(root, "Local Storage", "leveldb"),
                "idb_ldb":  os.path.join(root, "IndexedDB"),
            }
    return {}


def _scan_dirs(paths: dict) -> list:
    """Print detected directories and return list of found ones."""
    found = []
    for label, path in paths.items():
        if label == "app_root":
            continue
        exists = os.path.isdir(path)
        status = "✓ FOUND" if exists else "✗ missing"
        fc = ""
        if exists:
            files = glob.glob(os.path.join(path, "**", "*"), recursive=True)
            fc = f"  ({len(files)} files)"
        print(f"    [{status}] {label}: {path}{fc}")
        if exists:
            found.append(path)
    return found


# ═══════════════════════════════════════════════════════════════════════════════
# CHATGPT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def _ls_conversation_history(ls_dir: str) -> list:
    """Parse 'conversation-history' JSON from Local Storage LDB/LOG files."""
    results = []
    all_files = (
        sorted(glob.glob(os.path.join(ls_dir, "*.log")), key=os.path.getmtime, reverse=True) +
        sorted(glob.glob(os.path.join(ls_dir, "*.ldb")),
               key=os.path.getmtime, reverse=True)
    )
    pat = re.compile(
        r'conversation-history[^\{]{0,40}(\{"value":\{"pages":\[)')
    for fpath in all_files:
        raw = _safe_read(fpath)
        if not raw:
            continue
        text = raw.decode("utf-8", errors="replace")
        for m in pat.finditer(text):
            start = m.start(1)
            depth, end = 0, start
            for i in range(start, min(start + 800_000, len(text))):
                c = text[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            if end <= start:
                continue
            try:
                payload = json.loads(text[start:end])
            except Exception:
                continue
            pages = (payload.get("value") or payload).get("pages", [])
            for page in pages:
                for item in (page.get("items") or []):
                    if not isinstance(item, dict):
                        continue
                    cid = (item.get("id") or "").strip()
                    title = (item.get("title") or "").strip()
                    ts = 0.0
                    for ts_str in (item.get("update_time", ""), item.get("create_time", "")):
                        if ts_str:
                            try:
                                ts = datetime.fromisoformat(
                                    ts_str.replace("Z", "+00:00")).timestamp()
                                break
                            except Exception:
                                pass
                    results.append({
                        "conversation_id": cid,
                        "title": title,
                        "update_time": ts,
                        "is_archived": bool(item.get("is_archived")),
                        "is_starred":  bool(item.get("is_starred")),
                    })
    # Deduplicate
    seen: dict = {}
    for r in results:
        cid = r["conversation_id"]
        if cid not in seen or r["update_time"] > seen[cid]["update_time"]:
            seen[cid] = r
    return list(seen.values())


def run_chatgpt(paths: dict):
    """Full ChatGPT extraction pipeline → single report.
    Fully portable: works on any machine with ChatGPT Desktop installed.
    RECOVERED_CHATGPT_GROUPED.json is optionally merged as historical bonus.
    """
    _sep("─")

    SKIP = {"Unknown (deleted/orphaned conversation)", "New chat", "Student",
            "Test message response", "Testing cache behavior", "Deleted Fragment Recovery", ""}

    convs: dict = {}

    def upsert(cid, title, ts, is_arch, is_star, msgs, trust_ts=True):
        key = cid if cid else title[:40]
        if not key:
            return
        prev = convs.get(key)
        if prev is None:
            convs[key] = {"cid": cid, "title": title, "ts": ts,
                          "is_archived": is_arch, "is_starred": is_star,
                          "msgs": list(msgs)}
            return
        if cid and not prev["cid"]:
            prev["cid"] = cid
        if title and title not in SKIP:
            prev["title"] = title
        if trust_ts and ts > float(prev["ts"] or 0) and ts < 1_773_902_000:
            prev["ts"] = ts
        prev["is_archived"] = is_arch or prev["is_archived"]
        prev["is_starred"] = is_star or prev["is_starred"]
        seen = {m["snippet"][:100] for m in prev["msgs"]}
        for m in msgs:
            if m["snippet"][:100] not in seen:
                prev["msgs"].append(m)
                seen.add(m["snippet"][:100])

    def conv_to_msgs(item):
        ts = float(
            item.get("update_time")
            or item.get("latest_update")
            or 0
        )
        out = []
        for m in (item.get("messages") or []):
            snip = (m.get("snippet") or m.get("text") or "").strip()
            snip = _trim_glued_forensic_snippet(snip)
            if is_real(snip):
                out.append({"mid":     (m.get("message_id") or m.get("id") or ""),
                            "role":    (m.get("role") or "unknown").lower(),
                            "snippet": snip[:4000],
                            "ts":      float(m.get("timestamp") or m.get("update_time") or ts)})
        return out

    print("  [1/3] Full LevelDB + Cache scan (live) …")
    try:
        import chatgpt_extractor as cex
        live_convs = cex.run(verbose=False)
        for item in live_convs:
            cid = (item.get("conversation_id") or "").strip()
            title = (item.get("title") or "").strip()
            if title in SKIP:
                continue
            ts = float(item.get("update_time") or 0)
            msgs = conv_to_msgs(item)
            upsert(cid, title, ts,
                   bool(item.get("is_archived")), bool(item.get("is_starred")),
                   msgs, trust_ts=True)
        print(f"      → {len(live_convs)} live conversations found")
        print(f"      → {len(convs)} unique after dedup")
    except Exception as e:
        print(f"      [warn] Live scan error: {e}")

    print("  [2/3] Applying accurate timestamps from Local Storage …")
    ls_dir = paths.get("ls_ldb", "")
    if os.path.isdir(ls_dir):
        ch = _ls_conversation_history(ls_dir)
        applied = 0
        for entry in ch:
            ecid = entry.get("conversation_id", "")
            etitle = entry.get("title", "")
            ets = float(entry.get("update_time") or 0)
            key = ecid if ecid else etitle[:40]
            if key in convs and ets > 1e9:
                convs[key]["ts"] = ets
                if etitle:
                    convs[key]["title"] = etitle
                applied += 1
        print(f"      → {len(ch)} LS entries, {applied} timestamps corrected")
    else:
        print("      → Local Storage not found")

    old_file = os.path.join(REPORTS, "RECOVERED_CHATGPT_GROUPED.json")
    if os.path.isfile(old_file):
        print("  [3/4] Merging historical data (RECOVERED_CHATGPT_GROUPED.json) …")
        try:
            old_raw = json.load(open(old_file, encoding="utf-8"))
            old_items = old_raw if isinstance(
                old_raw, list) else old_raw.get("items", [])
            pre = len(convs)
            for item in old_items:
                cid = (item.get("conversation_id") or "").strip()
                title = (item.get("title") or "").strip()
                if title in SKIP:
                    continue
                ts = float(item.get("latest_update")
                           or item.get("update_time") or 0)
                msgs = conv_to_msgs(item)
                upsert(cid, title, ts,
                       bool(item.get("is_archived")), bool(
                           item.get("is_starred")),
                       msgs, trust_ts=(ts < 1_773_901_000))
            added = len(convs) - pre
            print(
                f"      → {len(old_items)} records, {added} new conversations added from history")
        except Exception as e:
            print(f"      [warn] Historical merge failed: {e}")
    else:
        print("  [3/4] No historical file — running in portable (live-only) mode")

    print("  [4/4] Scanning LevelDB logs (WAL) for very latest chats …")
    wal_files = glob.glob(os.path.join(ls_dir, "*.log"))
    if wal_files:
        found_wal = 0
        for fpath in wal_files:
            raw = _safe_read(fpath)
            if len(raw) < 100:
                continue
            text = raw.decode("utf-8", errors="replace")
            # Look for conversation_id fragments (regular UUID4)
            for cid_m in re.finditer(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', text):
                cid = cid_m.group(1)
                window = text[cid_m.start(): cid_m.start() + 4000]
                # Carve latest readable strings
                runs = re.findall(r'[A-Za-z][^\x00-\x1f]{20,3000}', window)
                for run in runs:
                    if is_real(run) and len(run) >= 35:
                        key = cid
                        if key in convs:
                            seen = {m["snippet"][:100]
                                    for m in convs[key]["msgs"]}
                            if run[:100] not in seen:
                                # Guess role
                                role = "assistant"
                                if "user" in window[max(0, window.find(run)-100): window.find(run)]:
                                    role = "user"
                                convs[key]["msgs"].append({
                                    "mid": "", "role": role, "snippet": run[:4000], "ts": time.time()
                                })
                                found_wal += 1
                                break
        if found_wal:
            print(
                f"      → {found_wal} 'live' snippets recovered from WAL logs")
    else:
        print("      → No WAL log files found to carve")

    # ── Build output ────────────────────────────────────────────
    print("      Building report …")
    clist = sorted(convs.values(), key=lambda c: float(
        c["ts"] or 0), reverse=True)
    out_items = []
    for conv in clist:
        cid = conv["cid"]
        title = conv["title"]
        ts = float(conv["ts"] or 0)
        msgs = sorted(conv["msgs"], key=lambda m: m.get("ts", 0))
        if not msgs:
            out_items.append({
                "conversation_id": cid, "current_node_id": "",
                "title": title, "model": "",
                "is_archived": conv["is_archived"], "is_starred": conv["is_starred"],
                "update_time": ts,
                "payload": {"kind": "message", "message_id": "",
                            "snippet": "[No content recovered — metadata only]", "role": ""}
            })
        else:
            for m in msgs:
                out_items.append({
                    "conversation_id": cid, "current_node_id": m["mid"],
                    "title": title, "model": "",
                    "is_archived": conv["is_archived"], "is_starred": conv["is_starred"],
                    "update_time": ts,
                    "payload": {"kind": "message", "message_id": m["mid"],
                                "snippet": m["snippet"], "role": m["role"]}
                })

    chatgpt_cids = sorted({x["conversation_id"] for x in out_items})
    _write_report("CHATGPT", chatgpt_cids, out_items)


def _scan_claude_idb_blob(paths: dict) -> list:
    """
    Scan Claude IndexedDB blob — stores all conversations including latest.

    Two-pass approach (discovered from raw blob analysis):
    - Blob 83 (large file):  conversations_v2 list → uuid, name, ts, leaf_msg_uuid
    - Blob 89+ (small files): individual message blobs → msg_uuid, role, text

    Pass 1: extract conversation metadata from the large conversations blob
    Pass 2: extract message content from message blobs  
    Join:   match via leaf_message uuid
    """
    idb_root = paths.get("idb_ldb", "")
    app_root = paths.get("app_root", "")

    blob_dirs = (
        glob.glob(os.path.join(idb_root, "*indexeddb.blob")) +
        glob.glob(os.path.join(app_root, "IndexedDB", "*indexeddb.blob"))
    )
    if not blob_dirs:
        return []
    blob_base = blob_dirs[0]

    # Gather all blob files + LevelDB logs (WAL) to catch latest un-compacted chats
    all_blobs = (
        glob.glob(os.path.join(blob_base, "1", "*")) +
        glob.glob(os.path.join(blob_base, "1", "**", "*"), recursive=True)
    )
    # Include LevelDB .log files from the IndexedDB structure
    all_blobs += glob.glob(os.path.join(idb_root, "**",
                           "*.log"), recursive=True)

    all_blobs = [f for f in all_blobs if os.path.isfile(f)]
    if not all_blobs:
        return []

    # Use all blobs for both passes (may be a single large blob with all data)
    conv_blobs = all_blobs

    # V8 blobs encode strings with length-prefix bytes before content
    # UUIDs appear as: uuid"[\x04][\x24]a1a60db8-... OR uuid"$a1a60db8-...
    # The \x24 IS the '$' character (ASCII 36)
    UUID4_RE = re.compile(
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')
    CONV_UUID_RE = re.compile(
        r'uuid["\s\x00-\x1f$]{0,12}'
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    )
    NAME_RE = re.compile(r'name["\s\x00-\x1f]{0,8}([^\x00-\x1f"\\]{3,120})')
    UPD_RE = re.compile(
        r'updated_a[tN\x00-\x1f][".\s\x00-\x1f]{0,10}(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)')
    MODEL_RE = re.compile(r'(claude-[a-z0-9\-]{3,30})')
    # leaf_message UUID: 5+ arbitrary bytes between key and UUID
    # Observed: leaf_message[05]>\xef\xbf\xbd"$019d0472-...
    # Allow any non-hex chars (up to 20) between tag and UUID
    LEAF_RE = re.compile(
        r'leaf_message.{1,25}'
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    )
    SENDER_RE = re.compile(
        r'sender["\s\x00-\x1f]{0,10}(human|assistant)', re.I)

    # Noise strings to filter out of titles
    NOI_TITLE = ["anthropic.com", "http", "MANIFEST", "claude.ai", "<server",
                 "onT", "offF", "defaultValue", "experimentResult",
                 "ruleId", "dataUpdate", "current_acc", "user_", "assistant"]

    # ── PASS 1: Extract conversation metadata from large blob(s) ──────────
    # conv_map: {conv_uuid → {title, ts, model, leaf_uuid}}
    conv_map: dict = {}

    for fpath in conv_blobs:
        raw = _safe_read(fpath)
        if len(raw) < 100:
            continue
        text = raw.decode("utf-8", errors="replace")

        # Find all conversation-level uuid matches
        # Also search raw bytes for '$'-prefixed UUIDs that CONV_UUID_RE may miss
        for um in CONV_UUID_RE.finditer(text):
            cid = um.group(1)
            window = text[um.start(): um.start() + 1000]

            nm = NAME_RE.search(window)
            if not nm:
                continue

            title = nm.group(1).strip()
            # Filter noise
            if any(n in title for n in NOI_TITLE):
                continue
            alpha = sum(1 for c in title if c.isalpha())
            if alpha < len(title) * 0.35 or len(title) > 120:
                continue

            ts = 0.0
            udm = UPD_RE.search(window)
            if udm:
                try:
                    ts = datetime.fromisoformat(
                        udm.group(1).replace("Z", "+00:00")).timestamp()
                except Exception:
                    pass

            model_m = MODEL_RE.search(window)
            model = model_m.group(1) if model_m else ""

            # Find leaf_message uuid (the latest message uuid)
            leaf_m = LEAF_RE.search(window)
            leaf_uuid = leaf_m.group(1) if leaf_m else ""

            if cid not in conv_map or ts > conv_map[cid].get("ts", 0):
                conv_map[cid] = {
                    "title": title,
                    "ts": ts,
                    "model": model,
                    "leaf_uuid": leaf_uuid,
                }

    # ── PASS 2: Extract message content from message blobs ────────────────
    # msg_map: {msg_uuid → {role, text}}
    msg_map: dict = {}

    for fpath in all_blobs:
        raw = _safe_read(fpath)
        if len(raw) < 20:
            continue
        text = raw.decode("utf-8", errors="replace")

        # Message blobs have: uuid → user_/sender → content → sender"human/assistant"
        # Look for uuid4 patterns followed by readable text + sender tag
        for um in UUID4_RE.finditer(text):
            mid = um.group(1)
            zone = text[um.start(): um.start() + 3000]

            # Check it has sender marker (conversation blobs have this too but
            # message blobs have very clean text runs near sender)
            sender_m = SENDER_RE.search(zone)
            if not sender_m:
                continue

            role = "user" if sender_m.group(
                1).lower() == "human" else "assistant"

            # V8 blob stores message text in a 'text"' field before sender tag.
            # Raw: ...text"[NUL][len]i want u to write me a[len]sender"human"...
            # Strategy 1: find explicit text" field
            best = ""
            tf_pos = zone.find('text"')
            if tf_pos >= 0 and tf_pos < sender_m.start():
                # content starts a few bytes after 'text"'
                txt_zone = zone[tf_pos + 5: tf_pos + 4005]
                runs = re.findall(
                    r'[A-Za-z][^\x00-\x08\x0b\x0e-\x1f]{14,4000}', txt_zone)
                for run in runs:
                    run = run.strip()
                    run = re.split(
                        r'(?:uuid|name"|sender|updated_a|model"|leaf_message|is_temp)',
                        run)[0].strip()
                    if is_real(run) and len(run) >= 15:
                        best = run[:4000]
                        break

            # Strategy 2: last 600 chars before sender tag
            if not best:
                before = zone[max(0, sender_m.start()-600): sender_m.start()]
                runs = re.findall(
                    r'[A-Za-z][^\x00-\x08\x0b\x0e-\x1f]{14,2000}', before)
                for run in runs:
                    run = run.strip()
                    run = re.split(
                        r'(?:uuid|name"|sender|updated_a|model"|leaf_message|is_temp)',
                        run)[0].strip()
                    if is_real(run) and len(run) >= 15 and len(run) > len(best):
                        best = run[:4000]

            # Strip V8 binary prefix (type/u/t/{X+ chars before actual text)
            if best:
                # Aggressive strip: remove non-ascii and up to 15 leading chars if they look like V8 tags
                clean = re.sub(
                    r'^(?:(?:type|user|text|human)[\s\x00-\x1fA-Za-z0-9+/{\[]*?)?[^A-Za-z0-9]+', '', best)
                if not clean or len(clean) < 10:
                    clean = best.split(
                        '+', 1)[-1].strip() if '+' in best[:50] else best[10:].strip()
                if len(clean) >= 10:
                    best = clean
            if best and mid not in msg_map:
                msg_map[mid] = {"role": role, "text": best}

    # ── JOIN: Merge conversations with their leaf message content ─────────
    items = []
    for cid, conv in conv_map.items():
        title = conv["title"]
        ts = conv["ts"]
        model = conv["model"]
        leaf_uuid = conv["leaf_uuid"]

        msg = msg_map.get(leaf_uuid) if leaf_uuid else None

        if msg:
            items.append({
                "conversation_id": cid,
                "current_node_id": leaf_uuid,
                "title": title,
                "model": model,
                "is_archived": False,
                "is_starred":  False,
                "update_time": ts,
                "payload": {
                    "kind": "message",
                    "message_id": leaf_uuid,
                    "snippet": msg["text"],
                    "role": msg["role"],
                }
            })
        else:
            items.append({
                "conversation_id": cid,
                "current_node_id": "",
                "title": title,
                "model": model,
                "is_archived": False,
                "is_starred":  False,
                "update_time": ts,
                "payload": {
                    "kind": "message",
                    "message_id": "",
                    "snippet": "[No content recovered — metadata only]",
                    "role": "",
                }
            })

    # Deduplicate
    seen_idb: set = set()
    deduped = []
    for it in items:
        key = f"{it['conversation_id']}::{it['payload']['snippet'][:60]}"
        k = hashlib.md5(key.encode()).hexdigest()
        if k not in seen_idb:
            seen_idb.add(k)
            deduped.append(it)
    return deduped


def run_claude(paths: dict):
    print("  [1/4] Attempting live cache extraction …")
    live_items = []
    try:
        import claude_extractor
        live_convs = claude_extractor.run(verbose=False)
        for h in live_convs:
            for m in h.get("messages", []):
                snip = m.get("snippet", "").strip()
                if not is_real(snip):
                    continue
                live_items.append({
                    "conversation_id": h.get("conversation_id", ""),
                    "current_node_id": m.get("message_id", ""),
                    "title": h.get("title", ""),
                    "model": h.get("model", ""),
                    "is_archived": False,
                    "is_starred":  False,
                    "update_time": float(h.get("update_time") or 0),
                    "payload": {
                        "kind": "message",
                        "message_id": m.get("message_id", ""),
                        "snippet": snip[:4000],
                        "role": m.get("role", "unknown")
                    }
                })
        print(f"      → {len(live_items)} live messages found")
    except Exception as e:
        print(f"      → Live extraction failed: {e}")

    # ── Stage 2: IndexedDB Blob scan (where latest chats live!) ──────────
    print("  [2/4] Scanning IndexedDB blob (latest conversations) …")
    idb_items = []
    try:
        idb_items = _scan_claude_idb_blob(paths)
        real_idb = sum(1 for x in idb_items
                       if not x["payload"]["snippet"].startswith("[No content"))
        print(
            f"      → {len(idb_items)} items from IDB blob ({real_idb} with real content)")
    except Exception as e:
        print(f"      → IDB blob scan failed: {e}")

    # ── Stage 3: RECOVERED_CLAUDE_HISTORY.json ───────────────────────────
    print("  [3/4] Loading previously recovered Claude history …")
    rec_file = os.path.join(REPORTS, "RECOVERED_CLAUDE_HISTORY.json")
    rec_items = []
    if os.path.isfile(rec_file):
        rec_raw = json.load(open(rec_file, encoding="utf-8"))
        rec_items = rec_raw.get("items", [])
        print(
            f"      → {len(rec_items)} items in RECOVERED_CLAUDE_HISTORY.json")
    else:
        print(f"      → {rec_file} not found")

    # ── Stage 4: Merge all items — real content AND metadata-only ─────────────────
    print("  [4/4] Merging & deduplicating …")

    _TS_PAT = re.compile(r'(?:updated|created)=(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)')

    def _parse_iso_from_snippet(snip: str) -> float:
        """Extract timestamp from '[No cached content] updated=...' strings."""
        for m in _TS_PAT.finditer(snip):
            try:
                return datetime.fromisoformat(
                    m.group(1).replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
        return 0.0

    def _clean_item(item: dict) -> dict:
        """Return a schema-clean copy — remove source_file, fix timestamps."""
        snip = (item.get("payload", {}).get("snippet") or "").strip()
        ts = float(item.get("update_time") or 0)

        # For meta-only: parse better ts from snippet if main ts looks wrong
        is_meta = snip.startswith("[No cached content]") or not is_real(snip)
        if is_meta:
            parsed_ts = _parse_iso_from_snippet(snip)
            if parsed_ts > 1e9:
                ts = parsed_ts
            snip = "[No content recovered — metadata only]"

        return {
            "conversation_id": (item.get("conversation_id") or "").strip(),
            "current_node_id": (item.get("current_node_id") or "").strip(),
            "title":           (item.get("title") or "").strip(),
            "model":           (item.get("model") or ""),
            "is_archived":     bool(item.get("is_archived")),
            "is_starred":      bool(item.get("is_starred")),
            "update_time":     ts,
            "payload": {
                "kind":       item.get("payload", {}).get("kind", "message"),
                "message_id": (item.get("payload", {}).get("message_id") or "").strip(),
                "snippet":    snip[:4000],
                "role":       (item.get("payload", {}).get("role") or "").strip(),
            },
        }

    seen_keys: set = set()
    out_items: list = []

    def add_item(item: dict):
        clean = _clean_item(item)
        cid = clean["conversation_id"]
        # Prefer message_id as it's truly unique per message; current_node_id is often per-turn
        mid = clean["payload"].get("message_id") or clean["current_node_id"]
        role = clean["payload"].get("role") or ""
        snip = clean.get("payload", {}).get("snippet", "")

        # Dedup key: (cid, mid, role) or (cid, snippet_hash) for meta-only
        if mid:
            key = f"{cid}::{mid}::{role}"
        else:
            key = f"{cid}::{hashlib.md5(snip[:80].encode()).hexdigest()}"

        if key not in seen_keys:
            seen_keys.add(key)
            out_items.append(clean)

    # IDB blob first — has the LATEST conversations
    for item in idb_items:
        add_item(item)
    # RECOVERED_CLAUDE_HISTORY next (historical depth)
    for item in rec_items:
        add_item(item)
    # Live cache last
    for item in live_items:
        add_item(item)

    # Sort newest → oldest
    out_items.sort(key=lambda x: float(x.get("update_time", 0)), reverse=True)

    cid_set = {x["conversation_id"] for x in out_items}
    total_real = sum(1 for x in out_items
                     if not x["payload"]["snippet"].startswith("[No content"))

    print(f"      → {len(out_items)} total items ({total_real} with real content, "
          f"{len(out_items)-total_real} metadata-only)")

    _write_report("CLAUDE", list(cid_set), out_items, is_claude=True)


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT WRITER (single-file output)
# ═══════════════════════════════════════════════════════════════════════════════

def _write_report(app: str, clist, out_items: list, is_claude: bool = False):
    now = ts_ist(datetime.utcnow().timestamp())
    total_convs = len(clist)
    with_content = sum(1 for x in out_items
                       if not x["payload"]["snippet"].startswith("[No content"))

    md_path = os.path.join(REPORTS, f"{app}_FORENSIC_REPORT.md")

    # ── Markdown report ───────────────────────────────────────────────────
    # Group items by conversation_id for readable report
    by_conv: dict = {}
    for item in out_items:
        cid = item["conversation_id"]
        by_conv.setdefault(cid, []).append(item)

    lines = [
        f"# {app} Forensic Extraction Report\n\n",
        f"**Generated:** {now}  \n",
        f"**App:** {app}  \n",
        f"**Conversations:** {total_convs}  \n",
        f"**Messages with content:** {with_content}  \n\n",
        "---\n\n",
    ]

    # Sort conversations by newest message
    def conv_ts(items_list):
        return max((float(x.get("update_time", 0)) for x in items_list), default=0)

    for cid, citems in sorted(by_conv.items(), key=lambda kv: conv_ts(kv[1]), reverse=True):
        title = citems[0].get("title", "(untitled)")
        ts = conv_ts(citems)
        lines.append(f"\n## {title}\n\n")
        lines.append(f"**Last updated (IST):** {ts_ist(ts)}  \n")
        lines.append(f"**Conversation ID:** `{cid}`\n\n")
        msgs_sorted = sorted(
            citems, key=lambda x: float(x.get("update_time", 0)))
        has_real = any(not x["payload"]["snippet"].startswith(
            "[No content") for x in msgs_sorted)
        if not has_real:
            lines.append("*[No message content recovered — metadata only]*\n")
        else:
            for item in msgs_sorted:
                snip = item["payload"]["snippet"]
                if snip.startswith("[No content"):
                    continue
                role = (item["payload"].get("role") or "unknown").upper()
                mt = ts_ist(float(item.get("update_time", 0)))
                lines.append(f"**[{mt}] {role}:**\n\n{snip}\n\n")
        lines.append("---\n")

    with open(md_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    _sep()
    print(f"\n  ✓ DONE — {app}")
    print(f"    Conversations  : {total_convs}")
    print(f"    Messages found : {with_content}")
    print(f"\n    Report → {md_path}")
    _sep()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║          LLM Artifact Forensic Tool  v3.0                        ║
║          Digital Evidence Recovery — ChatGPT & Claude            ║
╚══════════════════════════════════════════════════════════════════╝
"""

MENU = """
  Select Application:
  ─────────────────────────────────────────
    1.  ChatGPT
    2.  Claude
    0.  Exit
  ─────────────────────────────────────────
  Enter choice [0/1/2]: """


def main():
    # UTF-8 output for Windows terminal
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace")
    print(BANNER)

    while True:
        try:
            choice = input(MENU).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  Exiting.")
            break

        if choice not in ("0", "1", "2"):
            print("  Invalid choice.")
            continue

        if choice == "0":
            print("\n  Exiting.")
            break

        app = "ChatGPT" if choice == "1" else "Claude"
        _header(f"{app} Forensic Extraction")

        # ── Path detection ──────────────────────────────────────────────
        print(f"\n  Scanning for {app} directories …")
        paths = discover_chatgpt_paths() if choice == "1" else discover_claude_paths()

        if not paths:
            print(f"\n  [!] {app} Desktop installation not detected.")
            print(f"      (For ChatGPT: install from Microsoft Store)")
            print(f"      (For Claude:  install from anthropic.com)")
            if choice == "2":
                print(f"\n  Proceeding with RECOVERED_CLAUDE_HISTORY.json only …")
                paths = {}
            else:
                input("\n  Press Enter to return to menu …")
                continue

        _scan_dirs(paths)
        print()

        # ── Run pipeline ────────────────────────────────────────────────
        import time
        t0 = time.time()
        if choice == "1":
            run_chatgpt(paths)
        else:
            run_claude(paths)
        elapsed = time.time() - t0
        print(f"\n  Completed in {elapsed:.1f}s")
        print(f"\n  📂 Report saved to:")
        label = "CHATGPT" if choice == "1" else "CLAUDE"
        print(f"      {os.path.join(REPORTS, label + '_FORENSIC_REPORT.md')}")

        try:
            again = input("\n  Run another? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if again != "y":
            print("  Exiting.")
            break


if __name__ == "__main__":
    main()
