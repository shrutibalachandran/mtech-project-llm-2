"""
chatgpt_extractor.py  –  Fresh ChatGPT forensic extractor (v2).

STAGE 1 — LevelDB (IndexedDB + Local Storage)
  ▸ Carves id"$<uuid> conversation anchors
  ▸ Decodes 8-byte IEEE-754 double updateTime values
  ▸ Extracts title, account_user_id, text fragments
  ▸ Snappy decompression via cramjam

STAGE 2 — Cache (Chromium Cache_Data)
  ▸ Brute-force scans data_0/data_1/data_2/data_3 and f_* files
  ▸ Brotli → GZIP → raw decompression
  ▸ Parses ChatGPT API JSON response format:
      mapping[id].message.content.parts + author.role + create_time

STAGE 3 — Reconstruction
  ▸ Merges LDB + cache hits by conversation_id
  ▸ Deduplicates messages by snippet hash
  ▸ Sorts messages by timestamp, conversations newest-first
"""
import os
import re
import json
import struct
import glob
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import cramjam
    HAS_CRAMJAM = True
except ImportError:
    HAS_CRAMJAM = False
    print("[warn] cramjam not installed; Snappy decompression disabled")

# ─── Path discovery ───────────────────────────────────────────────────────────
_LOCALAPPDATA = os.getenv("LOCALAPPDATA", "")

def discover_paths() -> dict:
    pattern = os.path.join(
        _LOCALAPPDATA, "Packages",
        "OpenAI.ChatGPT-Desktop_*",
        "LocalCache", "Roaming", "ChatGPT"
    )
    roots = glob.glob(pattern)
    if not roots:
        return {}
    root = roots[0]
    idb_root = os.path.join(root, "IndexedDB")
    return {
        "idb":  os.path.join(idb_root, "https_chatgpt.com_0.indexeddb.leveldb"),
        "blob": os.path.join(idb_root, "https_chatgpt.com_0.indexeddb.blob"),
        "ls":   os.path.join(root, "Local Storage", "leveldb"),
        "cache":os.path.join(root, "Cache", "Cache_Data"),
    }


# ─── V8 text extraction helpers ───────────────────────────────────────────────
def _extract_v8_text(raw: bytes, min_len: int = 15) -> List[str]:
    """
    Stitch together printable segments in a V8-serialized buffer.
    V8 splits strings with 1-6 control bytes; we bridge those gaps
    to reconstruct complete message text.
    """
    # Collect (start, bytes) for every run of printable chars >= 4
    segments: List[tuple] = []
    i, n = 0, len(raw)
    while i < n:
        if 0x20 <= raw[i] <= 0x7e or raw[i] >= 0x80:
            start = i
            while i < n and (0x20 <= raw[i] <= 0x7e or raw[i] >= 0x80):
                i += 1
            seg = raw[start:i]
            if len(seg) >= 4:
                segments.append((start, seg))
        else:
            i += 1

    # Bridge segments separated by <= 6 binary bytes
    merged: List[bytes] = []
    j = 0
    while j < len(segments):
        pos, seg = segments[j]
        parts = [seg]
        j += 1
        while j < len(segments):
            tail_end = pos + sum(len(p) for p in parts)
            gap = segments[j][0] - tail_end
            if gap <= 6:
                parts.append(segments[j][1])
                j += 1
            else:
                break
        merged.append(b" ".join(parts))

    result: List[str] = []
    seen: set = set()
    for chunk in merged:
        txt = chunk.decode("utf-8", errors="replace")
        txt = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', txt)
        txt = re.sub(r'\s+', ' ', txt).strip()
        if len(txt) >= min_len and txt not in seen:
            seen.add(txt)
            result.append(txt)
    return result


# Patterns that indicate V8 metadata noise (not conversation text)
_NOISE_STRS = [
    'accountUserId', 'id"$', 'client-created-root', 'current_node',
    'conversation_id"', 'accountUserId"C', 'MANIFEST-', 'filter.leveldb',
]

def _is_useful_text(txt: str) -> bool:
    """True if text looks like real conversation content (not certs/b64/UUIDs/LDB metadata)."""
    if len(txt) < 10:
        return False
    # Block known V8/LDB metadata noise
    for noise in _NOISE_STRS:
        if noise in txt:
            return False
    # Require sufficient alpha content
    alpha = sum(1 for c in txt if c.isalpha())
    if alpha < len(txt) * 0.3:
        return False
    # Block bare base64 blobs
    if re.match(r'^[A-Za-z0-9+/=]{40,}$', txt):
        return False
    # Block certs
    if 'CERTIFICATE' in txt[:40] or txt.startswith('-----'):
        return False
    # Block bare URLs
    if txt.startswith('http') and ' ' not in txt[:60]:
        return False
    # Block short LDB key fragments that look like JSON keys only
    if txt.startswith('"') and txt.endswith('"') and len(txt) < 30:
        return False
    # Must contain at least one space (real sentences have spaces)
    if ' ' not in txt and len(txt) > 40:
        return False
    return True


def scan_idb_blob(blob_dir: str, verbose: bool = True) -> List[dict]:
    """
    Parse IndexedDB blob files (V8-serialized JS objects).
    These contain the actual full conversation message text.
    """
    if not os.path.isdir(blob_dir):
        if verbose:
            print("    [-] IDB Blob: directory not found")
        return []

    hits: Dict[str, dict] = {}
    blob_count = 0

    for root_d, dirs, bfiles in os.walk(blob_dir):
        for fname in bfiles:
            fpath = os.path.join(root_d, fname)
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
            except Exception:
                continue
            if len(raw) < 50:
                continue
            blob_count += 1

            texts = _extract_v8_text(raw, min_len=15)
            useful = [t for t in texts if _is_useful_text(t)]

            uuid_m = re.search(
                rb'id"\$([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                raw, re.I)
            cid = uuid_m.group(1).decode("ascii").lower() if uuid_m else ""

            for pat in (rb'title"[^"]{0,4}"([^"]{2,200})"',
                        rb'"title"\s*:\s*"([^"]{2,200})"'):
                tm = re.search(pat, raw)
                if tm:
                    title = tm.group(1).decode("utf-8", errors="replace").strip()
                    break
            else:
                title = ""

            ts = 0.0
            ts_m = re.search(rb'updateTime.(.{8})', raw)
            if ts_m:
                try:
                    v = struct.unpack("<d", ts_m.group(1)[:8])[0]
                    if 1e9 < v < 3e9:
                        ts = v
                except Exception:
                    pass

            if not useful and not title:
                continue

            messages = [
                {"message_id": "", "role": "unknown",
                 "snippet": t[:3000], "timestamp": ts}
                for t in useful
                if t != title and not re.match(r'^[0-9a-f-]{36}$', t)
            ]

            key = cid if cid else title[:40]
            if not key:
                continue
            prev = hits.get(key)
            if prev is None or ts > float(prev.get("update_time") or 0):
                hits[key] = {
                    "conversation_id": cid,
                    "title":           title,
                    "update_time":     ts,
                    "is_deleted":      False,
                    "messages":        messages,
                    "source":          f"blob/{fname}",
                }
            else:
                ex = {hashlib.md5(m["snippet"].encode()).hexdigest()
                      for m in prev["messages"]}
                for msg in messages:
                    h = hashlib.md5(msg["snippet"].encode()).hexdigest()
                    if h not in ex:
                        prev["messages"].append(msg)
                        ex.add(h)
                if title and not prev["title"]:
                    prev["title"] = title

    result = list(hits.values())
    if verbose:
        if result:
            print(f"    [+] IDB Blob: {blob_count} files → {len(result)} conversations")
        else:
            print(f"    [-] IDB Blob: {blob_count} files, no conversations extracted")
    return result



# ─── Regex patterns (matching user's proven carving approach) ─────────────────
# Conversation ID: stored as `id"$<uuid>` in LDB binary format
RE_CID       = re.compile(rb'id"\$([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I)
# Also standard JSON UUIDs for cache
RE_CID_JSON  = re.compile(rb'"conversation_id"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', re.I)
# Account user id
RE_USER      = re.compile(rb'accountUserId"C(user-[A-Za-z0-9_\-]+)')
# Title in LDB format (handles null bytes / binary delimiters)
RE_TITLE_LDB = re.compile(rb'title"[\x00-\x20]{0,4}:?[\x00-\x20]{0,4}"([^"]{2,300})"')
# Title in JSON format
RE_TITLE_JSON= re.compile(rb'"title"\s*:\s*"((?:[^"\\]|\\.){2,300})"')
# 8-byte IEEE-754 double timestamp (the key finding from user's script)
RE_UPDATE_TS = re.compile(rb'(?:updateTime|update_time).{0,4}(.{8})')
# Also ms-epoch timestamps (Local Storage)
RE_MS_TS     = re.compile(rb'(177[0-9]{10}|176[0-9]{10})')
# Text content
RE_TEXT      = re.compile(rb'"text"\s*:\s*"((?:[^"\\]|\\.){10,3000})"')
# Parts array
RE_PARTS     = re.compile(rb'"parts"\s*:\s*\[\s*"((?:[^"\\]|\\.){10,3000})"')
# Snippet
RE_SNIPPET   = re.compile(rb'"snippet"\s*:\s*"((?:[^"\\]|\\.){10,600})"')
# Role
RE_ROLE      = re.compile(rb'"(?:role|author\.role)"\s*[:"]{1,3}\s*"(user|assistant|system)"', re.I)

# ─── Helpers ──────────────────────────────────────────────────────────────────
def _decode_double_ts(raw8: bytes) -> float:
    """Decode 8-byte little-endian IEEE-754 double into Unix seconds."""
    if len(raw8) < 8:
        return 0.0
    try:
        val = struct.unpack("<d", raw8[:8])[0]
        if 1_000_000_000.0 < val < 3_000_000_000.0:
            yr = datetime.fromtimestamp(val, tz=timezone.utc).year
            if 2020 <= yr <= 2035:
                return val
    except Exception:
        pass
    return 0.0


def _decode_ms_ts(raw: bytes) -> float:
    """Decode millisecond-epoch bytes to Unix seconds."""
    try:
        v = int(raw)
        if v > 1_000_000_000_000:
            return v / 1000.0
    except Exception:
        pass
    return 0.0


def _best_ts(block: bytes) -> float:
    """Try double-precision first, then ms-epoch."""
    m = RE_UPDATE_TS.search(block)
    if m:
        ts = _decode_double_ts(m.group(1))
        if ts > 0:
            return ts
    m2 = RE_MS_TS.search(block)
    if m2:
        return _decode_ms_ts(m2.group(1))
    return 0.0


def _decode_b(b: bytes) -> str:
    try:
        return json.loads(b'"' + b + b'"')
    except Exception:
        return b.decode("utf-8", errors="replace")


def _extract_title(block: bytes) -> str:
    for pat in (RE_TITLE_LDB, RE_TITLE_JSON):
        m = pat.search(block)
        if m:
            t = _decode_b(m.group(1))
            if t and 2 <= len(t) <= 300 and not t.startswith('{'):
                return t
    return ""


def _extract_texts(block: bytes) -> List[str]:
    texts = []
    seen  = set()
    for pat in (RE_TEXT, RE_PARTS, RE_SNIPPET):
        for m in pat.finditer(block):
            txt = _decode_b(m.group(1)).strip()
            if len(txt) >= 10 and txt not in seen:
                seen.add(txt)
                texts.append(txt)
    return texts


def _safe_copy(fpath: str) -> bytes:
    """Copy file to temp and read, to avoid Windows file locks."""
    try:
        tmp = fpath + f"._tmp_{os.getpid()}"
        shutil.copy2(fpath, tmp)
        with open(tmp, "rb") as f:
            data = f.read()
        os.remove(tmp)
        return data
    except Exception:
        return b""


def _snappy_decompress_sliding(raw: bytes) -> List[bytes]:
    """Attempt Snappy decompression in sliding windows."""
    if not HAS_CRAMJAM:
        return []
    results = []
    CHUNK = 65536
    for i in range(0, min(len(raw), 4 * 1024 * 1024), CHUNK // 4):
        try:
            dec = bytes(cramjam.snappy.decompress(raw[i:i + CHUNK]))
            if len(dec) > 64:
                results.append(dec)
        except Exception:
            pass
    return results


# ─── STAGE 1: LevelDB extraction ──────────────────────────────────────────────
def _scan_ldb_file(fpath: str, is_ls: bool = False) -> List[dict]:
    """
    Scan one LDB/LOG file for conversation records.
    is_ls=True: use Local Storage carver (plain UUID + ms-epoch)
    is_ls=False: use IndexedDB carver (id"$ anchor + double-precision TS)
    """
    raw = _safe_copy(fpath)
    if not raw:
        return []

    fname   = os.path.basename(fpath)
    hits: Dict[str, dict] = {}
    buffers = [raw] + _snappy_decompress_sliding(raw)

    for buf in buffers:
        if is_ls:
            _carve_ls_buffer(buf, fname, hits)
        else:
            _carve_ldb_buffer(buf, fname, hits)

    return list(hits.values())


def _carve_ldb_buffer(buf: bytes, src: str, hits: dict):
    """Carve one buffer using id"$<uuid> anchors (user's method)."""
    matches = list(RE_CID.finditer(buf))

    for idx, m in enumerate(matches):
        cid = m.group(1).decode("ascii").lower()
        start = m.start()
        # Window: from this anchor to next anchor (max 64KB)
        next_start = matches[idx + 1].start() if idx + 1 < len(matches) else len(buf)
        end = min(next_start, start + 65536)
        block = buf[start:end]

        title   = _extract_title(block)
        ts      = _best_ts(block)
        texts   = _extract_texts(block)
        role_m  = RE_ROLE.search(block)
        role    = role_m.group(1).decode() if role_m else ""
        user_m  = RE_USER.search(block)
        acct    = user_m.group(1).decode("ascii", errors="replace") if user_m else ""

        msgs = [{
            "message_id": "",
            "role":       role or "unknown",
            "snippet":    txt,
            "timestamp":  ts,
        } for txt in texts]

        prev = hits.get(cid)
        if prev is None or ts > float(prev.get("update_time") or 0):
            hits[cid] = {
                "conversation_id": cid,
                "title":           title,
                "update_time":     ts,
                "account_user_id": acct,
                "is_deleted":      False,
                "messages":        msgs,
                "source":          f"ldb/{src}",
            }
        else:
            # Merge messages
            existing = {hashlib.md5(mm["snippet"].encode()).hexdigest()
                        for mm in prev["messages"]}
            for msg in msgs:
                h = hashlib.md5(msg["snippet"].encode()).hexdigest()
                if h not in existing:
                    prev["messages"].append(msg)
                    existing.add(h)
            if title and not prev["title"]:
                prev["title"] = title


# ─── Local Storage carver (UUID anchor + ms-epoch) ────────────────────────────
_MIN_MS_TS = 1_704_067_200_000   # Jan 1 2024 in ms

def _carve_ls_buffer(buf: bytes, src: str, hits: dict):
    """
    Local Storage format:
      - Plain UUIDs (not id"$)
      - ms-epoch timestamps 177xxxxxxxxx
      - JSON titles: "title":"..."
    Strategy: anchor on every title, search ±6KB for UUID + ms-timestamp.
    """
    text       = buf.decode("utf-8", errors="replace")
    title_pat  = re.compile(r'"title"\s*:\s*"((?:[^"\\]|\\.){2,300})"|title"([^"]{2,200})"')
    uuid_pat   = re.compile(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I)
    ms_pat     = re.compile(r'(177[0-9]{10}|176[0-9]{10})')

    seen_titles: set = set()
    for tm in title_pat.finditer(text):
        title = (tm.group(1) or tm.group(2) or "").strip()
        if not title or title.startswith("{") or len(title) > 300:
            continue
        # Try JSON-unescape
        try:
            title = json.loads('"' + title + '"')
        except Exception:
            pass
        if title in seen_titles:
            continue
        seen_titles.add(title)

        win_s = max(0, tm.start() - 6000)
        win_e = min(len(text), tm.end() + 6000)
        win   = text[win_s:win_e]

        # Best ms-epoch timestamp near title
        best_ts = 0.0
        for mm in ms_pat.finditer(win):
            try:
                v = int(mm.group(1))
                if v >= _MIN_MS_TS:
                    cand = v / 1000.0
                    if cand > best_ts:
                        best_ts = cand
            except Exception:
                pass

        # UUID
        um  = uuid_pat.search(win)
        cid = um.group(1).lower() if um else ""

        key  = cid if cid else title[:40]
        prev = hits.get(key)
        if prev is None or best_ts > float(prev.get("update_time") or 0):
            hits[key] = {
                "conversation_id": cid,
                "title":           title,
                "update_time":     best_ts,
                "is_deleted":      False,
                "messages":        [],
                "source":          f"ls/{src}",
            }
        elif not prev.get("title") and title:
            prev["title"] = title


def scan_ldb(directory: str, label: str, verbose: bool = True) -> List[dict]:
    if not os.path.isdir(directory):
        if verbose:
            print(f"    [skip] {label}: not found")
        return []

    files = (
        sorted(glob.glob(os.path.join(directory, "*.log")),
               key=os.path.getmtime, reverse=True) +
        sorted(glob.glob(os.path.join(directory, "*.ldb")),
               key=os.path.getmtime, reverse=True)
    )
    if verbose:
        print(f"    [{label}] {len(files)} files")

    is_ls = "Local Storage" in label or label.lower() == "ls"
    all_hits: Dict[str, dict] = {}
    for fpath in files:
        for h in _scan_ldb_file(fpath, is_ls=is_ls):
            cid = h.get("conversation_id") or h.get("title", "")[:40]
            prev = all_hits.get(cid)
            if prev is None or float(h.get("update_time") or 0) > float(prev.get("update_time") or 0):
                all_hits[cid] = h
            else:
                ex = {hashlib.md5(m["snippet"].encode()).hexdigest() for m in prev["messages"]}
                for msg in h.get("messages", []):
                    hh = hashlib.md5(msg["snippet"].encode()).hexdigest()
                    if hh not in ex:
                        prev["messages"].append(msg)
                        ex.add(hh)
                if h.get("title") and not prev.get("title"):
                    prev["title"] = h["title"]

    result = list(all_hits.values())

    # For Local Storage: also parse the structured conversation-history WAL key
    # This has clean JSON with title, create_time, update_time, is_archived
    if is_ls:
        ch_hits = _scan_ls_conversation_history(directory)
        for h in ch_hits:
            cid = h.get("conversation_id", "")
            key = cid if cid else h.get("title", "")[:40]
            if not key:
                continue
            prev = all_hits.get(key)
            if prev is None:
                all_hits[key] = h
            else:
                # Overlay the clean metadata (better title, proper ISO timestamps)
                if h.get("title") and (not prev.get("title") or prev["title"].startswith("(")):
                    prev["title"] = h["title"]
                if h.get("update_time", 0) > float(prev.get("update_time") or 0):
                    prev["update_time"] = h["update_time"]
                prev["is_archived"] = h.get("is_archived", False)
                prev["is_starred"]  = h.get("is_starred", False)
        result = list(all_hits.values())
        if verbose and ch_hits:
            print(f"    [+] LS conversation-history: {len(ch_hits)} entries parsed")

    if verbose:
        print(f"    [+] {label}: {len(result)} unique conversations")
    return result


def _scan_ls_conversation_history(ls_dir: str) -> List[dict]:
    """
    Parse the 'conversation-history' JSON from Local Storage files.

    The value is a JSON string starting with:
    {"value":{"pages":[{"items":[{"id":"...","title":"...","create_time":"...","update_time":"..."}]}]}}

    We scan ALL log + ldb files for this pattern via raw bytes regex.
    """
    results = []
    all_files = (
        sorted(glob.glob(os.path.join(ls_dir, "*.log")), key=os.path.getmtime, reverse=True) +
        sorted(glob.glob(os.path.join(ls_dir, "*.ldb")), key=os.path.getmtime, reverse=True)
    )

    for fpath in all_files:
        raw = _safe_copy(fpath)
        if not raw or len(raw) < 100:
            continue
        text = raw.decode("utf-8", errors="replace")

        # Find the conversation-history JSON value — it always starts with:
        # {"value":{"pages":...}} and contains "items"
        # Anchor on the key pattern and extract the JSON value
        pat = re.compile(r'conversation-history[^\{]{0,40}(\{"value":\{"pages":\[)')
        for m in pat.finditer(text):
            start = m.start(1)
            # Walk forward to find the balanced JSON object
            depth = 0
            end = start
            for i in range(start, min(start + 500_000, len(text))):
                c = text[i]
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if end <= start:
                continue
            frag = text[start:end]
            try:
                payload = json.loads(frag)
            except Exception:
                continue

            pages = (payload.get("value") or payload).get("pages", [])
            for page in pages:
                for item in page.get("items", []) or []:
                    if not isinstance(item, dict):
                        continue
                    cid   = (item.get("id") or "").strip()
                    title = (item.get("title") or "").strip()
                    ct    = item.get("create_time") or ""
                    ut    = item.get("update_time") or ""

                    ts = 0.0
                    for ts_str in (ut, ct):
                        if ts_str:
                            try:
                                ts = datetime.fromisoformat(
                                    ts_str.replace("Z", "+00:00")
                                ).timestamp()
                                break
                            except Exception:
                                pass

                    results.append({
                        "conversation_id": cid,
                        "title":           title,
                        "update_time":     ts,
                        "is_archived":     bool(item.get("is_archived")),
                        "is_starred":      bool(item.get("is_starred")),
                        "is_deleted":      False,
                        "messages":        [],
                        "source":          f"ls_ch/{os.path.basename(fpath)}",
                    })

    # Deduplicate by CID, keep newest
    seen: Dict[str, dict] = {}
    for r in results:
        cid = r["conversation_id"]
        if cid not in seen or r["update_time"] > seen[cid]["update_time"]:
            seen[cid] = r
    return list(seen.values())



# ─── STAGE 2: Cache extraction ────────────────────────────────────────────────
def _decompress_cache(data: bytes) -> bytes:
    """Zstandard → Brotli → GZIP → raw (Chromium may use any of these)."""
    try:
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(data)
    except Exception:
        pass
    try:
        import brotli
        return brotli.decompress(data)
    except Exception:
        pass
    try:
        import gzip
        return gzip.decompress(data)
    except Exception:
        pass
    return data


def _flatten_parts(parts) -> str:
    """Turn ChatGPT content.parts (strings and/or dicts) into plain text."""
    if parts is None:
        return ""
    if isinstance(parts, str):
        return parts.strip()
    if isinstance(parts, dict):
        return _flatten_parts([parts])
    if not isinstance(parts, (list, tuple)):
        return ""

    chunks: List[str] = []
    for p in parts:
        if p is None:
            continue
        if isinstance(p, str):
            if p.strip():
                chunks.append(p.strip())
        elif isinstance(p, dict):
            txt = None
            for key in ("text", "input_text", "markdown", "result", "output"):
                v = p.get(key)
                if isinstance(v, str) and v.strip():
                    txt = v.strip()
                    break
            if txt:
                chunks.append(txt)
            else:
                nested = p.get("parts")
                if nested is not None:
                    inner = _flatten_parts(nested)
                    if inner:
                        chunks.append(inner)
                else:
                    c = p.get("content")
                    if isinstance(c, str) and c.strip():
                        chunks.append(c.strip())
                    elif isinstance(c, (list, dict)):
                        inner = _flatten_parts(c)
                        if inner:
                            chunks.append(inner)
        elif isinstance(p, list):
            inner = _flatten_parts(p)
            if inner:
                chunks.append(inner)
    return " ".join(chunks)


def _text_from_message_content(content) -> str:
    """Extract readable text from message.content (dict, str, list)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        return _flatten_parts(content).strip()
    if not isinstance(content, dict):
        return ""

    for key in ("text", "input_text", "body"):
        v = content.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    parts = content.get("parts")
    if parts is not None:
        t = _flatten_parts(parts)
        if t.strip():
            return t.strip()

    return ""


def _iter_parseable_conv_dicts(obj: dict):
    """Walk nested API wrappers; propagate conversation_id/title from ancestors."""
    seen_yield: set = set()
    stack: List[tuple] = [(obj, "", "")]
    while stack:
        o, inherited_cid, inherited_title = stack.pop()
        if not isinstance(o, dict):
            continue
        cid = (o.get("conversation_id") or "").strip() or inherited_cid
        title = (o.get("title") or "").strip() or inherited_title
        msgs = o.get("messages")
        has_msgs = isinstance(msgs, list) and len(msgs) > 0
        if "mapping" in o or has_msgs:
            oid = id(o)
            if oid not in seen_yield:
                seen_yield.add(oid)
                merged = dict(o)
                if cid and not (merged.get("conversation_id") or "").strip():
                    merged["conversation_id"] = cid
                if title and not (merged.get("title") or "").strip():
                    merged["title"] = title
                yield merged
        for nest_key in ("conversation", "data", "result", "node", "chat"):
            inner = o.get(nest_key)
            if isinstance(inner, dict):
                stack.append((inner, cid, title))
        for list_key in ("items", "conversations", "pages"):
            arr = o.get(list_key)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        stack.append((item, cid, title))


def _parse_mapping_api(obj: dict, src: str) -> Optional[dict]:
    """
    Parse ChatGPT API response format:
    { "conversation_id": "...", "title": "...", "mapping": { id: { message: {...} } } }
    """
    conv = obj
    mapping = conv.get("mapping") or {}
    if not mapping:
        return None

    cid   = (conv.get("conversation_id") or "").strip()
    title = (conv.get("title") or "").strip()
    ut    = float(conv.get("update_time") or conv.get("create_time") or 0)

    messages = []

    for node in mapping.values():
        if not isinstance(node, dict):
            continue
        msg = node.get("message")
        if not msg:
            continue
        if not isinstance(msg, dict):
            continue

        content = msg.get("content") or {}
        parts = content.get("parts") or []

        text_parts = []
        for p in parts:
            if isinstance(p, str):
                t = p.strip()
                if t:
                    text_parts.append(t)

        if not text_parts:
            continue

        text = " ".join(text_parts)

        if text.startswith("{") or "startTime" in text:
            continue

        role = (msg.get("author") or {}).get("role", "unknown")
        if isinstance(role, str):
            role = role.lower()
        ts_raw = msg.get("create_time")
        ts = float(ts_raw) if ts_raw is not None else float(msg.get("update_time") or ut)

        messages.append({
            "message_id": msg.get("id"),
            "role":       role,
            "snippet":    text.strip()[:3000],
            "timestamp":  ts,
        })

    print("[MSG COUNT]", conv.get("id"), len(messages))

    if not messages:
        return None

    if ut <= 0:
        times = [m["timestamp"] for m in messages if m["timestamp"] > 0]
        ut = max(times) if times else 0.0

    return {
        "conversation_id": cid,
        "title":           title or "(recovered from cache)",
        "update_time":     ut,
        "is_deleted":      False,
        "messages":        sorted(messages, key=lambda m: m["timestamp"]),
        "source":          f"cache/{src}",
    }


def _parse_messages_api(obj: dict, src: str) -> Optional[dict]:
    """
    Parse flat messages format:
    { "conversation_id": "...", "messages": [...] }
    """
    msgs_raw = obj.get("messages") or obj.get("items") or []
    if not msgs_raw or not isinstance(msgs_raw, list):
        return None

    cid   = (obj.get("conversation_id") or "").strip()
    title = (obj.get("title") or "").strip()
    ut    = float(obj.get("update_time") or obj.get("create_time") or 0)

    messages = []
    for m in msgs_raw:
        if not isinstance(m, dict):
            continue
        content = m.get("content", {})
        text = _text_from_message_content(content)
        if not text:
            if isinstance(content, str):
                text = content.strip()
            else:
                text = (m.get("text") or "").strip()

        if not text or len(text.strip()) < 1:
            continue

        author = m.get("author", {})
        role   = (author.get("role") or m.get("role") or "unknown").lower()
        ts     = float(m.get("create_time") or m.get("update_time") or ut)
        mid    = m.get("id", "")

        messages.append({
            "message_id": mid, "role": role,
            "snippet": text.strip()[:3000], "timestamp": ts,
        })

    if not messages:
        return None
    if ut <= 0:
        times = [m["timestamp"] for m in messages if m["timestamp"] > 0]
        ut = max(times) if times else 0.0

    return {
        "conversation_id": cid,
        "title":           title or "(recovered from cache)",
        "update_time":     ut,
        "is_deleted":      False,
        "messages":        sorted(messages, key=lambda m: m["timestamp"]),
        "source":          f"cache/{src}",
    }


def _scan_cache_file(fpath: str, hits: dict):
    """Scan one Chromium cache file for ChatGPT API JSON."""
    raw = _safe_copy(fpath)
    if not raw or len(raw) < 50:
        return

    src = os.path.basename(fpath)

    # Try multiple parse windows (Chromium cache has a header before the body)
    windows = []
    for offset in [0, 8, 256, 512, 2048, 8192]:
        chunk = raw[offset:]
        if chunk:
            windows.append(chunk)
            dec = _decompress_cache(chunk)
            if dec != chunk:
                windows.append(dec)

    for window in windows:
        text = window.decode("utf-8", errors="replace")

        # ChatGPT cache bodies vary; be permissive so nested JSON still parses.
        has_mapping  = '"mapping"' in text
        has_messages = '"messages"' in text and (
            '"conversation_id"' in text or '"title"' in text or '"author"' in text
        )
        if not has_mapping and not has_messages:
            continue

        # Find all JSON objects (balanced braces)
        _extract_json_from_text(text, src, hits)


def _extract_json_from_text(text: str, src: str, hits: dict):
    """Find balanced JSON objects containing conversation data."""
    i = 0
    while i < len(text):
        if text[i] != '{':
            i += 1
            continue
        depth = 0
        start = i
        end   = i
        for j in range(i, min(i + 5_000_000, len(text))):
            c = text[j]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        if end <= start:
            i += 1
            continue

        fragment = text[start:end]
        i = end

        # Quick filter
        if len(fragment) < 100:
            continue
        has_conv = '"conversation_id"' in fragment
        has_map  = '"mapping"' in fragment
        has_msgs = '"messages"' in fragment

        if not (has_conv or has_map or has_msgs):
            continue

        try:
            obj = json.loads(fragment)
        except Exception:
            continue

        if not isinstance(obj, dict):
            continue

        candidates = list(_iter_parseable_conv_dicts(obj))
        if not candidates:
            candidates = [obj]

        for cand in candidates:
            conv = None
            if "mapping" in cand:
                conv = _parse_mapping_api(cand, src)
            if conv is None and isinstance(cand.get("messages"), list):
                conv = _parse_messages_api(cand, src)
            if conv is None:
                continue

            cid = conv["conversation_id"]
            key = cid if cid else conv["title"][:40]
            if not key:
                continue
            prev = hits.get(key)
            if prev is None:
                hits[key] = conv
            else:
                _merge_into(prev, conv)


def scan_cache(directory: str, verbose: bool = True) -> List[dict]:
    if not os.path.isdir(directory):
        if verbose:
            print("    [cache] directory not found")
        return []

    files = (
        sorted(glob.glob(os.path.join(directory, "data_[0-3]"))) +
        sorted(glob.glob(os.path.join(directory, "data_[0-3]_*"))) +
        sorted(glob.glob(os.path.join(directory, "f_*")))
    )
    if verbose:
        print(f"    [cache] {len(files)} files to scan")

    hits: Dict[str, dict] = {}
    found = 0
    for fpath in files:
        before = len(hits)
        _scan_cache_file(fpath, hits)
        if len(hits) > before:
            found += 1

    result = list(hits.values())
    if verbose:
        if result:
            print(f"    [+] Cache: {len(result)} conversations from {found} files")
        else:
            print("    [-] Cache: no conversations found (cache may be cleared)")
    return result


# ─── STAGE 3: Reconstruction ──────────────────────────────────────────────────
def _merge_into(target: dict, source: dict):
    """Merge source conversation into target in-place."""
    # Update timestamp
    src_ut = float(source.get("update_time") or 0)
    tgt_ut = float(target.get("update_time") or 0)
    if src_ut > tgt_ut:
        target["update_time"] = src_ut

    # Prefer real title over placeholder
    if not target.get("title") or target["title"].startswith("(recovered"):
        if source.get("title") and not source["title"].startswith("(recovered"):
            target["title"] = source["title"]

    # Merge messages (dedup by snippet hash)
    existing = {hashlib.md5(m.get("snippet", "").encode()).hexdigest()
                for m in target.get("messages", [])}
    for msg in source.get("messages", []):
        h = hashlib.md5(msg.get("snippet", "").encode()).hexdigest()
        if h not in existing:
            target.setdefault("messages", []).append(msg)
            existing.add(h)


def reconstruct(ldb_hits: List[dict], cache_hits: List[dict]) -> List[dict]:
    """
    Merge LDB + cache hits.
    Cache data fills in full message content for LDB-discovered conversations.
    """
    merged: Dict[str, dict] = {}

    # Seed with LDB data first (has deleted titles)
    for h in ldb_hits:
        cid = h.get("conversation_id", "")
        key = cid if cid else h.get("title", "")[:40]
        if not key:
            continue
        merged[key] = h.copy()
        merged[key]["messages"] = list(h.get("messages", []))

    # Overlay cache data (has full message content)
    for h in cache_hits:
        cid = h.get("conversation_id", "")
        title = h.get("title", "")
        key = cid if cid else title[:40]
        if not key:
            continue

        if key in merged:
            _merge_into(merged[key], h)
        else:
            # New conversation from cache only
            merged[key] = h.copy()
            merged[key]["messages"] = list(h.get("messages", []))

    # Sort messages in each conversation chronologically
    result = []
    for conv in merged.values():
        conv["messages"].sort(key=lambda m: m.get("timestamp", 0))
        result.append(conv)

    # Sort conversations newest → oldest
    result.sort(key=lambda c: float(c.get("update_time") or 0), reverse=True)
    return result


# ─── Public entry point ───────────────────────────────────────────────────────
def run(verbose: bool = True) -> List[dict]:
    paths = discover_paths()
    if not paths:
        if verbose:
            print("  [!] ChatGPT app not found.")
        return []

    # Stage 1: LevelDB (WAL + SSTable + Blob)
    if verbose:
        print("\n  [Stage 1] LevelDB extraction...")
    ldb_hits = []
    for label, key in [("IndexedDB", "idb"), ("Local Storage", "ls")]:
        d = paths.get(key, "")
        ldb_hits.extend(scan_ldb(d, label, verbose=verbose))

    # Stage 1b: IndexedDB Blob files (V8 serialized — actual message text)
    if verbose:
        print("\n  [Stage 1b] IndexedDB Blob extraction...")
    blob_hits = scan_idb_blob(paths.get("blob", ""), verbose=verbose)

    # Stage 2: Cache
    if verbose:
        print("\n  [Stage 2] Cache extraction...")
    cache_hits = scan_cache(paths.get("cache", ""), verbose=verbose)

    # Stage 3: Reconstruction (LDB metadata + Blob text + Cache full messages)
    if verbose:
        print("\n  [Stage 3] Reconstruction...")
    conversations = reconstruct(ldb_hits + blob_hits, cache_hits)

    with_msgs = sum(1 for c in conversations if c.get("messages"))

    if verbose:
        print(f"    [✓] {len(conversations)} conversations ({with_msgs} with message content)")
        if conversations:
            top = conversations[0]
            ts  = float(top.get("update_time") or 0)
            dt  = (datetime.fromtimestamp(ts + 5.5 * 3600, tz=timezone.utc)
                   .strftime("%Y-%m-%d %H:%M:%S IST") if ts > 0 else "N/A")
            print(f"    [✓] Newest: {dt} — {top.get('title', '')}")

    return conversations

