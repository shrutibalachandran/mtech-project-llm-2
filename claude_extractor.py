"""
claude_extractor.py  –  Strict JSON-only Claude forensic extractor.

Rules:
  - Cache files ONLY (data_* and f_*)
  - Decompress: ZSTD → GZIP → Brotli → raw
  - Accept ONLY JSON objects containing "messages" OR "chat_messages"
  - NO fallback carving
  - NO noise/domain/certificate entries
  - Minimum message length: 30 chars
  - If nothing found → returns [] so output_writer can write the "no data" notice

Returns: list of conversation dicts suitable for output_writer.write_outputs()
"""
import os
import re
import json
import glob
import shutil
import hashlib
from datetime import datetime, timezone
from typing import List, Dict

# ─── Path discovery ───────────────────────────────────────────────────────────
_APPDATA  = os.getenv("APPDATA", "")
_LAPPDATA = os.getenv("LOCALAPPDATA", "")

_CLAUDE_ROOTS = [
    os.path.join(_APPDATA,  "Claude"),
    os.path.join(_LAPPDATA, "Claude"),
    os.path.join(_APPDATA,  "Anthropic", "Claude"),
]


def discover_paths() -> dict:
    for root in _CLAUDE_ROOTS:
        if os.path.isdir(root):
            return {
                "cache": os.path.join(root, "Cache", "Cache_Data"),
                "ls":    os.path.join(root, "Local Storage", "leveldb"),
                "idb":   os.path.join(root, "IndexedDB"),
            }
    return {}


# ─── Decompression ────────────────────────────────────────────────────────────
def _decompress(data: bytes) -> bytes:
    """Try ZSTD → GZIP → Brotli → raw."""
    # ZSTD
    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=16 * 1024 * 1024)
    except Exception:
        pass
    # GZIP
    try:
        import gzip
        return gzip.decompress(data)
    except Exception:
        pass
    # Brotli
    try:
        import brotli
        return brotli.decompress(data)
    except Exception:
        pass
    return data


# ─── Noise filters ────────────────────────────────────────────────────────────
_NOISE_PATTERNS = [
    r"^https?://",
    r"^-----BEGIN CERTIFICATE",
    r"^<!DOCTYPE html",
    r"^<html",
    r"\.(com|net|org|edu|gov)\b",
    r"^[a-zA-Z0-9+/]{40,}={0,2}$",          # base64 blob
    r"^[0-9A-Fa-f]{64,}$",                   # hex hash
]
_NOISE_RE = re.compile("|".join(_NOISE_PATTERNS))

def _is_noise(text: str) -> bool:
    if len(text) < 30:
        return True
    stripped = text.strip()
    return bool(_NOISE_RE.search(stripped[:200]))


# ─── JSON extraction ──────────────────────────────────────────────────────────
def _find_json_objects(text: str) -> List[str]:
    """Locate all top-level balanced JSON objects in a string."""
    objects = []
    i = 0
    while i < len(text):
        if text[i] == "{":
            depth = 0
            start = i
            for j in range(i, min(i + 2_000_000, len(text))):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        frag = text[start:j + 1]
                        if len(frag) > 50:
                            objects.append(frag)
                        i = j
                        break
        i += 1
    return objects


def _parse_claude_object(obj: dict, src: str) -> dict | None:
    """
    Convert a raw Claude JSON object to our internal conversation format.
    Returns None if the object is not a valid conversation.
    """
    # Must have messages or chat_messages
    msgs_raw = obj.get("messages") or obj.get("chat_messages")
    if not msgs_raw or not isinstance(msgs_raw, list):
        return None

    cid   = (obj.get("uuid") or obj.get("conversation_id") or obj.get("id") or "").strip()
    title = (obj.get("name") or obj.get("title") or "").strip()

    # Parse update_time
    ut = 0.0
    for ts_key in ("updated_at", "update_time", "created_at", "create_time"):
        raw_ts = obj.get(ts_key)
        if raw_ts:
            try:
                if isinstance(raw_ts, (int, float)):
                    ut = float(raw_ts)
                elif isinstance(raw_ts, str):
                    # ISO format
                    dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                    ut = dt.timestamp()
                break
            except Exception:
                pass

    # Parse messages
    messages = []
    for m in msgs_raw:
        if not isinstance(m, dict):
            continue

        # Extract text
        text = ""
        content = m.get("content") or m.get("text") or ""
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text += block.get("text", "")
                elif isinstance(block, str):
                    text += block

        if not text or _is_noise(text):
            continue

        # Role
        role = (m.get("role") or m.get("sender") or "unknown").lower()
        if role not in ("user", "assistant", "human", "system"):
            role = "unknown"
        if role == "human":
            role = "user"

        # Timestamp
        msg_ts = ut
        for ts_key in ("created_at", "updated_at", "timestamp"):
            raw_ts = m.get(ts_key)
            if raw_ts:
                try:
                    if isinstance(raw_ts, (int, float)):
                        msg_ts = float(raw_ts)
                    elif isinstance(raw_ts, str):
                        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        msg_ts = dt.timestamp()
                    break
                except Exception:
                    pass

        mid = (m.get("uuid") or m.get("id") or "").strip()

        messages.append({
            "message_id": mid,
            "role":       role,
            "snippet":    text[:3000],
            "timestamp":  msg_ts,
        })

    if not messages:
        return None

    # Update ut from messages if needed
    if ut <= 0:
        times = [m["timestamp"] for m in messages if m["timestamp"] > 0]
        ut = max(times) if times else 0.0

    return {
        "conversation_id": cid,
        "title":           title or "(recovered conversation)",
        "update_time":     ut,
        "is_deleted":      False,
        "messages":        sorted(messages, key=lambda m: m["timestamp"]),
        "source":          src,
    }


# ─── Cache scanner ────────────────────────────────────────────────────────────
def _scan_cache_file(fpath: str, results: list):
    """Scan one cache file for Claude conversation JSON."""
    try:
        tmp = fpath + "_tmp_claude"
        shutil.copy2(fpath, tmp)
        with open(tmp, "rb") as f:
            raw = f.read()
        os.remove(tmp)
    except Exception:
        return

    if len(raw) < 50:
        return

    # Decode header to find body offset (Chromium simple cache format)
    # Try multiple offsets for the actual content start
    for offset in [0, 256, 512, 8192]:
        chunk = raw[offset:offset + 16 * 1024 * 1024]
        if not chunk:
            continue
        decompressed = _decompress(chunk)
        text = decompressed.decode("utf-8", errors="replace")

        # Only process if it contains Claude-related keys
        if not any(k in text for k in ('"messages"', '"chat_messages"', '"uuid"', '"updated_at"')):
            continue

        for obj_str in _find_json_objects(text):
            try:
                obj = json.loads(obj_str)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue

            conv = _parse_claude_object(obj, os.path.basename(fpath))
            if conv:
                results.append(conv)


# ─── Dedup & merge ────────────────────────────────────────────────────────────
def _merge(raw_results: list) -> list:
    merged: Dict[str, dict] = {}

    for conv in raw_results:
        cid   = (conv.get("conversation_id") or "").strip()
        title = (conv.get("title") or "").strip()
        ut    = float(conv.get("update_time") or 0)
        key   = cid if cid else title[:40]
        if not key:
            continue

        prev = merged.get(key)
        if prev is None:
            merged[key] = conv.copy()
            merged[key]["messages"] = list(conv.get("messages", []))
        else:
            if ut > float(prev.get("update_time") or 0):
                prev["update_time"] = ut
            existing_hashes = {
                hashlib.md5(m.get("snippet", "").encode()).hexdigest()
                for m in prev["messages"]
            }
            for msg in conv.get("messages", []):
                h = hashlib.md5(msg.get("snippet", "").encode()).hexdigest()
                if h not in existing_hashes:
                    prev["messages"].append(msg)
                    existing_hashes.add(h)

    result = list(merged.values())
    for conv in result:
        conv["messages"].sort(key=lambda m: m.get("timestamp", 0))
    result.sort(key=lambda c: float(c.get("update_time") or 0), reverse=True)
    return result


# ─── Public entry point ───────────────────────────────────────────────────────
def run(verbose: bool = True) -> List[dict]:
    """
    Run the Claude extraction pipeline (strict JSON only).
    Returns list of conversation dicts.
    """
    paths = discover_paths()
    if not paths:
        if verbose:
            print("  [!] Claude app path not found on this system.")
        return []

    raw_results = []

    cache_dir = paths.get("cache", "")
    if not os.path.isdir(cache_dir):
        if verbose:
            print(f"  [!] Cache directory not found: {cache_dir}")
    else:
        cache_files = (
            sorted(glob.glob(os.path.join(cache_dir, "data_[123]"))) +
            sorted(glob.glob(os.path.join(cache_dir, "f_*")))
        )
        if verbose:
            print(f"\n  [Cache] Scanning {len(cache_files)} files...")

        for fpath in cache_files:
            before = len(raw_results)
            _scan_cache_file(fpath, raw_results)
            diff = len(raw_results) - before
            if verbose and diff:
                print(f"    [+] {os.path.basename(fpath)}: {diff} conversation(s) found")

    result = _merge(raw_results)

    if verbose:
        if result:
            print(f"\n  [✓] Total: {len(result)} unique conversations")
            newest = result[0]
            ts_s   = float(newest.get("update_time") or 0)
            dt_str = (datetime.fromtimestamp(ts_s + 5.5 * 3600, tz=timezone.utc)
                      .strftime("%Y-%m-%d %H:%M:%S IST") if ts_s > 0 else "N/A")
            print(f"  [✓] Newest: {dt_str} — {newest.get('title','')}")
        else:
            print("\n  [–] No recoverable conversation data found.")

    return result
