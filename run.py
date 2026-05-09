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


def _load_deleted_cids() -> set:
    cids: set = set()
    # Evidence extractor output
    jpath = os.path.join(REPORTS, "DELETED_METADATA_EXTRACT.json")
    try:
        if os.path.isfile(jpath):
            data = json.load(open(jpath, encoding="utf-8"))
            res = data.get("results") or {}
            for key in ("chatgpt", "claude"):
                for r in (res.get(key) or []):
                    cid = (r.get("conversation_id") or "").strip()
                    if cid:
                        cids.add(cid)
    except Exception:
        pass

    # Optional manual list
    mpath = os.path.join(REPORTS, "DELETED_CIDS_MANUAL.txt")
    try:
        if os.path.isfile(mpath):
            for ln in open(mpath, encoding="utf-8"):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                cids.add(s)
    except Exception:
        pass
    return cids


def _split_report_blocks(md_text: str) -> tuple[list[str], list[dict]]:
    """
    Split markdown into:
      - prefix lines before first conversation block
      - list of conversation blocks with parsed metadata
    """
    lines = md_text.splitlines(keepends=True)
    n = len(lines)

    def is_conv_header(i: int) -> bool:
        if i < 0 or i >= n or not lines[i].startswith("## "):
            return False
        look = "".join(lines[i + 1: min(n, i + 14)])
        return ("**Last updated (IST):**" in look) and ("**Conversation ID:**" in look)

    starts = [i for i in range(n) if is_conv_header(i)]
    if not starts:
        return lines, []

    prefix = lines[:starts[0]]
    blocks = []
    for idx, s in enumerate(starts):
        e = starts[idx + 1] if idx + 1 < len(starts) else n
        block_lines = lines[s:e]
        block_text = "".join(block_lines)
        title = lines[s][3:].strip()
        cid = ""
        last_updated = ""
        first_assistant = ""
        roles = []
        for k, ln in enumerate(block_lines):
            t = ln.strip()
            if t.startswith("**Last updated (IST):**"):
                last_updated = t.replace("**Last updated (IST):**", "").strip()
            if t.startswith("**Conversation ID:**") and "`" in t:
                parts = t.split("`")
                if len(parts) >= 3:
                    cid = parts[1].strip()
            if t.startswith("**[") and "] USER:**" in t:
                roles.append("USER")
            elif t.startswith("**[") and "] ASSISTANT:**" in t:
                roles.append("ASSISTANT")
                if not first_assistant:
                    # next non-empty line as snippet seed
                    for p in block_lines[k + 1:]:
                        ps = p.strip()
                        if ps and not ps.startswith("**["):
                            first_assistant = ps
                            break
            elif t.startswith("**[") and "] TOOL:**" in t:
                roles.append("TOOL")
        blocks.append({
            "lines": block_lines,
            "text": block_text,
            "title": title,
            "cid": cid,
            "last_updated": last_updated,
            "roles": roles,
            "first_assistant": first_assistant,
        })
    return prefix, blocks


def _normalize_sig_text(s: str) -> str:
    s = (s or "").lower().strip()
    s = re.sub(r"\s+", " ", s)
    return s


def _postprocess_chatgpt_report(
    md_text: str,
    partial_convs: list | None = None,
    metadata_convs: list | None = None,
) -> tuple[str, dict]:
    """
    Clean chatgpt report:
      - remove unknown/low-quality blocks
      - remove duplicate CIDs
      - remove duplicate conversation clones (same title + first assistant seed)
      - move deleted CIDs into dedicated appendix section
    """
    prefix, blocks = _split_report_blocks(md_text)
    deleted_cids = _load_deleted_cids()

    kept = []
    deleted = []
    seen_cid: set = set()
    seen_sig: set = set()
    stats = {
        "removed_unknown": 0,
        "removed_dup_cid": 0,
        "removed_dup_clone": 0,
        "moved_deleted": 0,
        "partial_conversations": 0,
        "partial_messages": 0,
        "metadata_conversations": 0,
        "kept": 0,
    }

    for b in blocks:
        cid = b.get("cid", "")
        title = b.get("title", "")
        last_updated = (b.get("last_updated") or "").lower()

        # Unknown/noisy blocks
        if "unknown" in last_updated or "**[Unknown] " in b["text"]:
            stats["removed_unknown"] += 1
            continue

        # Move deleted to appendix
        title_l = title.lower()
        looks_deleted = (
            cid in deleted_cids
            or "deleted" in title_l
            or "orphaned" in title_l
            or "unknown (deleted" in title_l
        )
        if looks_deleted:
            deleted.append(b)
            stats["moved_deleted"] += 1
            continue

        # Duplicate CIDs
        if cid and cid in seen_cid:
            stats["removed_dup_cid"] += 1
            continue
        if cid:
            seen_cid.add(cid)

        # Duplicate conversation clones (conservative)
        sig = _normalize_sig_text(title) + "|" + _normalize_sig_text(b.get("first_assistant", ""))[:200]
        if sig.endswith("|"):
            # no assistant seed; don't dedupe aggressively
            kept.append(b)
            continue
        if sig in seen_sig:
            stats["removed_dup_clone"] += 1
            continue
        seen_sig.add(sig)
        kept.append(b)

    out_lines = list(prefix)
    for b in kept:
        out_lines.extend(b["lines"])

    partial_convs = partial_convs or []
    if partial_convs:
        out_lines.append("\n\n---\n\n")
        out_lines.append("## Appendix: Partially Reconstructed Conversations\n\n")
        out_lines.append(
            "These conversations contain readable partial recovery that did not meet strict active "
            "confidence requirements. Snippets are marked as PARTIAL and may be incomplete.\n\n"
        )
        for pc in partial_convs:
            title = (pc.get("title") or "(untitled partial)").strip()
            cid = (pc.get("conversation_id") or "").strip()
            lu = ts_ist(float(pc.get("latest_ts") or 0))
            msgs = list(pc.get("messages") or [])
            out_lines.append(f"### {title}\n\n")
            out_lines.append(f"**Last updated (IST):** {lu}  \n")
            out_lines.append(f"**Conversation ID:** `{cid}`  \n")
            out_lines.append(f"**Reconstruction:** PARTIAL ({len(msgs)} snippet{'s' if len(msgs) != 1 else ''})\n\n")
            for m in msgs:
                mt = ts_ist(float(m.get("ts") or 0))
                role = (m.get("role") or "unknown").upper()
                sn = (m.get("snippet") or "").strip()
                out_lines.append(f"**[{mt}] PARTIAL {role}:**\n\n{sn}\n\n")
            out_lines.append("---\n")
            stats["partial_messages"] += len(msgs)
        stats["partial_conversations"] = len(partial_convs)

    metadata_convs = metadata_convs or []
    if metadata_convs:
        out_lines.append("\n\n---\n\n")
        out_lines.append("## Appendix: Recently Seen Conversations (Metadata Only)\n\n")
        out_lines.append(
            "Conversations detected from local sidebar/history metadata but without clean "
            "recoverable message content yet.\n\n"
        )
        for mc in metadata_convs:
            title = (mc.get("title") or "(untitled)").strip()
            cid = (mc.get("conversation_id") or "").strip()
            lu = ts_ist(float(mc.get("update_time") or 0))
            out_lines.append(f"- **{title}**  \n")
            out_lines.append(f"  - Conversation ID: `{cid}`  \n")
            out_lines.append(f"  - Last updated (IST): {lu}\n")
        stats["metadata_conversations"] = len(metadata_convs)

    if deleted:
        out_lines.append("\n\n---\n\n")
        out_lines.append("## Appendix: Deleted Conversations (Metadata / Evidence)\n\n")
        out_lines.append(
            "Conversations listed here were marked as deleted/tombstoned by evidence "
            "or manual deleted-CID mapping. They are separated from active report content.\n\n"
        )
        for b in deleted:
            title = b.get("title") or "(untitled)"
            cid = b.get("cid") or ""
            lu = b.get("last_updated") or "Unknown"
            out_lines.append(f"- **{title}**  \n")
            out_lines.append(f"  - Conversation ID: `{cid}`  \n")
            out_lines.append(f"  - Last updated (IST): {lu}\n")
    elif deleted_cids:
        out_lines.append("\n\n---\n\n")
        out_lines.append("## Appendix: Deleted Conversations (Metadata / Evidence)\n\n")
        out_lines.append(
            "Deleted CIDs were provided via evidence/manual mapping but did not appear "
            "in active high-confidence reconstruction in this run.\n\n"
        )
        for cid in sorted(deleted_cids):
            out_lines.append("- **(deleted conversation — metadata only)**  \n")
            out_lines.append(f"  - Conversation ID: `{cid}`  \n")
            out_lines.append("  - Last updated (IST): Unknown\n")

    stats["kept"] = len(kept)
    return "".join(out_lines), stats


def _sync_chatgpt_header_counts(md_text: str) -> str:
    """Ensure header counts match final cleaned content."""
    _, blocks = _split_report_blocks(md_text)
    conv_count = len(blocks)
    msg_count = len(re.findall(
        r'^\*\*\[[^\]]+\]\s+(?:USER|ASSISTANT|TOOL|SYSTEM):\*\*$',
        md_text,
        flags=re.M,
    ))
    md_text = re.sub(r'^\*\*Conversations:\*\* \d+\s*$', f"**Conversations:** {conv_count}  ", md_text, flags=re.M)
    md_text = re.sub(r'^\*\*Messages with content:\*\* \d+\s*$', f"**Messages with content:** {msg_count}  ", md_text, flags=re.M)
    return md_text

# ═══════════════════════════════════════════════════════════════════════════════
# Noise Filtering
# ═══════════════════════════════════════════════════════════════════════════════


_NOISE = [
    "[No cached content]", '{"conversation_id"', '"conversation_id"',
    '"current_node_id"', "accountUserId", 'id"$', "client-created-root",
    "created=20", "updated=20", "chatgpt.com_0",
    "conversation-history", "indexeddb.leveldb", "MANIFEST-",
    "Cache_Data", "object store", "Local Storage\\leveldb",
    "blob 83", "lastUpdate", "startTime", "app-minified", "webRTC",
    "CERTIFICATE", "-----BEGIN",
]
_META_JSON_RE = re.compile(
    r'^\s*\{\s*"(?:conversation_id|current_node_id|mapping|title|value|pages|items|accountUserId)"\s*:',
    re.I,
)
_HTML_RE = re.compile(r'<[a-zA-Z][^>]{0,30}>')
_UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)


def _replacement_ratio(s: str) -> float:
    if not s:
        return 1.0
    bad = s.count("\ufffd")
    return bad / max(1, len(s))


def _looks_forensic_fragment(s: str) -> bool:
    t = (s or "").strip()
    if not t:
        return True
    low = t.lower()
    if any(n.lower() in low for n in _NOISE):
        return True
    if _META_JSON_RE.search(t):
        return True
    if _replacement_ratio(t) >= 0.03:
        return True
    if "conversation-history" in low and _UUID_RE.search(low):
        return True
    if re.search(r'^[0-9a-f-]{8,}\s*","starttime":\d{10,}', low):
        return True
    if re.search(r'lastupdate"\s*:\s*\d{10,}', low):
        return True
    if re.search(r'/(?:conversation-history|backend-api)/', low):
        return True
    if re.search(r'timestamp"\s*:\s*\d{10,}\s*,\s*"version"\s*:\s*\d+', low):
        return True
    if re.search(r'","(?:title|create_time|update_time|mapping|current_node|is_archived|memory_scope|workspace_id)"\s*:', low):
        return True
    if "context_scopes_v2" in low or "pageparams" in low:
        return True
    if t.count('":') >= 6 and ("{" in t or "}" in t):
        return True
    return False


def _is_high_conf_message(s: str) -> bool:
    s = (s or "").strip()
    if len(s) < 4:
        return False
    if _looks_forensic_fragment(s):
        return False
    if _HTML_RE.search(s[:120]):
        return False
    if s.startswith("<"):
        return False
    letters = sum(
        1 for c in s if c.isalpha() or unicodedata.category(c).startswith("L")
    )
    printable = sum(1 for c in s if c.isprintable() and c not in "\x00\x01\x02\x03\x04")
    if printable < len(s) * 0.90:
        return False
    return letters >= len(s) * 0.18


def _is_balanced_partial_message(s: str) -> bool:
    """Readable but lower-confidence text for partial appendix."""
    s = (s or "").strip()
    if len(s) < 8:
        return False
    if _looks_forensic_fragment(s):
        return False
    if s.startswith("<") and ">" in s[:20]:
        return False
    if _replacement_ratio(s) >= 0.08:
        return False
    if any((ord(c) < 32 and c not in "\n\r\t") for c in s):
        return False
    if re.search(r'^\s*[\{\[]\s*"(?:conversation_id|mapping|title|value|pages|items)"\s*:', s, re.I):
        return False
    letters = sum(
        1 for c in s if c.isalpha() or unicodedata.category(c).startswith("L")
    )
    printable = sum(1 for c in s if c.isprintable())
    if printable < len(s) * 0.85:
        return False
    if letters < max(3, int(len(s) * 0.08)):
        return False
    return True


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


# ── Topic-similarity helpers (Rules 1-4) ─────────────────────────────────────

_STOPWORDS = frozenset({
    "the", "a", "an", "is", "in", "it", "of", "to", "and", "or", "that",
    "this", "for", "on", "with", "you", "i", "my", "your", "we", "are",
    "was", "be", "at", "by", "from", "as", "have", "has", "not", "do",
    "did", "can", "will", "but", "so", "if", "me", "he", "she", "they",
    "then", "what", "how", "when", "where", "which", "its", "our", "their",
    "about", "also", "just", "more", "use", "used", "using", "like",
})
_TOPIC_DRIFT_THRESHOLD = 0.15  # Jaccard below this → split instead of merge


def _word_set(text: str, max_words: int = 40) -> frozenset:
    """Significant word set for topic comparison (stopwords excluded)."""
    words = re.findall(r'[a-zA-Z]{3,}', (text or ""))
    return frozenset(
        w.lower() for w in words[:max_words] if w.lower() not in _STOPWORDS
    )


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _infer_dominant_title(msgs: list, fallback_title: str) -> tuple[str, bool]:
    """
    Infer dominant topic from all message snippets.
    Returns (best_title, is_low_confidence).
    Accepts fallback_title if it overlaps with dominant words, otherwise flags
    the title as [LOW CONFIDENCE TITLE].
    """
    all_text = " ".join((m.get("snippet") or "") for m in (msgs or []))
    words = re.findall(r'[a-zA-Z]{4,}', all_text)
    freq: dict[str, int] = {}
    for w in words:
        wl = w.lower()
        if wl in _STOPWORDS:
            continue
        freq[wl] = freq.get(wl, 0) + 1
    if not freq:
        return (fallback_title or "(untitled)"), True
    top_words = [w for w, _ in sorted(freq.items(), key=lambda x: -x[1])[:5]]
    dom_set = frozenset(top_words)
    if fallback_title:
        ft_set = _word_set(fallback_title, max_words=20)
        if ft_set & dom_set:
            return fallback_title, False   # title matches dominant topic
        # Title doesn't overlap — mark low confidence
        return fallback_title, True
    inferred = " ".join(top_words[:3]).title()
    return inferred, True


def _merge_chatgpt_convs_by_uuid(convs: dict, skip_titles: set) -> tuple[dict, list]:
    """One row per conversation UUID; merges duplicate keys that share the same id.

    Returns (merged_dict, drifted_items) where drifted_items contains records
    that were NOT merged because topic-drift was detected (Rules 1, 2, 3).
    Their messages are routed to the low-confidence / partial appendix by the caller.
    """
    by_uuid: dict = {}
    rest = {}
    drifted: list = []   # records split off due to topic drift

    for _key, c in convs.items():
        cid = (c.get("cid") or "").strip()
        if not cid:
            rest[_key] = c
            continue
        cl = cid.lower()
        new_msgs = list(c.get("msgs") or [])

        if cl not in by_uuid:
            by_uuid[cl] = {
                "cid": cid,
                "title": c.get("title") or "",
                "ts": float(c.get("ts") or 0),
                "is_archived": bool(c.get("is_archived")),
                "is_starred": bool(c.get("is_starred")),
                "msgs": new_msgs,
            }
            continue

        tgt = by_uuid[cl]
        tgt_msgs = tgt["msgs"]

        # ── Topic-drift guard (Rules 1, 2, 3) ────────────────────────────
        # Only compare when both sides carry real message content.
        if tgt_msgs and new_msgs:
            tgt_text = " ".join(m.get("snippet", "") for m in tgt_msgs[:3])
            new_text  = " ".join(m.get("snippet", "") for m in new_msgs[:3])
            combined_tgt = (tgt.get("title") or "") + " " + tgt_text
            combined_new  = (c.get("title") or "")   + " " + new_text
            sim = _jaccard(_word_set(combined_tgt), _word_set(combined_new))
            if sim < _TOPIC_DRIFT_THRESHOLD:
                # Divergent topic — split off; caller routes to low_conf/partial.
                drifted.append({
                    "cid":   cid,
                    "title": c.get("title") or tgt.get("title") or "",
                    "ts":    float(c.get("ts") or 0),
                    "msgs":  new_msgs,
                    "_drift_similarity": sim,
                })
                continue

        # No drift — standard merge
        seen = {m["snippet"][:100] for m in tgt_msgs}
        for m in new_msgs:
            sk = m["snippet"][:100]
            if sk not in seen:
                tgt_msgs.append(m)
                seen.add(sk)
        ot = c.get("title") or ""
        if ot and ot not in skip_titles:
            if not tgt["title"] or tgt["title"] in skip_titles:
                tgt["title"] = ot
        tgt["ts"] = max(tgt["ts"], float(c.get("ts") or 0))
        tgt["is_archived"] = tgt["is_archived"] or bool(c.get("is_archived"))
        tgt["is_starred"]  = tgt["is_starred"]  or bool(c.get("is_starred"))

    out = dict(rest)
    for _cl, c in by_uuid.items():
        out[c["cid"]] = c
    return out, drifted


def _chatgpt_report_out_items(out_items: list) -> list:
    """Omit metadata-only stubs; drop chats with no recoverable message rows."""
    by_cid: dict = {}
    for x in out_items:
        cid = x.get("conversation_id") or ""
        if not cid:
            continue
        by_cid.setdefault(cid, []).append(x)
    out = []
    for _cid, items in by_cid.items():
        real = [
            x for x in items
            if _is_high_conf_message((x.get("payload") or {}).get("snippet", ""))
        ]
        if real:
            out.extend(real)
    return out


def is_real(s: str) -> bool:
    # Backward-compatible alias used by Claude path.
    return _is_high_conf_message(s)


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


def _write_chatgpt_low_conf_archive(items: list):
    """Write quarantined low-confidence records outside active report."""
    json_path = os.path.join(REPORTS, "CHATGPT_LOW_CONFIDENCE_ARCHIVE.json")
    md_path = os.path.join(REPORTS, "CHATGPT_LOW_CONFIDENCE_ARCHIVE.md")

    dedup = {}
    for it in items:
        cid = (it.get("conversation_id") or "").strip()
        title = (it.get("title") or "").strip()
        role = (it.get("role") or "").strip().lower()
        snip = (it.get("snippet") or "").strip()
        src = (it.get("source") or "").strip()
        reason = (it.get("reason") or "").strip()
        ts = float(it.get("timestamp") or 0)
        k = hashlib.md5(f"{cid}|{title}|{role}|{snip[:180]}|{src}|{reason}".encode("utf-8", errors="ignore")).hexdigest()
        if k not in dedup:
            dedup[k] = {
                "conversation_id": cid,
                "title": title,
                "role": role,
                "timestamp": ts,
                "snippet": snip[:4000],
                "source": src,
                "reason": reason,
            }

    out = sorted(dedup.values(), key=lambda x: float(x.get("timestamp") or 0), reverse=True)
    payload = {
        "generated_at_ist": ts_ist(time.time()),
        "count": len(out),
        "items": out,
    }
    with open(json_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    lines = [
        "# CHATGPT Low Confidence Archive\n\n",
        f"**Generated:** {ts_ist(time.time())}  \n",
        f"**Items:** {len(out)}\n\n",
        "This file stores low-confidence fragments intentionally excluded from active reconstruction.\n\n",
        "---\n\n",
    ]
    for it in out:
        title = it.get("title") or "(untitled)"
        cid = it.get("conversation_id") or "(missing)"
        role = (it.get("role") or "unknown").upper()
        reason = it.get("reason") or "low-confidence fragment"
        src = it.get("source") or "unknown"
        when = ts_ist(float(it.get("timestamp") or 0))
        lines.append(f"## {title}\n\n")
        lines.append(f"**Conversation ID:** `{cid}`  \n")
        lines.append(f"**Reason:** {reason}  \n")
        lines.append(f"**Source:** `{src}`  \n")
        lines.append(f"**Timestamp (IST):** {when}\n\n")
        lines.append(f"**[{when}] {role}:**\n\n{(it.get('snippet') or '').strip()}\n\n")
        lines.append("---\n\n")
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(lines)
    return json_path, md_path, len(out)


def _validate_chatgpt_active_items(out_items: list) -> tuple[list, dict]:
    """Final guardrail pass for active report integrity (Rules 9 & 10).

    ONLY messages that pass _is_high_conf_message enter the active section.
    Messages that pass _is_balanced_partial_message but NOT _is_high_conf_message
    are counted as partial-only slip-throughs and blocked here.  The caller
    routes them to the partial appendix via the low_conf pipeline instead.
    """
    stats = {
        "removed_missing_cid": 0,
        "removed_bad_role": 0,
        "removed_bad_time": 0,
        "removed_garbage": 0,
        "removed_partial_only": 0,  # Rule 9/10 gate
        "removed_duplicates": 0,
        "kept": 0,
    }
    seen: set = set()
    clean = []
    valid_roles = {"user", "assistant", "tool", "system"}
    for it in out_items:
        cid  = (it.get("conversation_id") or "").strip()
        pl   = it.get("payload") or {}
        role = (pl.get("role") or "").strip().lower()
        snip = (pl.get("snippet") or "").strip()
        ts   = float(it.get("update_time") or 0)
        if not cid:
            stats["removed_missing_cid"] += 1
            continue
        if role not in valid_roles:
            stats["removed_bad_role"] += 1
            continue
        if ts < 1e9:
            stats["removed_bad_time"] += 1
            continue
        # Rules 9 & 10 — accuracy over completeness:
        # Partial-quality text must NOT enter the active section.
        if not _is_high_conf_message(snip):
            if _is_balanced_partial_message(snip):
                stats["removed_partial_only"] += 1
            else:
                stats["removed_garbage"] += 1
            continue
        dedup_key = (
            f"{cid}|{role}|{round(ts)}|"
            f"{hashlib.md5(snip[:300].encode('utf-8', errors='ignore')).hexdigest()}"
        )
        if dedup_key in seen:
            stats["removed_duplicates"] += 1
            continue
        seen.add(dedup_key)
        clean.append(it)
    stats["kept"] = len(clean)
    return clean, stats


def _build_partial_conversations(low_conf_items: list, deleted_cids: set) -> tuple[list, dict]:
    """
    Build readable partial conversations (balanced filter) for appendix.
    Deleted CIDs are excluded to keep deleted segregation unchanged.
    """
    valid_roles = {"user", "assistant", "tool", "system"}
    by_cid: dict = {}
    seen_keys: set = set()
    stats = {
        "included_snippets": 0,
        "included_conversations": 0,
        "dropped_missing_cid": 0,
        "dropped_deleted_cid": 0,
        "dropped_unreadable": 0,
        "dropped_bad_role": 0,
        "dropped_duplicates": 0,
    }

    for it in low_conf_items:
        cid = (it.get("conversation_id") or "").strip()
        title = (it.get("title") or "").strip()
        role = (it.get("role") or "unknown").strip().lower()
        snip = (it.get("snippet") or "").strip()
        ts = float(it.get("timestamp") or 0)
        if not cid:
            stats["dropped_missing_cid"] += 1
            continue
        if cid in deleted_cids:
            stats["dropped_deleted_cid"] += 1
            continue
        if role not in valid_roles:
            stats["dropped_bad_role"] += 1
            continue
        if not _is_balanced_partial_message(snip):
            stats["dropped_unreadable"] += 1
            continue

        norm = _normalize_sig_text(snip)[:350]
        dedup_key = hashlib.md5(
            f"{cid}|{role}|{round(ts)}|{norm}".encode("utf-8", errors="ignore")
        ).hexdigest()
        if dedup_key in seen_keys:
            stats["dropped_duplicates"] += 1
            continue
        seen_keys.add(dedup_key)

        key = cid.lower()
        entry = by_cid.get(key)
        if entry is None:
            entry = {
                "conversation_id": cid,
                "title": title or "(untitled partial)",
                "latest_ts": ts,
                "messages": [],
            }
            by_cid[key] = entry
        elif title and (not entry.get("title") or entry.get("title") == "(untitled partial)"):
            entry["title"] = title

        entry["latest_ts"] = max(float(entry.get("latest_ts") or 0), ts)
        entry["messages"].append({
            "role": role,
            "snippet": snip[:4000],
            "ts": ts,
        })
        stats["included_snippets"] += 1

    out = []
    for conv in by_cid.values():
        conv["messages"].sort(key=lambda m: float(m.get("ts") or 0))
        out.append(conv)
    out.sort(key=lambda c: float(c.get("latest_ts") or 0), reverse=True)
    stats["included_conversations"] = len(out)
    return out, stats


def _build_metadata_only_conversations(
    ls_entries: list,
    active_items: list,
    partial_convs: list,
    deleted_cids: set,
) -> list:
    active_cids = {(x.get("conversation_id") or "").strip() for x in (active_items or []) if (x.get("conversation_id") or "").strip()}
    partial_cids = {(x.get("conversation_id") or "").strip() for x in (partial_convs or []) if (x.get("conversation_id") or "").strip()}
    out_map: dict = {}
    for e in (ls_entries or []):
        cid = (e.get("conversation_id") or "").strip()
        title = (e.get("title") or "").strip()
        ts = float(e.get("update_time") or 0)
        if not cid:
            continue
        if cid in deleted_cids or cid in active_cids or cid in partial_cids:
            continue
        if not title or title.lower() in {"new chat", "unknown (deleted/orphaned conversation)"}:
            continue
        if _looks_forensic_fragment(title):
            continue
        prev = out_map.get(cid)
        if prev is None or ts > float(prev.get("update_time") or 0):
            out_map[cid] = {
                "conversation_id": cid,
                "title": title,
                "update_time": ts,
            }
    out = list(out_map.values())
    out.sort(key=lambda x: float(x.get("update_time") or 0), reverse=True)
    return out


def _load_prior_reconstructed_by_cid() -> dict:
    out: dict = {}
    candidates = [
        os.path.join(REPORTS, "CHATGPT_PREVIOUSLY_EXTRACTED.json"),
        os.path.join(REPORTS, "RECOVERED_CHATGPT_GROUPED.json"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            raw = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        items = raw.get("conversations") if isinstance(raw, dict) and "conversations" in raw else raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            continue
        for conv in items:
            if not isinstance(conv, dict):
                continue
            cid = (conv.get("conversation_id") or "").strip()
            if not cid:
                continue
            title = (conv.get("title") or "").strip()
            lts = float(conv.get("last_seen_ts") or conv.get("latest_update") or conv.get("update_time") or 0)
            msgs = []
            for m in (conv.get("messages") or []):
                role = (m.get("role") or "").strip().lower()
                sn = (m.get("snippet") or "").strip()
                mts = float(m.get("ts") or m.get("update_time") or lts)
                if role not in {"user", "assistant", "tool", "system"}:
                    continue
                if not _is_balanced_partial_message(sn):
                    continue
                msgs.append({"role": role, "snippet": sn[:4000], "ts": mts})
            if not msgs:
                continue
            cur = out.get(cid)
            if cur is None or lts > float(cur.get("latest_ts") or 0):
                msgs.sort(key=lambda x: float(x.get("ts") or 0))
                out[cid] = {
                    "title": title or "(untitled)",
                    "latest_ts": lts,
                    "messages": msgs[:3],
                }
    return out


def _promote_metadata_with_prior_reconstruction(
    metadata_convs: list,
    partial_convs: list,
) -> tuple[list, list, int]:
    prior_map = _load_prior_reconstructed_by_cid()
    existing_partial = {(c.get("conversation_id") or "").strip() for c in (partial_convs or [])}
    promoted = []
    kept_meta = []
    promoted_count = 0
    for m in (metadata_convs or []):
        cid = (m.get("conversation_id") or "").strip()
        if not cid or cid in existing_partial:
            kept_meta.append(m)
            continue
        prior = prior_map.get(cid)
        if not prior:
            kept_meta.append(m)
            continue
        promoted.append({
            "conversation_id": cid,
            "title": (m.get("title") or prior.get("title") or "(untitled)").strip(),
            "latest_ts": float(m.get("update_time") or prior.get("latest_ts") or 0),
            "messages": list(prior.get("messages") or []),
        })
        promoted_count += 1
    merged_partial = list(partial_convs or []) + promoted
    merged_partial.sort(key=lambda c: float(c.get("latest_ts") or 0), reverse=True)
    return merged_partial, kept_meta, promoted_count


def run_chatgpt(paths: dict):
    """Full ChatGPT extraction pipeline → single report.
    Strict mode:
      - active report uses high-confidence CID-bound messages only
      - low-confidence data (WAL/history/noisy fragments) is archived separately
    """
    _sep("─")

    SKIP = {"Unknown (deleted/orphaned conversation)", "New chat", "Student",
            "Test message response", "Testing cache behavior", "Deleted Fragment Recovery", ""}

    convs: dict = {}  # keyed strictly by CID
    low_conf: list = []

    def add_low_conf(source: str, reason: str, cid: str, title: str, snip: str, role: str = "", ts: float = 0.0):
        sn = (snip or "").strip()
        if not sn:
            return
        low_conf.append({
            "source": source,
            "reason": reason,
            "conversation_id": cid or "",
            "title": title or "",
            "role": role or "unknown",
            "timestamp": float(ts or 0.0),
            "snippet": sn[:4000],
        })

    def upsert_active(cid, title, ts, is_arch, is_star, msgs, trust_ts=True):
        if not cid:
            for m in msgs:
                add_low_conf("live", "missing_cid", "", title, m.get("snippet", ""), m.get("role", ""), m.get("ts", ts))
            return
        key = cid.strip().lower()
        prev = convs.get(key)
        if prev is None:
            convs[key] = {"cid": cid.strip(), "title": title, "ts": ts,
                          "is_archived": is_arch, "is_starred": is_star,
                          "msgs": list(msgs)}
            return
        if cid and not prev["cid"]:
            prev["cid"] = cid.strip()
        if title and title not in SKIP:
            if not prev["title"] or prev["title"] in SKIP:
                prev["title"] = title
        if trust_ts and ts > float(prev["ts"] or 0) and ts < 1_773_902_000:
            prev["ts"] = ts
        prev["is_archived"] = is_arch or prev["is_archived"]
        prev["is_starred"] = is_star or prev["is_starred"]
        seen = {
            hashlib.md5(
                f"{(m.get('role') or '').lower()}|{(m.get('snippet') or '').strip()[:250]}|{round(float(m.get('ts') or 0))}".encode(
                    "utf-8", errors="ignore"
                )
            ).hexdigest()
            for m in prev["msgs"]
        }
        for m in msgs:
            mk = hashlib.md5(
                f"{(m.get('role') or '').lower()}|{(m.get('snippet') or '').strip()[:250]}|{round(float(m.get('ts') or 0))}".encode(
                    "utf-8", errors="ignore"
                )
            ).hexdigest()
            if mk not in seen:
                prev["msgs"].append(m)
                seen.add(mk)

    def conv_to_msgs(item, source: str):
        ts = float(
            item.get("update_time")
            or item.get("latest_update")
            or 0
        )
        icid  = item.get("conversation_id", "")
        ititle = item.get("title", "")
        raw_out = []
        for m in (item.get("messages") or []):
            snip = (m.get("snippet") or m.get("text") or "").strip()
            snip = _trim_glued_forensic_snippet(snip)
            role = (m.get("role") or "unknown").lower().strip()
            mts = float(m.get("timestamp") or m.get("update_time") or ts)
            if role not in {"user", "assistant", "tool", "system"}:
                add_low_conf(source, "invalid_role", icid, ititle, snip, role, mts)
                continue
            if not _is_high_conf_message(snip):
                add_low_conf(source, "garbage_or_low_conf", icid, ititle, snip, role, mts)
                continue
            raw_out.append({
                "mid":     (m.get("message_id") or m.get("id") or ""),
                "role":    role,
                "snippet": snip[:4000],
                "ts":      mts,
            })

        # ── Rule 7: assistant-reply guard ────────────────────────────────
        # An assistant turn that shares zero word-overlap with ANY preceding
        # user turn (within a 3-turn window) is unrelated — route to partial.
        raw_out.sort(key=lambda x: x.get("ts", 0))
        out = []
        for i, msg in enumerate(raw_out):
            if msg["role"] == "assistant":
                preceding_user = [
                    raw_out[j]["snippet"]
                    for j in range(max(0, i - 3), i)
                    if raw_out[j]["role"] == "user"
                ]
                if preceding_user:
                    asst_words = _word_set(msg["snippet"])
                    user_words = _word_set(" ".join(preceding_user))
                    if asst_words and user_words and _jaccard(asst_words, user_words) == 0.0:
                        add_low_conf(
                            source, "no_user_context_overlap",
                            icid, ititle,
                            msg["snippet"], msg["role"], msg["ts"],
                        )
                        continue
            out.append(msg)
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
            msgs = conv_to_msgs(item, "live_cache_ldb")
            upsert_active(
                cid, title, ts,
                bool(item.get("is_archived")), bool(item.get("is_starred")),
                msgs, trust_ts=True
            )
        print(f"      → {len(live_convs)} live conversations found")
        print(f"      → {len(convs)} unique after dedup")
    except Exception as e:
        print(f"      [warn] Live scan error: {e}")

    print("  [2/3] Applying accurate timestamps from Local Storage …")
    ls_dir = paths.get("ls_ldb", "")
    ch = []
    if os.path.isdir(ls_dir):
        ch = _ls_conversation_history(ls_dir)
        applied = 0
        for entry in ch:
            ecid = entry.get("conversation_id", "")
            etitle = entry.get("title", "")
            ets = float(entry.get("update_time") or 0)
            if ecid and ecid.lower() in convs and ets > 1e9:
                convs[ecid.lower()]["ts"] = ets
                if etitle:
                    convs[ecid.lower()]["title"] = etitle
                applied += 1
            elif ecid and ets > 1e9:
                # metadata-only shell kept for CID correctness if messages arrive later
                convs[ecid.lower()] = {
                    "cid": ecid, "title": etitle, "ts": ets,
                    "is_archived": bool(entry.get("is_archived")),
                    "is_starred": bool(entry.get("is_starred")),
                    "msgs": [],
                }
        print(f"      → {len(ch)} LS entries, {applied} timestamps corrected")
    else:
        print("      → Local Storage not found")

    old_file = os.path.join(REPORTS, "RECOVERED_CHATGPT_GROUPED.json")
    if os.path.isfile(old_file):
        print("  [3/4] Archiving historical recovered data (excluded from active) …")
        try:
            old_raw = json.load(open(old_file, encoding="utf-8"))
            old_items = old_raw if isinstance(
                old_raw, list) else old_raw.get("items", [])
            for item in old_items:
                cid = (item.get("conversation_id") or "").strip()
                title = (item.get("title") or "").strip()
                if title in SKIP:
                    continue
                ts = float(item.get("latest_update") or item.get("update_time") or 0)
                for m in conv_to_msgs(item, "historical_file"):
                    add_low_conf("historical_file", "historical_not_active", cid, title, m.get("snippet", ""), m.get("role", ""), float(m.get("ts") or ts))
            print(f"      → {len(old_items)} records moved to low-confidence archive")
        except Exception as e:
            print(f"      [warn] Historical merge failed: {e}")
    else:
        print("  [3/4] No historical file — running strict live-only active mode")

    print("  [4/4] Scanning LevelDB logs (WAL) to quarantine weak fragments …")
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
                    role = "assistant"
                    if "user" in window[max(0, window.find(run)-100): window.find(run)].lower():
                        role = "user"
                    if _is_high_conf_message(run) and len(run) >= 35:
                        add_low_conf("wal_log", "wal_untrusted_for_active", cid, "", run[:4000], role, time.time())
                        found_wal += 1
                        break
        if found_wal:
            print(f"      → {found_wal} snippets quarantined from WAL logs")
    else:
        print("      → No WAL log files found")

    convs, drifted_records = _merge_chatgpt_convs_by_uuid(convs, SKIP)

    # Route topic-drift records to low_conf / partial appendix (Rules 1-3)
    for drift_rec in drifted_records:
        cid   = drift_rec.get("cid", "")
        title = drift_rec.get("title", "")
        sim   = drift_rec.get("_drift_similarity", 0.0)
        for m in drift_rec.get("msgs", []):
            add_low_conf(
                "drift_split",
                f"topic_drift_detected(sim={sim:.2f})",
                cid, title,
                m.get("snippet", ""), m.get("role", ""),
                float(m.get("ts") or 0),
            )
    if drifted_records:
        print(f"      → {len(drifted_records)} drift-split records routed to partial appendix")

    # ── Build output ────────────────────────────────────────────
    print("      Building report …")
    clist = [c for c in convs.values() if (c.get("cid") or "").strip()]
    clist = sorted(clist, key=lambda c: float(c["ts"] or 0), reverse=True)
    out_items = []
    for conv in clist:
        cid = conv["cid"]
        msgs_sorted = sorted(conv["msgs"], key=lambda m: m.get("ts", 0))
        ts = float(conv["ts"] or 0)

        # Rule 4 — validate title against dominant topic (no visible label)
        inferred_title, _ = _infer_dominant_title(
            msgs_sorted, conv.get("title") or ""
        )
        title = inferred_title or conv.get("title") or "(untitled)"

        for m in msgs_sorted:
            out_items.append({
                "conversation_id": cid, "current_node_id": m["mid"],
                "title": title, "model": "",
                "is_archived": conv["is_archived"], "is_starred": conv["is_starred"],
                "update_time": ts,
                "payload": {"kind": "message", "message_id": m["mid"],
                            "snippet": m["snippet"], "role": m["role"]}
            })

    out_report = _chatgpt_report_out_items(out_items)
    out_report, val_stats = _validate_chatgpt_active_items(out_report)
    chatgpt_cids = sorted({x["conversation_id"] for x in out_report if x.get("conversation_id")})
    deleted_cids = _load_deleted_cids()
    partial_convs, partial_stats = _build_partial_conversations(low_conf, deleted_cids)
    metadata_convs = _build_metadata_only_conversations(ch, out_report, partial_convs, deleted_cids)
    partial_convs, metadata_convs, promoted_count = _promote_metadata_with_prior_reconstruction(
        metadata_convs, partial_convs
    )
    print(
        f"      Active validation: kept={val_stats['kept']} "
        f"removed_missing_cid={val_stats['removed_missing_cid']} "
        f"removed_bad_role={val_stats['removed_bad_role']} "
        f"removed_bad_time={val_stats['removed_bad_time']} "
        f"removed_garbage={val_stats['removed_garbage']} "
        f"removed_partial_only={val_stats['removed_partial_only']} "
        f"removed_duplicates={val_stats['removed_duplicates']}"
    )
    print(
        f"      Partial appendix: conversations={partial_stats['included_conversations']} "
        f"snippets={partial_stats['included_snippets']} dropped_missing_cid={partial_stats['dropped_missing_cid']} "
        f"dropped_deleted={partial_stats['dropped_deleted_cid']} dropped_unreadable={partial_stats['dropped_unreadable']} "
        f"dropped_bad_role={partial_stats['dropped_bad_role']} dropped_duplicates={partial_stats['dropped_duplicates']}"
    )
    print(f"      Prior reconstruction promotions: {promoted_count} conversations")
    print(f"      Metadata-only appendix: conversations={len(metadata_convs)}")
    _write_report(
        "CHATGPT",
        chatgpt_cids,
        out_report,
        chatgpt_partial_convs=partial_convs,
        chatgpt_metadata_convs=metadata_convs,
    )
    jpath, mpath, arc_count = _write_chatgpt_low_conf_archive(low_conf)
    print(f"      Low-confidence archive: {arc_count} items")
    print(f"      Archive JSON → {jpath}")
    print(f"      Archive MD   → {mpath}")


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

    # ── Cross-CID deduplication ───────────────────────────────────────────────
    # Same conversation can arrive from multiple sources with different CIDs.
    # Strategy: group by conversation_id first, then by normalized title.
    # Within each title-group, prefer the CID that has real message content;
    # among ties keep the one with the latest timestamp.

    def _norm_title(t: str) -> str:
        return re.sub(r'\s+', ' ', (t or "").strip().lower())

    # Build per-CID summaries
    by_cid_summary: dict = {}   # cid → {has_real, latest_ts, title}
    for it in out_items:
        cid  = it["conversation_id"]
        is_real_msg = not it["payload"]["snippet"].startswith("[No content")
        ts   = float(it.get("update_time") or 0)
        title = it.get("title") or ""
        if cid not in by_cid_summary:
            by_cid_summary[cid] = {"has_real": is_real_msg, "latest_ts": ts, "title": title}
        else:
            s = by_cid_summary[cid]
            s["has_real"] = s["has_real"] or is_real_msg
            s["latest_ts"] = max(s["latest_ts"], ts)
            if title and not s["title"]:
                s["title"] = title

    # Group CIDs by normalized title; pick the winner per group
    title_to_cids: dict = {}
    for cid, s in by_cid_summary.items():
        nt = _norm_title(s["title"])
        if not nt or nt in {"new chat", "untitled"}:
            continue   # can't dedup anonymous chats safely
        title_to_cids.setdefault(nt, []).append(cid)

    dropped_cids: set = set()
    for nt, cids in title_to_cids.items():
        if len(cids) < 2:
            continue
        # Score: (has_real=1, latest_ts); highest score wins
        ranked = sorted(
            cids,
            key=lambda c: (by_cid_summary[c]["has_real"], by_cid_summary[c]["latest_ts"]),
            reverse=True,
        )
        for loser in ranked[1:]:
            dropped_cids.add(loser)

    if dropped_cids:
        before = len(out_items)
        out_items = [x for x in out_items if x["conversation_id"] not in dropped_cids]
        print(f"      → Dropped {len(dropped_cids)} duplicate CIDs (same title, different UUID): "
              f"{before} → {len(out_items)} items")

    # ── Within each CID, drop duplicate snippets ─────────────────────────────
    seen_snip: dict = {}   # cid → set of snippet hashes
    deduped_final = []
    for it in out_items:
        cid  = it["conversation_id"]
        snip = it["payload"]["snippet"]
        h    = hashlib.md5(snip[:200].encode("utf-8", errors="ignore")).hexdigest()
        if h not in seen_snip.setdefault(cid, set()):
            seen_snip[cid].add(h)
            deduped_final.append(it)
    out_items = deduped_final

    cid_set = {x["conversation_id"] for x in out_items}
    total_real = sum(1 for x in out_items
                     if not x["payload"]["snippet"].startswith("[No content"))

    print(f"      → {len(out_items)} total items ({total_real} with real content, "
          f"{len(out_items)-total_real} metadata-only)")

    _write_report("CLAUDE", list(cid_set), out_items, is_claude=True)


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT WRITER (single-file output)
# ═══════════════════════════════════════════════════════════════════════════════

def _write_report(
    app: str,
    clist,
    out_items: list,
    is_claude: bool = False,
    chatgpt_partial_convs: list | None = None,
    chatgpt_metadata_convs: list | None = None,
):
    now = ts_ist(datetime.utcnow().timestamp())
    total_convs = len(clist)
    with_content = sum(1 for x in out_items
                       if not x["payload"]["snippet"].startswith("[No content"))

    md_path = os.path.join(REPORTS, f"{app}_FORENSIC_REPORT.md")
    raw_path = os.path.join(REPORTS, f"{app}_FORENSIC_REPORT_RAW.md")

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
        msgs_sorted = sorted(
            citems, key=lambda x: float(x.get("update_time", 0)))
        real_msgs = [
            x for x in msgs_sorted
            if not x["payload"]["snippet"].startswith("[No content")
        ]
        if app == "CHATGPT":
            if not real_msgs:
                continue
            title = real_msgs[0].get("title", "(untitled)")
            ts = conv_ts(citems)
            lines.append(f"\n## {title}\n\n")
            lines.append(f"**Last updated (IST):** {ts_ist(ts)}  \n")
            lines.append(f"**Conversation ID:** `{cid}`\n\n")

            for item in sorted(real_msgs, key=lambda x: float(x.get("update_time", 0))):
                snip = item["payload"]["snippet"]
                role = (item["payload"].get("role") or "unknown").upper()
                mt = ts_ist(float(item.get("update_time", 0)))
                lines.append(f"**[{mt}] {role}:**\n\n{snip}\n\n")
            lines.append("---\n")
            continue

        title = citems[0].get("title", "(untitled)")
        ts = conv_ts(citems)
        lines.append(f"\n## {title}\n\n")
        lines.append(f"**Last updated (IST):** {ts_ist(ts)}  \n")
        lines.append(f"**Conversation ID:** `{cid}`\n\n")
        has_real = bool(real_msgs)
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

    report_text = "".join(lines)
    if app == "CHATGPT":
        # Raw backup first (for traceability).
        with open(raw_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(report_text)

        cleaned, st = _postprocess_chatgpt_report(
            report_text,
            partial_convs=(chatgpt_partial_convs or []),
            metadata_convs=(chatgpt_metadata_convs or []),
        )
        cleaned = _sync_chatgpt_header_counts(cleaned)
        with open(md_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(cleaned)

        print(
            f"    Postprocess: kept={st['kept']}, removed_unknown={st['removed_unknown']}, "
            f"removed_dup_cid={st['removed_dup_cid']}, removed_dup_clone={st['removed_dup_clone']}, "
            f"moved_deleted={st['moved_deleted']}, partial_conversations={st.get('partial_conversations',0)}, "
            f"partial_messages={st.get('partial_messages',0)}, metadata_conversations={st.get('metadata_conversations',0)}"
        )
        print(f"    Raw backup → {raw_path}")
    else:
        with open(md_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(report_text)

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
