# Digital Forensic Analysis of LLM Desktop Application Artifacts
## Technical Implementation Notes — Thesis Level Documentation

---

> **Project:** Forensic Tool for Analyzing LLM Artifacts  
> **Scope:** ChatGPT Desktop (Windows) and Claude Desktop (Windows)  
> **Language:** Python 3.11+  
> **Platform:** Windows 10/11  
> **Date:** March 2026

---

## Table of Contents

1. [Introduction and Motivation](#1-introduction-and-motivation)
2. [Background: How Electron Apps Store Data](#2-background-how-electron-apps-store-data)
3. [Storage Architecture of LLM Desktop Apps](#3-storage-architecture-of-llm-desktop-apps)
4. [ChatGPT Data Extraction Pipeline](#4-chatgpt-data-extraction-pipeline)
5. [Claude Data Extraction Pipeline](#5-claude-data-extraction-pipeline)
6. [Data Recovery Strategy](#6-data-recovery-strategy)
7. [Unified Entry Point — run.py Architecture](#7-unified-entry-point--runpy-architecture)
8. [Snippet Quality Filtering](#8-snippet-quality-filtering)
9. [Output Schema Design](#9-output-schema-design)
10. [Portability and Forensic Considerations](#10-portability-and-forensic-considerations)
11. [Results and Validation](#11-results-and-validation)
12. [Limitations and Future Work](#12-limitations-and-future-work)

---

## 1. Introduction and Motivation

Large Language Model (LLM) desktop applications such as **OpenAI's ChatGPT Desktop** and **Anthropic's Claude Desktop** are increasingly used for sensitive academic, professional, and personal tasks. From a digital forensics perspective, these applications leave behind rich artifacts — conversation histories, message content, timestamps, and session metadata — stored in structured binary formats on the host operating system.

This tool was developed to answer a core forensic question:

> *"What conversation data can be recovered from a Windows system running ChatGPT or Claude Desktop, and how can it be presented in a forensically sound, human-readable format?"*

Unlike web browser forensics (where history, cookies, and cache are well-understood), LLM desktop app forensics is a relatively unexplored domain. Both ChatGPT and Claude desktop apps are built on **Electron**, a framework that wraps web applications in a native desktop shell using **Chromium** as the rendering engine. This means their storage patterns follow Chromium's internal data formats — LevelDB, IndexedDB, HTTP Cache — but at paths unique to each application's Windows package identity.

---

## 2. Background: How Electron Apps Store Data

### 2.1 Electron and Chromium Storage

Electron applications use Chromium's storage engine, which provides:

| Storage Mechanism | Purpose | Format |
|---|---|---|
| **IndexedDB** | Structured JS object storage (conversations, settings) | LevelDB (SSTable + WAL) |
| **Local Storage** | Key-value pairs (conversation list, metadata) | LevelDB |
| **HTTP Cache** | API response caching | Chromium Simple Cache |
| **IndexedDB Blob** | Large binary objects (message bodies) | V8-serialized binary |

### 2.2 LevelDB Format

LevelDB is a key-value store developed by Google. It stores data in two file types:

- **`.ldb` / `.sst` files** — Sorted String Tables (SSTables). Immutable on-disk blocks of key-value pairs, organized in a B-tree-like layered compaction structure. Even after a key is logically deleted, its data may persist in older SSTable levels until a compaction run.
- **`.log` / `MANIFEST` files** — Write-Ahead Log (WAL). Uncommitted writes exist here in a sequential binary format before being flushed to SSTables.

**Forensic implication:** Deleted or evicted data from JavaScript's perspective may still physically exist in older SSTable files. This is the primary mechanism that allows recovery of "deleted" conversations.

### 2.3 V8 Binary Serialization

Chromium's JavaScript engine (V8) serializes JavaScript objects into a compact binary format when writing to IndexedDB. Key characteristics:

- Strings are stored as UTF-8 byte sequences interspersed with control bytes (length prefixes, type tags)
- Object boundaries are marked by V8-specific tag bytes (e.g., `0xFF` version marker, `0x6F` for object begin)
- Arrays and nested objects use recursive encoding

**Extraction challenge:** These blobs cannot be parsed with a simple JSON decoder. They require **V8 deserialization** or heuristic text scanning across printable character runs.

### 2.4 Chromium HTTP Cache Format

Chromium uses a **Simple Cache** format for its HTTP disk cache:

- `data_0` — cache index (entry metadata: URL, timestamps, flags)
- `data_1`, `data_2`, `data_3` — cache data (response headers + body)
- `f_XXXXXX` — individual cache entry files (used when entries are too large for data blocks)

Each cache entry file contains a 64-byte entry header followed by the compressed response body. Compression used: **Brotli** (primary), **Gzip**, or raw.

---

## 3. Storage Architecture of LLM Desktop Apps

### 3.1 ChatGPT Desktop (Windows Store / MSIX Package)

ChatGPT Desktop is distributed via the Microsoft Store as an MSIX package. Its package identity string follows the pattern:

```
OpenAI.ChatGPT-Desktop_<version>_<arch>__<publisherid>
```

All user data is isolated in the package's virtual file system under:

```
%LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\
```

**Key subdirectories discovered and their forensic relevance:**

```
ChatGPT/
├── IndexedDB/
│   ├── https_chatgpt.com_0.indexeddb.leveldb/   ← conversation metadata (IDB LDB)
│   │   ├── *.ldb                                 ← SSTable files (may contain deleted data)
│   │   ├── *.log                                 ← WAL (live uncommitted writes)
│   │   └── MANIFEST-*                            ← compaction manifest
│   └── https_chatgpt.com_0.indexeddb.blob/       ← message body blobs (V8)
│       └── 1/                                    ← blob files numbered by entry ID
│           ├── 1, 2, 3, ...                      ← raw V8-serialized message text
├── Local Storage/
│   └── leveldb/                                  ← conversation list with titles + UUIDs
│       ├── *.ldb
│       └── *.log
└── Cache/
    └── Cache_Data/                               ← Chromium HTTP cache
        ├── data_0 (index)
        ├── data_1, data_2, data_3 (blocks)
        └── f_* (individual large entries)
```

### 3.2 Claude Desktop (Windows)

Claude Desktop is distributed as a standard Windows installer (not MSIX). Its data resides at:

```
%APPDATA%\Claude\
%LOCALAPPDATA%\Claude\
%APPDATA%\Anthropic\Claude\
```

**Key subdirectories:**

```
Claude/
├── Cache/
│   └── Cache_Data/                ← HTTP cache (same Chromium format)
│       ├── data_1, data_2, data_3
│       └── f_XXXXXX
├── Local Storage/
│   └── leveldb/                   ← conversations metadata
└── IndexedDB/                     ← structure similar to ChatGPT
```

The key difference from ChatGPT: Claude's conversation data tends to be more fully present in the HTTP cache as Claude uses a REST-style API with clean JSON responses from `api.claude.ai`, whereas ChatGPT uses a streaming format that is harder to reassemble.

---

## 4. ChatGPT Data Extraction Pipeline

Implemented in `chatgpt_extractor.py`. The pipeline has 3 stages.

### Stage 1A: IndexedDB LevelDB Scanning (`scan_ldb`)

**Goal:** Extract conversation UUIDs, titles, and timestamps from the IDB LevelDB files.

**Method:**
1. All `.ldb` and `.log` files in the IDB directory are copied to a temp location (to avoid Windows file-lock conflicts with the running app).
2. Each file is read as a raw byte buffer.
3. A **carving algorithm** (`_carve_ldb_buffer`) scans for the pattern `id"$<uuid>` which marks the start of a conversation anchor key in the LevelDB serialization.
4. From each anchor, the surrounding block (±4 KB) is scanned for:
   - `title":"` → conversation title (UTF-8 string)
   - IEEE-754 8-byte double values → `updateTime` timestamps
   - `account_user_id` → user identifier
5. Timestamps are decoded from raw bytes using `struct.unpack('<d', raw8)` — a little-endian IEEE-754 double representing Unix epoch seconds.

**Why raw carving?** LevelDB's block format interleaves key-value pairs without a clean delimiter. The Chromium LevelDB wrapper uses a custom serialization format where JavaScript objects are encoded as V8 blobs. Rather than implementing a full V8 deserializer, a printable-character carving approach is used — bridging printable segments separated by ≤6 control bytes to reconstruct field values.

### Stage 1B: Local Storage LevelDB Scanning

The Local Storage LDB contains a `conversation-history` key that holds an array of conversation summaries as a JSON-encoded string. This provides:
- Per-conversation ISO 8601 `update_time` strings (accurate to millisecond)
- Titles
- UUIDs

These are used to **correct timestamps** obtained from Stage 1A, which may have batch-level granularity (all conversations from one session share the same cache time).

**Key function:** `_ls_conversation_history(ls_dir)` — scans all LDB files in the LS directory, carves `conversations_v2` or `conversation-history` JSON blobs, and parses them.

### Stage 1C: IndexedDB Blob Files (`scan_idb_blob`)

**Goal:** Extract actual message text (the most valuable artifact).

**Background:** When IndexedDB stores a large JavaScript object (e.g., a full conversation with many messages), Chromium writes the value as a binary file in the `.blob` directory rather than embedding it in the LDB file. These files contain V8-serialized JavaScript objects.

**Method:**
1. All numeric-named files in `https_chatgpt.com_0.indexeddb.blob/1/` are read.
2. `_extract_v8_text(raw)` is applied — this scans for contiguous runs of printable characters (≥4 bytes), then bridges adjacent runs separated by ≤6 binary bytes. This reconstructs V8 string fields that were split by length prefixes and type tags.
3. Each text segment is filtered through `_is_useful_text()` to discard:
   - Metadata keys (`accountUserId`, `current_node`, etc.)
   - Base64 blobs (>40 chars matching `[A-Za-z0-9+/=]+`)
   - TLS certificates (`-----BEGIN CERTIFICATE`)
   - Bare URLs (no spaces in first 60 chars)
   - Short JSON key fragments
4. Surviving segments are grouped by blob file into conversation-like bundles.

### Stage 2: HTTP Cache Scanning (`scan_cache`)

**Goal:** Find complete conversation JSON objects in Chromium cache files.

**Method:**
1. All `data_1`, `data_2`, `data_3`, and `f_*` files are scanned.
2. Each file is decompressed with Brotli → Gzip → raw fallback.
3. The decompressed text is searched for ChatGPT API response patterns:
   - `/api/auth/session` → user account info
   - `conversation` key containing `mapping` → full conversation tree
4. Two API formats are handled:
   - **Mapping format** (`_parse_mapping_api`): `mapping[message_id].message.content.parts[]` — the primary ChatGPT web API format post-2023.
   - **Messages format** (`_parse_messages_api`): simpler array format used in some API versions.
5. Each message's `author.role` (`user` / `assistant` / `tool`), `content.parts[]` (array of text strings), and `create_time` (float Unix epoch) are extracted.

### Stage 3: Reconstruction (`reconstruct`)

**Goal:** Merge Stage 1 (metadata) and Stage 2 (full content) into unified conversation objects.

**Method:**
- Conversations keyed by `conversation_id` (UUID).
- Stage 1 provides: UUID, title, timestamp.
- Stage 2 provides: full message list with roles and text.
- `_merge_into()` merges message lists, deduplicating by snippet MD5 hash.
- Final sort: conversations by `update_time` descending; messages by `create_time` ascending.

---

## 5. Claude Data Extraction Pipeline

Implemented in `claude_extractor.py`. Simpler than ChatGPT because Claude's API returns clean JSON rather than a streaming format.

### Cache Scanning

**Method:**
1. `data_1`, `data_2`, `data_3`, and `f_*` files in Claude's Cache_Data are scanned.
2. Decompression cascade: ZSTD → Gzip → Brotli → raw.
3. Only files containing at least one of `"messages"`, `"chat_messages"`, `"uuid"`, `"updated_at"` are processed (early exit filter reduces noise).
4. `_find_json_objects(text)` locates all top-level balanced JSON objects using a depth-tracking brace counter.
5. Each JSON object is passed to `_parse_claude_object()`:
   - Must contain `messages` or `chat_messages` (array of ≥1 items).
   - Extracts: `uuid`/`conversation_id`, `name`/`title`, `updated_at`/`update_time`.
   - For each message: `content`/`text` field, `role`/`sender`, `created_at`/`timestamp`, `uuid`/`id`.
   - Content can be a plain string or an array of blocks (`{"text": "..."}` objects).
6. Noise filter (`_is_noise`): rejects text < 30 chars, URLs, HTML, certificates, base64 blobs.

### Deduplication and Merge (`_merge`)

- Conversations keyed by UUID or title prefix.
- Newer `update_time` wins for metadata.
- Messages deduplicated by MD5 of snippet text.
- Final sort: conversations newest-first; messages oldest-first within each conversation.

### RECOVERED_CLAUDE_HISTORY.json Integration

Since Claude's live cache tends to be small (only the most recent conversations remain in cache), the tool integrates data from `RECOVERED_CLAUDE_HISTORY.json` — a file built by earlier pipeline iterations that scanned LevelDB SSTable files and older cache formats.

**Key integration logic in `run_claude()`:**
1. Live cache extraction runs first.
2. `RECOVERED_CLAUDE_HISTORY.json` is loaded if present.
3. All items are merged — including **metadata-only entries** (conversations whose content was not recovered, but whose UUID, title, and timestamp were).
4. For metadata-only entries (identified by `[No cached content]` prefix in snippet), the ISO timestamp is parsed from the snippet string using regex: `(?:updated|created)=(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)`.
5. The `source_file` field is removed (not forensically relevant in the final report).
6. Final snippet for metadata-only: `"[No content recovered — metadata only]"`.

---

## 6. Data Recovery Strategy

### 6.1 Why Historical Files Exist

During early development, the pipeline was run many times against different LDB files and cache snapshots at different points in time. Each run produced a `RECOVERED_*.json` file containing conversations found at that moment. Over multiple sessions, this accumulated a larger dataset than any single live scan.

**Key insight:** The more SSTable compaction cycles have occurred, the fewer old records remain in current LDB files. By preserving results from earlier scans before compaction, the historical files contain conversations that are no longer physically present in the current LDB state.

### 6.2 Merge Priority

The final merge strategy in `run_chatgpt()`:

```
Priority: live_scan > LS_timestamps > historical_file
```

- **Live scan** (chatgpt_extractor.run()) always runs first — most up-to-date.
- **LS timestamps** correct any batch-assigned timestamps with accurate per-conversation ISO times.
- **Historical file** adds conversations discovered in previous sessions but no longer in current LDB.

### 6.3 Timestamp Accuracy

A key forensic issue discovered: the older pipeline assigned **batch timestamps** — when many conversations were parsed from the same LDB block (which had a single block-level timestamp), all received the same timestamp even if they were created days apart.

**Fix:** Local Storage's `conversation-history` key contains per-conversation `updatedAt` ISO timestamps (accurate to millisecond). These are used to override the batch timestamps.

**Guard condition:** Timestamps > `1,773,901,000` (a specific future-batch threshold discovered empirically) are treated as unreliable batch artifacts and are not overwritten with — unless they came from the LS scan.

---

## 7. Unified Entry Point — run.py Architecture

### 7.1 Design Philosophy

`run.py` is designed as a **single-file orchestrator** — all orchestration logic (menu, path detection, pipeline invocation, report writing) lives here. This makes the tool:
- Easy to audit
- Portable (copy 5 files to any machine)
- Understandable without a complex module dependency graph

### 7.2 Path Discovery

**ChatGPT (`discover_chatgpt_paths`):**
```python
glob.glob(os.path.join(LOCALAPPDATA, "Packages", "OpenAI.ChatGPT-Desktop_*",
          "LocalCache", "Roaming", "ChatGPT"))
```
Uses a wildcard to match any package version. Returns a dict with keys:
`app_root`, `idb_ldb`, `idb_blob`, `ls_ldb`, `cache`

**Claude (`discover_claude_paths`):**
Tries three fallback locations in order:
1. `%APPDATA%\Claude`
2. `%LOCALAPPDATA%\Claude`
3. `%APPDATA%\Anthropic\Claude`

Returns: `app_root`, `cache`, `ls_ldb`, `idb_ldb`

### 7.3 Directory Scanning and Reporting

After path discovery, `_scan_dirs(paths)` walks each directory and reports:
```
[✓ FOUND] idb_ldb: C:\...\leveldb  (7 files)
[✗ MISSING] ls_ldb: C:\...\...
```
This gives the forensic examiner immediate visibility into which data sources are available.

### 7.4 Main Menu Loop

```python
while True:
    choice = input(MENU).strip()
    if choice == "1":
        paths = discover_chatgpt_paths()
        run_chatgpt(paths)
    elif choice == "2":
        paths = discover_claude_paths()
        run_claude(paths)
    elif choice.lower() == "q":
        break
```

The examiner can run both pipelines in sequence without restarting the tool.

### 7.5 Report Writer (`_write_report`)

Outputs two files to `reports/`:

**JSON report** (`CHATGPT_FORENSIC_REPORT.json`):
```json
{
  "_forensic_notes": "DIGITAL FORENSIC INTEGRITY STATEMENT: ...",
  "app": "CHATGPT",
  "total_conversations": 659,
  "total_messages": 762,
  "messages_with_content": 511,
  "extraction_time_ist": "2026-03-19 10:35:30 IST",
  "items": [ ... ]
}
```

**Markdown report** (`CHATGPT_FORENSIC_REPORT.md`):
- Human-readable
- Summary statistics header
- Each conversation grouped with all messages
- IST timestamps
- Role labels (user / assistant / tool)

---

## 8. Snippet Quality Filtering

### 8.1 The `is_real()` Function

Both pipelines use a shared quality gate to determine whether a recovered text string is genuine conversation content vs. technical noise. Implemented as `is_real(s: str) -> bool` in `run.py`.

**Filtering criteria:**

| Check | Rationale |
|---|---|
| Length < 8 chars | Too short to be meaningful |
| Starts with `[No cached content]` | Placeholder from cache index |
| Contains `JSON.parse`, `api.openai.com` | Internal API noise |
| Starts with `<html`, `<!DOCTYPE` | HTML response noise |
| Matches `[A-Za-z0-9+/=]{40,}` | Base64 blob |
| Starts with `-----BEGIN` | TLS certificate |
| `id"$` or `"conversation_id"` in text | LevelDB metadata key |
| `fileciteturn` in text | ChatGPT internal citation marker |
| `updated=20` without other text | Bare timestamp placeholder |
| Alpha character ratio < 30% | Not natural language |
| Contains `<meta ` or `<link ` | HTML head content |

### 8.2 Metadata-Only Entries

When a conversation is known to exist (from UUID/title in LDB) but no message content was recovered, it is marked as:
```json
{
  "payload": {
    "snippet": "[No content recovered — metadata only]"
  }
}
```
This preserves forensic completeness — the conversation's existence is documented even when its content is unrecoverable. These entries appear in the report with accurate timestamps parsed from whatever sources were available.

---

## 9. Output Schema Design

### 9.1 Unified Schema (matches RECOVERED_CLAUDE_HISTORY.json format)

The output schema was standardized to match Claude's natural API response format, providing consistency across both ChatGPT and Claude reports:

```json
{
  "conversation_id": "<UUID>",
  "current_node_id": "<message UUID or blank>",
  "title": "Snow Moon Meaning",
  "model": "",
  "is_archived": false,
  "is_starred": false,
  "update_time": 1773901654.881,
  "payload": {
    "kind": "message",
    "message_id": "<UUID or blank>",
    "snippet": "<actual message text, up to 4000 chars>",
    "role": "user | assistant | tool | (blank)"
  }
}
```

**Design decisions:**
- One JSON object per **message** (not per conversation). This allows forensic tools and analysts to search individual messages without parsing nested arrays.
- `conversation_id` is repeated across all messages of the same conversation — enabling GROUP BY queries.
- `update_time` is the conversation's latest update timestamp (Unix epoch float), not the individual message timestamp.
- `snippet` is capped at 4000 characters to control report size while preserving forensic utility.
- `source_file` was deliberately removed from the final report to keep schema clean and prevent confusion with internal implementation details.

---

## 10. Portability and Forensic Considerations

### 10.1 File Copy Before Reading

A critical detail: Windows locks LevelDB and cache files when the LLM application is running. Direct reads fail with `PermissionError`. The tool uses `_safe_read()`:

```python
def _safe_read(path: str) -> bytes:
    tmp = path + f"._r{os.getpid()}"
    shutil.copy2(path, tmp)       # shadow copy bypasses file lock
    with open(tmp, "rb") as f:
        data = f.read()
    os.remove(tmp)
    return data
```

This shadow-copy technique is forensically important: it avoids modifying the original file's access time while still reading locked files.

### 10.2 Making the Tool Machine-Independent

The tool was redesigned to not depend on pre-existing `RECOVERED_*.json` files. The pipeline order:

1. **Live scan** (IDB LDB → Blob → Cache) — works on any machine with the app installed.
2. **Optional historical merge** — if `RECOVERED_CHATGPT_GROUPED.json` exists, it provides additional conversations from earlier scans.

This means:
- On a fresh machine → live-only mode, recovers whatever is in the current LDB/Cache.
- On the investigator's machine → historical + live, maximum recovery.

### 10.3 Portability Requirements

To run the tool on any Windows machine:
```
run.py               ← main entry point
chatgpt_extractor.py ← ChatGPT LDB/Blob/Cache scanner
claude_extractor.py  ← Claude cache scanner
merge_max_chatgpt.py ← ChatGPT merge helper
output_writer.py     ← report formatter
```
Required Python packages: `cramjam` (optional, for Snappy), `brotli`, standard library only otherwise.

---

## 11. Results and Validation

### 11.1 ChatGPT Recovery Results

| Source | Conversations | Messages |
|---|---|---|
| Live IDB LDB + Blob scan | ~11–49 | varies |
| Live HTTP Cache | 3–10 | varies |
| Historical merge (RECOVERED_CHATGPT_GROUPED.json) | +617 | varies |
| **Final merged output** | **~659** | **~511 with real content** |

### 11.2 Claude Recovery Results

| Source | Items |
|---|---|
| Live cache extraction | 0 (cache frequently evicted) |
| RECOVERED_CLAUDE_HISTORY.json | 23 total |
| — Real content | 10 |
| — Metadata only | 13 |
| **Final merged output** | **15 unique conversations** |

Note: Claude's lower count reflects that Claude Desktop caches responses more aggressively with shorter TTLs than ChatGPT, and the LevelDB extraction for Claude yielded metadata without full message bodies.

### 11.3 Timestamp Accuracy

Before fix: Many conversations showed the same timestamp (batch artifact from old pipeline).  
After fix: Per-conversation ISO timestamps from Local Storage `conversation-history` key applied.

---

## 12. Limitations and Future Work

### 12.1 Current Limitations

1. **LevelDB compaction**: Once LevelDB compacts older SSTable files, deleted records are permanently gone. The tool cannot recover data that has been fully compacted away.
2. **Claude live extraction**: Claude's HTTP cache has a short TTL. Only the most recent conversations appear in live cache; older ones require SSTable carving.
3. **V8 deserialization**: The tool uses heuristic text carving rather than full V8 deserialization. Some message boundaries may be missed or incorrectly joined.
4. **Streaming responses**: ChatGPT uses Server-Sent Events (SSE) for streaming responses. The cache may not contain complete messages if the SSE stream was interrupted.
5. **Encrypted profiles**: If Windows DPAPI encryption is enabled for the app profile, LDB files may be encrypted and inaccessible without the user's credentials.

### 12.2 Future Work

1. **Full V8 deserializer**: Implement proper V8 SerializedData parsing to accurately extract object boundaries from blob files.
2. **LevelDB `memtable` scanning**: Add support for reading the in-memory table from `.log` WAL files using LevelDB's block format specification.
3. **DPAPI decryption support**: Integrate Windows DPAPI (`win32crypt`) to handle encrypted profiles.
4. **SQLite support**: Some newer Electron apps are moving to SQLite for IndexedDB. Extend the tool to handle this format.
5. **Gemini and Copilot support**: Apply the same methodology to Google Gemini Desktop and Microsoft Copilot desktop apps, which use similar Chromium-based storage.
6. **Timeline reconstruction**: Generate a chronological timeline of all LLM interactions across both apps, suitable for court presentation.
7. **Hash verification**: Add MD5/SHA-256 hashing of all source files at extraction time to support chain-of-custody documentation.

---

## Appendix A: Key File Paths Reference

### ChatGPT Desktop (Windows)
```
%LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\
├── IndexedDB\https_chatgpt.com_0.indexeddb.leveldb\     ← conversation metadata
├── IndexedDB\https_chatgpt.com_0.indexeddb.blob\1\      ← message bodies (V8)
├── Local Storage\leveldb\                               ← conversation list
└── Cache\Cache_Data\                                    ← HTTP cache (API responses)
```

### Claude Desktop (Windows)
```
%APPDATA%\Claude\
├── Cache\Cache_Data\          ← HTTP cache (conversation JSON)
├── Local Storage\leveldb\     ← session metadata
└── IndexedDB\                 ← structured storage
```

---

## Appendix B: Tool File Structure

```
project/
├── run.py                  ← Unified entry point. Run: python run.py
│                             - App selection menu
│                             - Path discovery and directory scanning
│                             - Pipeline orchestration
│                             - Report generation (JSON + Markdown)
│
├── chatgpt_extractor.py    ← ChatGPT forensic extractor
│                             - Stage 1: IDB LDB carving (UUIDs, titles, timestamps)
│                             - Stage 1b: Blob file V8 text extraction
│                             - Stage 2: HTTP cache JSON parsing
│                             - Stage 3: Reconstruction and deduplication
│
├── claude_extractor.py     ← Claude forensic extractor
│                             - Strict JSON-only cache scanning
│                             - Multi-format decompression (ZSTD/GZIP/Brotli)
│                             - Conversation deduplication
│
├── merge_max_chatgpt.py    ← Merge helper for ChatGPT historical data
│
├── output_writer.py        ← Report formatter (used internally)
│
└── reports/
    ├── CHATGPT_FORENSIC_REPORT.json   ← Primary output (machine-readable)
    ├── CHATGPT_FORENSIC_REPORT.md     ← Human-readable report
    ├── CLAUDE_FORENSIC_REPORT.json
    ├── CLAUDE_FORENSIC_REPORT.md
    └── RECOVERED_*.json               ← Optional historical data (portable bonus)
```

---

## Appendix C: Running the Tool

```bash
# On any Windows machine with Python 3.11+ and ChatGPT/Claude Desktop installed:
python run.py

# Output:
# ════════════════════════════════════
#   LLM Artifact Forensic Tool
# ════════════════════════════════════
#   1. ChatGPT
#   2. Claude
#   Q. Quit
# > _
```

The tool automatically:
1. Detects the application data directory
2. Reports which data sources (LDB, Blob, Cache) are present
3. Runs the full extraction pipeline
4. Saves reports to `reports/` in the same directory as `run.py`

---

*End of Technical Notes*  
*Document generated: 2026-03-19*
