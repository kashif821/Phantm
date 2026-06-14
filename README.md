# 👻 Phantm

**A cost-optimized, 3-tier AI security scanner prototype.**

## ⚡ The Problem
Sending entire repositories to LLMs for security analysis is slow, exposes proprietary code unnecessarily, and results in massive token costs. Most of the scanned code is boilerplate or inherently safe. Phantm solves this by pre-filtering code locally and only sending suspicious blocks to the LLM.

---

## 🏗️ The 3-Tier Architecture

Phantm uses a surgical approach to code auditing, drastically reducing token usage and execution time:

### 🛡️ Tier 1: AST Slicing (Pre-Filter)
Before any external API is hit, Phantm utilizes Python's built-in `ast` module to statically slice files locally. It filters out safe code and extracts only the specific function or class blocks containing risky sinks and calls (e.g., `os.system`, `subprocess`, `requests`, `litellm`).

### 🧠 Tier 2: Threat Intel Caching
Phantm extracts hardcoded IPs and URLs from the Tier 1 AST blocks using advanced regex. These artifacts are checked against a local SQLite TTL cache. On a cache miss, Phantm queries external providers like **VirusTotal** or **AbuseIPDB** and caches the result.

### 🤖 Tier 3: Targeted LLM Dispatch
The isolated AST blocks, combined with any Threat Intel context, are routed through a Universal LLM Router (LiteLLM). This minimal payload ensures a drastically reduced context window, saving costs while delivering targeted analysis.

---

## 🔐 Current Security Model & Hardening

Security tools must be built securely. Key hardening features include:

* **Robust Testing:** A comprehensive 54-test suite that includes adversarial prompt injection and rigorous path handling checks.
* **Strict Permissions & Masking:** Enforces strict `0o600` permissions on the local database (`~/.phantm/phantm.db`) to prevent OS umask leaks, along with zero-knowledge secret masking.
* **Directory Escape Prevention:** Symlinks are strictly rejected *before* path resolution to prevent symlink hijacking and directory escapes.

---

## ⚠️ Current Maturity & Known Gaps (v1.0.0)

Phantm is a prototype. We believe in brutal transparency regarding its limitations:

* Phantm relies heavily on a hardcoded allowlist of risky AST nodes. It does not perform deep taint-analysis.
* The LLM trust boundary relies on JSON extraction heuristics. Sophisticated prompt injection within the audited code could theoretically bypass the parser.
* Path jailing relies on local convention rather than a rigorous OS-level sandbox.

---

## 🚀 Usage & Configuration

### Installation
```bash
pip install -e .
```

### Configuration
```bash
phantm config set CEREBRAS_API_KEY <key>
```

### Scanning
```bash
phantm scan run src/
```

### Reporting
```bash
phantm report
```

---

## 🚦 Exit Codes

Phantm is built for automated pipelines and returns standard exit codes:

* `0` : Clean scan (No vulnerabilities found)
* `1` : Vulnerabilities found
* `2` : Configuration or Authentication error
* `3` : Major network/API failure
* `4` : Engine crash / Internal error

---

**Made by Kashif Khan.**
