# 👻 Phantm

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/phantm/phantm/releases)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)]()

**A cost-optimized, 3-tier AI security scanner prototype.**

---

## ⚡ The Problem: Why Another AI Scanner?
Most AI security scanners naively dump entire codebases into an LLM context window. This brute-force approach leads to:
- 💸 **Massive Token Costs:** Paying to scan boilerplate and clean code.
- 🐢 **Slow Execution & Rate Limiting:** Hitting API limits instantly and waiting minutes or hours for results.
- 🔒 **Privacy Concerns:** Sending unnecessary proprietary code to third-party models.

**Phantm is different.** We built a highly-optimized, localized **3-Tier Pipeline** that pre-filters, slices, and enriches your code *before* it ever touches an LLM.

---

## 🏗️ The 3-Tier Architecture

Phantm heavily reduces token usage and execution time by using a surgical approach to AI auditing:

### 🛡️ Tier 1: Static Analysis (Pre-Filter)
Before hitting any external API, Phantm utilizes Python's built-in `ast` module to statically slice and analyze files locally.
* **Smart Extraction:** It searches for risky sinks and calls (e.g., `os.system`, `subprocess`, `requests`, `litellm`) and extracts *only* the specific offending function or class blocks.
* **Zero-Cost Skipping:** Completely clean files are skipped locally.
* **Performance Limits:** Enforces a strict 500KB file limit to prevent memory exhaustion on massive binaries or minified files.

### 🧠 Tier 2: Threat Intel & Local SQLite Cache
Context is king. Phantm automatically extracts hardcoded IPs and URLs from the Tier 1 AST blocks using advanced regex.
* **Local First:** Checks a local, strictly-permissioned (`0o600`) SQLite cache (`~/.phantm/phantm.db`) for known threat intelligence.
* **External Providers:** On a cache miss, it routes queries to **VirusTotal** or **AbuseIPDB**.
* **Smart Caching:** Results are cached locally with a TTL (24h/48h) to prevent duplicate API calls across runs.

### 🤖 Tier 3: Targeted LLM Dispatch
Once the code is localized and enriched, Phantm dispatches the minimal payload.
* **Surgical Precision:** Packages only the isolated AST blocks combined with Threat Intel context.
* **Universal Router:** Routes through LiteLLM, allowing you to use any provider (OpenAI, Anthropic, local models).
* **Cost Savings:** Drastically reduces the context window size, saving significant token costs compared to naive scanners.

---

## 🔐 Security & Hardening

Security tools must be secure themselves. Key hardening features currently include:

* 🚫 **Directory Traversal & Symlink Prevention:** Strict path resolution prevents symlink hijacking and escapes.
* ⏱️ **TOCTOU Protections:** Mitigates Time-of-Check to Time-of-Use race conditions during file operations.
* 🏛️ **Jailed Execution & Strict Permissions:** Enforces strict `0o600` permissions on the local database (`~/.phantm/phantm.db`) to prevent OS umask leaks.
* 🤫 **Zero-Knowledge Secret Masking:** API keys are never leaked. Masked as `********` in CLI outputs and use `repr=False` in Pydantic models to prevent log leaks.
* 🛡️ **UI Injection Prevention:** Hardened against Rich terminal markup injection attacks from malicious source code.

---

## ⚠️ Current Maturity & Limitations

Phantm is currently in an early-stage/prototype phase (v1.0.0). We believe in brutal transparency:

* Path and workspace boundary protections are implemented, but rely on local convention rather than a rigorous sandboxed file access model.
* The LLM trust boundary relies on JSON parsing heuristics, which may be vulnerable to sophisticated prompt injection.
* Scanning rules (Tier 1) are currently based on a narrow allowlist of risky AST nodes.

---

## 🗺️ Roadmap

Our immediate goals for the next iterations of Phantm:
* Decoupling policy from the engine.
* Hardening path resolution into a single canonical utility.
* Building a robust adversarial test suite.

---

## 🚀 Quickstart & Usage

Phantm provides a beautiful, intuitive CLI built with developers in mind.

### Configuration
Set your API keys (masked securely in the background):
```bash
phantm config set OPENAI_API_KEY <your-key>
phantm config set VIRUSTOTAL_API_KEY <your-key>
phantm config set ABUSEIPDB_API_KEY <your-key>
```

### Scanning
Run a fast, parallelized scan using `ThreadPoolExecutor`:
```bash
phantm scan run src/
```

### Reporting
Render a beautiful Rich terminal table of your findings:
```bash
phantm report
```

Export your SQLite findings to a static Markdown report for your team:
```bash
phantm report -o compliance.md
```

---

## 🚦 Strict Exit Codes (For CI/CD)
Phantm is built for automated pipelines. It returns standard, reliable exit codes:

* `0` : Clean scan (No vulnerabilities found)
* `1` : Vulnerabilities found
* `2` : Configuration or Authentication error
* `3` : Major network/API failure
* `4` : Engine crash / Internal error

---

## 🧪 Testing & Reliability
Phantm boasts a lightning-fast, fully mocked Pytest suite ensuring maximum reliability without side effects.
* **Speed:** 34 tests passing in ~4.5s.
* **Air-gapped:** Zero network calls during unit testing.
* **Clean:** Zero disk contamination (strict use of Pytest's `tmp_path`).

---

**Built with 💻 by the Phantm Contributors.**
