# Graph Report - .  (2026-06-12)

## Corpus Check
- Corpus is ~8,812 words - fits in a single context window. You may not need a graph.

## Summary
- 54 nodes · 48 edges · 14 communities
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 6 edges (avg confidence: 0.82)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Graphify Extraction Pipeline|Graphify Extraction Pipeline]]
- [[_COMMUNITY_Phantm Project Structure|Phantm Project Structure]]
- [[_COMMUNITY_Config Read Layer|Config Read Layer]]
- [[_COMMUNITY_Config Write Layer|Config Write Layer]]
- [[_COMMUNITY_Scan Command Layer|Scan Command Layer]]
- [[_COMMUNITY_Main CLI Entrypoint|Main CLI Entrypoint]]
- [[_COMMUNITY_Graphify Update Hooks|Graphify Update Hooks]]

## God Nodes (most connected - your core abstractions)
1. `Knowledge Graph` - 10 edges
2. `set()` - 4 edges
3. `main()` - 4 edges
4. `Phantm` - 4 edges
5. `show()` - 3 edges
6. `load_config()` - 3 edges
7. `save_config()` - 3 edges
8. `PhantmSettings` - 3 edges
9. `run()` - 3 edges
10. `run_scan()` - 3 edges

## Surprising Connections (you probably didn't know these)
- `Phantm` --conceptually_related_to--> `Graphify Integration`  [INFERRED]
  AGENTS.md → CLAUDE.md
- `Graphify Integration` --references--> `Graphify`  [EXTRACTED]
  CLAUDE.md → .claude/skills/graphify/SKILL.md
- `Incremental Update` --conceptually_related_to--> `Knowledge Graph`  [EXTRACTED]
  .claude/skills/graphify/references/update.md → .claude/skills/graphify/SKILL.md
- `Post-Commit Hook` --semantically_similar_to--> `File Watcher`  [INFERRED] [semantically similar]
  .claude/skills/graphify/references/hooks.md → .claude/skills/graphify/references/add-watch.md
- `CLAUDE.md Integration` --conceptually_related_to--> `Graphify Integration`  [EXTRACTED]
  .claude/skills/graphify/references/hooks.md → CLAUDE.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Graph Building Pipeline** — graphify_skill_astextraction, graphify_skill_semanticextraction, graphify_skill_subagentdispatch, graphify_skill_communitydetection, graphify_skill_godnodes, graphify_skill_knowledgegraph [EXTRACTED 1.00]
- **Graph Query System** — references_query_queryexpansion, references_query_bfstraversal, references_query_dfstraversal, graphify_skill_knowledgegraph [EXTRACTED 1.00]
- **Graph Maintenance** — references_update_incrementalupdate, references_hooks_postcommithook, references_add_watch_filewatcher, references_github_and_merge_crossrepomerge [EXTRACTED 1.00]

## Communities (14 total, 0 thin omitted)

### Community 0 - "Graphify Extraction Pipeline"
Cohesion: 0.18
Nodes (13): AST Extraction, Community Detection, God Nodes, Honesty Rules, Knowledge Graph, Semantic Extraction, Subagent Dispatch, Confidence Score Rubric (+5 more)

### Community 1 - "Phantm Project Structure"
Cohesion: 0.25
Nodes (8): First-Run Init, Package Boundaries, Phantm, Src Layout, Graphify Trigger, Graphify Integration, Graphify, CLAUDE.md Integration

### Community 2 - "Config Read Layer"
Cohesion: 0.33
Nodes (4): BaseSettings, Show current configuration., show(), PhantmSettings

### Community 3 - "Config Write Layer"
Cohesion: 0.47
Nodes (5): Set a configuration value., set(), load_config(), save_config(), Path

### Community 4 - "Scan Command Layer"
Cohesion: 0.33
Nodes (4): Run a security scan on the given path., run(), Execute the scanning logic., run_scan()

### Community 5 - "Main CLI Entrypoint"
Cohesion: 0.50
Nodes (4): Context, _ensure_phantm_dir(), main(), Phantm - Security scanner for LLM-generated code.

### Community 6 - "Graphify Update Hooks"
Cohesion: 0.67
Nodes (3): File Watcher, Post-Commit Hook, Incremental Update

## Knowledge Gaps
- **9 isolated node(s):** `Context`, `God Nodes`, `BFS Traversal`, `DFS Traversal`, `Whisper Transcription` (+4 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Knowledge Graph` connect `Graphify Extraction Pipeline` to `Phantm Project Structure`, `Graphify Update Hooks`?**
  _High betweenness centrality (0.152) - this node is a cross-community bridge._
- **Why does `Graphify` connect `Phantm Project Structure` to `Graphify Extraction Pipeline`?**
  _High betweenness centrality (0.086) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `set()` (e.g. with `load_config()` and `save_config()`) actually correct?**
  _`set()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Show current configuration.`, `Set a configuration value.`, `Context` to the rest of the system?**
  _18 weakly-connected nodes found - possible documentation gaps or missing edges._