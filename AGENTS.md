# Agent Guidance

This repo is part of the `pike-ws` workspace. A shared Understand Anything
knowledge graph is available one directory up:

- Graph: `../.understand-anything/knowledge-graph.json`
- Summary: `../.understand-anything/summary.json`

Use that graph before making non-trivial changes. It maps this Rust repo along
with `../pike-cloud`, including the Pike CLI, Pike Core Protocol, Pike Server,
deployment/configuration files, and their relationships.

Recommended workflow:

1. Check `../.understand-anything/summary.json` for the layer overview.
2. Search `../.understand-anything/knowledge-graph.json` for relevant files,
   functions, classes/types, imports, and tour steps before choosing where to
   edit or add code.
3. Keep new Rust code within the existing layer boundaries:
   `pike/crates/pike-core`, `pike/crates/pike-server`, `pike/crates/pike`, and
   repo operations/configuration.
4. After adding modules, moving files, or making broad structural changes,
   refresh the shared graph from the workspace root with
   `$understand-anything:understand`.

The workspace root is not a git repo; this child directory is.
