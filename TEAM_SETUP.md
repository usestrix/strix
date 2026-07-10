# Team Setup

Notes for teammates working on this Strix fork.

## HackerOne intelligence tool (`hackerone_intel`)

The root agent has a `hackerone_intel` tool that consults a local HackerOne
knowledge base (12,340 disclosed reports + distilled playbooks, tech/feature
intel, chains, and a ranked hunt planner) for report-grounded intel before
hunting. It shells out, read-only, to `bin/h1_query.py` inside that KB.

### `H1_KB_HOME`

The tool locates the KB via the `H1_KB_HOME` environment variable:

- **Default (unset):** `~/.claude/skills/hackerone-kb`
- The tool expects `${H1_KB_HOME}/db/h1_kb.sqlite` and
  `${H1_KB_HOME}/bin/h1_query.py` to exist.

Set it only if your KB lives elsewhere, e.g.:

```bash
export H1_KB_HOME=/path/to/hackerone-kb
```

### No KB? No problem — it degrades gracefully

The ~104 MB KB database is **not** bundled in this repo. Teammates who don't
have their own `hackerone-kb` data will simply get:

```json
{"success": false, "error": "HackerOne KB not configured at H1_KB_HOME"}
```

returned from the tool at call time. **This is not a crash** — the tool checks
for the DB on every call and returns that structured result if it's missing, so
scans run fine without the KB (the root agent just won't have report-grounded
intel available). Nothing else in Strix is affected.

If you want the intel, obtain/point `H1_KB_HOME` at a `hackerone-kb` install
that provides `db/h1_kb.sqlite` and `bin/h1_query.py`.
