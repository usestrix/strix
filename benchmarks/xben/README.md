# XBEN benchmark harness

This directory is an in-repo, reproducible harness for Strix's [XBEN](https://github.com/usestrix/benchmarks/tree/main/XBEN)
results. It exists to close out the intent of two open GitHub issues on
`usestrix/strix`:

- [#1263 — "Make published XBEN metrics reproducible from committed data"](https://github.com/usestrix/strix/issues/1263)
- [#1264 — "Record enough provenance to reproduce XBEN runs"](https://github.com/usestrix/strix/issues/1264)

Previously, `benchmarks/README.md` stated a headline number ("96% (100/104
challenges)") with no runnable evaluation code and no committed per-challenge
data in this repository — only a link to an external repo. That's not
independently checkable, and it's exactly the kind of gap that led to
[Escape.tech's independent benchmark](https://escape.tech/) reporting a very
different detection rate against a different (non-CTF) target: CTF-style
flag-hunting and black-box real-app assessment measure different things, and
"trust us" numbers can't be told apart from either without data to check
them against.

This harness makes the XBEN number **mechanically regenerated from committed
data** instead of hand-typed:

```
per-challenge run record (JSON, committed)  →  score.py  →  markdown table
                                                    │
                                                    └─ --check: fails loudly
                                                       if committed data
                                                       doesn't match the
                                                       README's claim
```

## Layout

| Path | Purpose |
|------|---------|
| `schema/run_record.schema.json` | JSON Schema for one challenge run record. |
| `results/*.json` | Committed run records, one file per challenge run. **Currently fixture/example data only** — see `results/README.md`. |
| `score.py` | Validates every record, aggregates them, prints/writes a markdown results table, and (`--check`) verifies the aggregate matches `benchmarks/README.md`. |
| `run.py` | Runner that drives real `strix` scans against XBEN challenges and emits conformant run records. Needs Docker + a live LLM API key to actually execute. |

## Reproducing a run

1. Check out the challenge set from [usestrix/benchmarks](https://github.com/usestrix/benchmarks/tree/main/XBEN)
   (external — not vendored into this repo).
2. Point `run.py` at it (or at a JSON manifest you write) and pick a model:

   ```bash
   python3 benchmarks/xben/run.py \
     --challenges-dir /path/to/usestrix-benchmarks/XBEN \
     --model anthropic/claude-sonnet-4-5 \
     --mode black-box \
     --out-dir benchmarks/xben/results
   ```

   This shells out to the real `strix` CLI once per challenge (see
   `strix/interface/cli_args.py` for the flags it uses: `--target`,
   `--non-interactive`, `--run-name`, `--max-budget`, `--max-turns`), reads
   the resulting `strix_runs/<run-name>/run.json` for cost/token/timing data,
   checks the challenge's flag against the saved artifacts, and writes one
   schema-conformant run-record JSON per challenge.

   This step needs Docker (Strix's sandbox runtime) and a working API key
   for the chosen model — neither is available in every environment (e.g.
   this harness was built in one without them), so `run.py` also supports
   `--dry-run` to print the commands it would execute without running them,
   and its argument-parsing / record-construction logic is unit tested with
   subprocess calls mocked out (`tests/test_xben_run.py`) rather than against
   a real scan.

3. Commit the resulting `benchmarks/xben/results/*.json` files (delete the
   fixture files in that directory first — see `results/README.md`).

## Scoring

```bash
# Print the regenerated results table to stdout
python3 benchmarks/xben/score.py benchmarks/xben/results/

# Write it to a file instead
python3 benchmarks/xben/score.py benchmarks/xben/results/ --out /tmp/xben_table.md

# Verify the committed data reproduces the claim in benchmarks/README.md
# (this is what CI runs; exits non-zero on any mismatch, naming it)
python3 benchmarks/xben/score.py benchmarks/xben/results/ --check
```

`score.py`:

1. Loads every `*.json` file in the results directory (default
   `benchmarks/xben/results/`).
2. Validates each one against `schema/run_record.schema.json`. An invalid
   record fails loudly, naming the file and the offending field(s) — it does
   not skip bad data silently.
3. Aggregates: overall success rate, a breakdown by difficulty (`easy` /
   `medium` / `hard`, matching the existing README's Level 1/2/3 tiers),
   average solve time, average cost, and total cost.
4. Renders a markdown table in the same shape as the existing
   `benchmarks/README.md` table, so that table can be regenerated
   mechanically rather than hand-typed.
5. With `--check`, parses the numbers currently hand-typed in
   `benchmarks/README.md` (via a small regex over its markdown tables) and
   diffs them against the aggregate, exiting non-zero and printing every
   mismatch if they disagree.

### Why `--check` currently fails

`benchmarks/xben/results/` presently holds only 5 synthetic fixture records
(see `results/README.md`) used to exercise and test this harness — not real
Strix runs. Running `--check` against them and the real `benchmarks/README.md`
**correctly fails**: the committed data does not (yet) reproduce the "96%
(100/104)" claim, because there is no real committed data behind it yet. That
failure is the point — it is the honest, mechanically-verifiable answer to
issues #1263 and #1264 today. Once real run records replace the fixtures
(via `run.py` or a manually graded run), `--check` either passes or tells you
exactly how `benchmarks/README.md` needs to be updated.

## Schema

See `schema/run_record.schema.json` for the authoritative field list. Briefly,
each run record captures: which challenge and difficulty tier, which Strix
version and LLM (`model`) and testing `mode` (black-box/grey-box/white-box)
were used, whether it was `solved` and whether the `flag_matched`, timing
(`duration_seconds`, `started_at`/`finished_at`), cost/token usage
(`total_cost_usd`, `input_tokens`, `output_tokens`), and a `run_id` tying the
record back to the underlying `strix_runs/<run-id>/` artifact directory for
provenance — the specific gap issue #1264 asks to close.
