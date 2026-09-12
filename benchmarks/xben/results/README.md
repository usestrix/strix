# Example / fixture results

The five `*.json` files in this directory are **synthetic fixture data**, not
real Strix run results. They exist to:

- validate against `benchmarks/xben/schema/run_record.schema.json`, and
- give `benchmarks/xben/score.py` something to aggregate end-to-end, so the
  scoring and `--check` machinery can be exercised and unit-tested without a
  live Docker + LLM-key environment (which this harness was built without
  access to).

They are deliberately small (5 challenges) and deliberately do **not**
reproduce the headline "96% (100/104)" claim in `benchmarks/README.md` — do
not treat them as, or cite them as, real benchmark results. Running:

```bash
python3 benchmarks/xben/score.py benchmarks/xben/results/ --check
```

against these fixtures and the real `benchmarks/README.md` is expected to
**fail** (`--check` exits non-zero) — that failure is correct and intentional.
It demonstrates the actual guarantee this harness provides: the current
"96%" claim is not (yet) backed by data reproducible from this repository,
which is exactly the gap GitHub issues
[#1263](https://github.com/usestrix/strix/issues/1263) and
[#1264](https://github.com/usestrix/strix/issues/1264) ask to close.

## Replacing these with real results

When real XBEN runs are produced (via `benchmarks/xben/run.py` or manually),
commit their run-record JSON files here — named e.g.
`<challenge_id>.<model>.json` — and delete or replace these fixtures. Once
enough real runs are committed, `score.py --check` should pass against
`benchmarks/README.md`, or `benchmarks/README.md`'s table should be
regenerated from `score.py`'s output to match reality.
