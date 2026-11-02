# REC-MCP: Relational Effect Contracts for MCP tool execution

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23875455.svg)](https://doi.org/10.5281/zenodo.23875455)

Replication package for:

> Sugiantoro, B., Hafizuddin, F.A. *Relational Effect Contracts for Securing MCP Tool Execution.* Manuscript under review.

The package contains the static analyzer, the audit and enforcement broker, the benchmarks for every research question, the frozen corpus manifest, the tool-level labels and all raw and summary results reported in the paper.

## Layout

| Path | Contents | Paper section |
|---|---|---|
| `analyzer/rec_analyzer.py` | AST analyzer (v3): tool detection, sensitive-site catalogue, import-graph helper resolution, relation inference (`arg`, `cfg`, `const`, `join`, `under`, `stored(d)`, `union`, `derive`, ⊥) | §4, RQ1 |
| `analyzer/rec_analyzer_v1.py` | First version, kept for the ablation in §6 | §6 |
| `broker/effect_broker.py` | In-process enforcement broker and the compared policies (NoDefense, ToolAllowlist, ArgPolicy, SandboxScope, RECPolicy, Intersect) | §5, RQ2 |
| `broker/audit_shim.py`, `broker/run_tool.py`, `broker/dynamic.py` | Audit-mode interposition and the dynamic run used to cross-check static results | RQ1 |
| `broker/stubs/` | Minimal `mcp` / `fastmcp` stubs so tools can be imported without network access | RQ1 |
| `bench/rq2_bench.py` | Eight attack cases × nine defense configurations | RQ2 |
| `bench/rq4_overhead.py` | Per-call overhead micro-benchmark | RQ3 |
| `tests/` | Fixture servers with known answers | §4 |
| `data/corpus/`, `py_local.json` | Sampled candidates, the Python/local filter of the source list, `corpus_manifest.csv` (repository URL and frozen commit for every clone) | §6.1 |
| `data/lists/awesome/` | Snapshot of the source list (`punkpeye/awesome-mcp-servers`, commit `f225f117f926`) | §6.1 |
| `annotation/` | Labelling guideline (Indonesian); the summary in English is Appendix B of the paper | §6.2 |
| `results/` | Raw and summary output of every run (`expanded_*_v3.json` = final RQ1 numbers; `rq0_rq1_labels.json`; `dynamic_*.json`; `rq2_results.json`; `rq4_overhead.json`) | §7 |
| `scripts/` | Corpus sampling, expansion, re-run and form-generation scripts | §6 |

## Requirements

- Linux with user namespaces (`unshare -Urn`) for the sandbox baseline
- Python ≥ 3.10, standard library only for the analyzer
- The broker's dynamic run needs `httpx==0.28.1`, `httpcore==1.0.9`, `h11==0.16.0`, `certifi`, `idna`, `sniffio==1.3.1`, `aiofiles`. Install them into `broker/vendor/`:

```
pip install --target broker/vendor -r requirements-broker.txt
```

## Reproduce

```
# 0. sanity check on the fixture (expects 6 tools, 7 sites)
python3 analyzer/rec_analyzer.py tests/fixture fx

# 1. clone the corpus at the frozen commits
python3 scripts/clone_corpus.py data/corpus/corpus_manifest.csv corpus/

# 2. RQ0/RQ1: static analysis over the included repositories
python3 scripts/rerun_included.py results/expanded_raw_v3.json   # run from the repository root

# 3. RQ1: dynamic cross-check
python3 broker/dynamic.py results/expanded_raw_v3.json corpus/ results/dynamic_a.json

# 4. RQ2: enforcement benchmark
python3 bench/rq2_bench.py                   # writes results/rq2_results.json

# 5. RQ3: overhead
python3 bench/rq4_overhead.py                # writes results/rq4_overhead.json
```

Corpus sampling uses seed `20261102` (`scripts/expand_corpus.py`); the labelled tool sample uses seed `20261103` (`scripts/make_annotation_forms.py`). Numbers in the paper are computed from the JSON files in `results/`.

## What is not included

- Clones of third-party repositories (re-create them from `corpus_manifest.csv`).
- Third-party libraries vendored for the offline run (install them as above).
- Per-annotator working files and the researcher answer key used during calibration. The consolidated labels are in `results/labels_parsed.json` and `results/rq0_rq1_labels.json`.

## Licence

Code: MIT (see `LICENSE`). Data and results: CC BY 4.0. Third-party repositories keep their own licences; the list snapshot keeps its original licence (`data/lists/awesome/LICENSE`).

## Citation

See `CITATION.cff`. Archived release v1.0.0: https://doi.org/10.5281/zenodo.23875455

## Contact

Bambang Sugiantoro, Informatics Department, UIN Sunan Kalijaga, Yogyakarta, Indonesia — bambang.sugiantoro@uin-suka.ac.id
