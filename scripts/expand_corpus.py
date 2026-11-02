"""Expand the corpus by seeded random sampling with explicit inclusion criteria.

Inclusion: (I1) repository clones publicly; (I2) Python MCP tools registered via
@x.tool / x.tool(...)(f) / x.add_tool(f) in shipped code; (I3) at least one
catalogued file or HTTP site reachable from a tool. Every attempt is logged with
the criterion it failed, so the funnel can be reported.
Resumable: re-running continues from the log.
"""
import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, "analyzer")
sys.setrecursionlimit(5000)
from rec_analyzer import analyze_repo  # noqa: E402

TARGET = int(sys.argv[1]) if len(sys.argv) > 1 else 40
BUDGET_S = int(sys.argv[2]) if len(sys.argv) > 2 else 500
SEED = 20261102
LOG = "results/expansion_log.csv"
OUT = "results/expanded_raw.json"

rows = json.load(open("py_local.json"))
uniq = {}
for sec, name, url, *_ in rows:
    m = re.match(r"https://github.com/([^/]+)/([^/#?]+)(?:/tree/[^/]+/(.*))?", url)
    if m:
        uniq.setdefault(f"{m.group(1)}/{m.group(2)}".rstrip("."), (sec, m.group(3)))
order = sorted(uniq)
random.Random(SEED).shuffle(order)

done = {}
if os.path.exists(LOG):
    for r in csv.DictReader(open(LOG)):
        done[r["repo"]] = r
results = json.load(open(OUT)) if os.path.exists(OUT) else []
included = sum(1 for r in done.values() if r["included"] == "1")
start = time.time()
new = open(LOG, "a", newline="")
w = csv.DictWriter(new, fieldnames=["rank", "repo", "category", "commit", "included", "reason", "tools", "sites"])
if not done:
    w.writeheader()
for rank, repo in enumerate(order, 1):
    if included >= TARGET or time.time() - start > BUDGET_S:
        break
    if repo in done:
        continue
    sec, sub = uniq[repo]
    cat = re.search(r'name="([^"]+)"', sec or "")
    cat = cat.group(1) if cat else (sec or "")
    dest = f"corpus/{repo.replace('/', '__')}"
    rec = {"rank": rank, "repo": repo, "category": cat, "commit": "", "included": 0, "reason": "", "tools": 0, "sites": 0}
    if not os.path.exists(dest):
        r = subprocess.run(["git", "clone", "-q", "--depth", "1", f"https://github.com/{repo}.git", dest],
                           capture_output=True, text=True, timeout=120, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if r.returncode:
            rec["reason"] = "I1: clone failed"
            w.writerow(rec); new.flush(); continue
    rec["commit"] = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    root = os.path.join(dest, sub) if sub else dest
    try:
        a = analyze_repo(root, repo)
    except Exception as e:  # analyzer crash is itself a coverage datum
        rec["reason"] = f"analyzer error: {type(e).__name__}"
        w.writerow(rec); new.flush(); shutil.rmtree(dest, ignore_errors=True); continue
    rec["tools"], rec["sites"] = a["n_tools"], len(a["sites"])
    if a["n_tools"] == 0:
        rec["reason"] = "I2: no decorated/registered Python MCP tool"
    elif not a["sites"]:
        rec["reason"] = "I3: no file/HTTP site reachable"
    else:
        rec["included"] = 1
        rec["reason"] = "included"
        a["category"] = cat
        a["commit"] = rec["commit"]
        results.append(a)
        included += 1
    w.writerow(rec); new.flush()
    if not rec["included"]:
        shutil.rmtree(dest, ignore_errors=True)   # keep disk small
    print(f"{rank:4} {repo:50} {rec['reason']:45} tools={rec['tools']} sites={rec['sites']} [{included}/{TARGET}]", flush=True)
json.dump(results, open(OUT, "w"), indent=1, ensure_ascii=False)
print("included", included, "attempted", len(done) + 0)
