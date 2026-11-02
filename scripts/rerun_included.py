import csv, json, os, re, sys, time
sys.path.insert(0, "analyzer"); sys.setrecursionlimit(5000)
from rec_analyzer import analyze_repo
rows = json.load(open("py_local.json")); sub = {}
for sec, name, url, *_ in rows:
    m = re.match(r"https://github.com/([^/]+)/([^/#?]+)(?:/tree/[^/]+/(.*))?", url)
    if m: sub.setdefault(f"{m.group(1)}/{m.group(2)}", m.group(3))
log = [r for r in csv.DictReader(open("results/expansion_log.csv")) if r["included"] == "1"]
out = []
for r in log:
    root = os.path.join("corpus", r["repo"].replace("/", "__"), sub.get(r["repo"]) or "")
    a = analyze_repo(root, r["repo"]); a["category"] = r["category"]; a["commit"] = r["commit"]
    out.append(a)
json.dump(out, open(sys.argv[1], "w"), indent=1, ensure_ascii=False)
print("repos", len(out), "sites", sum(len(a["sites"]) for a in out))
