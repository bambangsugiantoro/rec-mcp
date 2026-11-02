"""Dynamic confirmation for RQ0 (audit mode): call each tool with probe arguments
inside a sandbox (user + network namespace, temporary HOME/cwd/TMPDIR) and
compare observed effect objects with the static analysis.

usage: dynamic.py <static_results.json> <corpus_dir> <out.json> [repo,...]
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
PATHLIKE = re.compile(r"(path|file|dir|folder|name|doc|note|target|dest|src|output|input|filename|slug|key)", re.I)
URLLIKE = re.compile(r"(url|uri|link|endpoint|host|href)", re.I)
CONTENT = re.compile(r"(content|text|data|body|message|query|prompt|code)", re.I)
NOISE = re.compile(r"(\.pyc?$|site-packages|/usr/lib|/usr/local/lib|__pycache__|/proc/|/dev/|/etc/(ssl|localtime|hosts|resolv)|\.so$|/opt/)")


def probes_for(params):
    def val(p, escape):
        if URLLIKE.search(p):
            return "http://127.0.0.1:9/rec_probe"
        if CONTENT.search(p) and not PATHLIKE.search(p):
            return "rec probe content"
        if PATHLIKE.search(p):
            return "../rec_escape_probe.txt" if escape else "rec_probe.txt"
        if re.search(r"(count|limit|num|size|max|min|n$|top|depth|page|line)", p, re.I):
            return 1
        return "rec_probe"
    return [{p: val(p, False) for p in params}, {p: val(p, True) for p in params}]


def classify(ev, sandbox):
    r = ev["resolved"]
    if ev["kind"] == "http.request":
        host = r.split("://", 1)[-1].rsplit(":", 1)[0]
        return "net-probe" if host in ("127.0.0.1",) and ":9" in r else "net-other"
    if NOISE.search(r):
        return "noise"
    arg = ("rec_probe" in r) or ("rec_escape_probe" in r)
    inside = r.startswith(sandbox)
    if "rec_escape_probe" in r and not inside:
        return "arg-escape"
    if arg:
        return "arg-inside" if inside else "arg-outside"
    return "nonarg-inside" if inside else "nonarg-outside"


def run_repo(entry, corpus_dir, sub):
    repo = entry["repo"]
    root = os.path.join(corpus_dir, repo.replace("/", "__"), sub or "")
    by_file = defaultdict(list)
    for t in entry["tools"]:
        if t["n_sites"]:
            by_file[t["file"]].append(t)
    out = []
    for rel, tools in by_file.items():
        sandbox = tempfile.mkdtemp(prefix="recsb_")
        os.makedirs(os.path.join(sandbox, "home"), exist_ok=True)
        os.makedirs(os.path.join(sandbox, "tmp"), exist_ok=True)
        work = os.path.join(sandbox, "work"); os.makedirs(work)
        probes = {t["tool"]: probes_for(t["params"]) for t in tools}
        args_path = os.path.join(sandbox, "probes.json"); json.dump(probes, open(args_path, "w"))
        res_path = os.path.join(sandbox, "result.json")
        env = {"PATH": os.environ["PATH"], "HOME": os.path.join(sandbox, "home"), "TMPDIR": os.path.join(sandbox, "tmp"),
               "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*", "LANG": "C.UTF-8"}
        cmd = ["unshare", "-Urn", sys.executable, "-I" if False else "-B", os.path.join(HERE, "run_tool.py"),
               os.path.abspath(root), rel, res_path, ",".join(probes), args_path]
        try:
            p = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=60)
            res = json.load(open(res_path)) if os.path.exists(res_path) else {"import_ok": False, "import_error": (p.stderr or "")[-200:]}
            events = json.load(open(res_path + ".events.json")) if os.path.exists(res_path + ".events.json") else []
        except subprocess.TimeoutExpired:
            res, events = {"import_ok": False, "import_error": "timeout"}, []
        for e in events:
            e["class"] = classify(e, sandbox)
        out.append({"repo": repo, "file": rel, "tools": [t["tool"] for t in tools], "result": res, "events": events})
        shutil.rmtree(sandbox, ignore_errors=True)
    return out


if __name__ == "__main__":
    static = json.load(open(sys.argv[1]))
    corpus_dir = sys.argv[2]
    only = set(sys.argv[4].split(",")) if len(sys.argv) > 4 else None
    rows = json.load(open(os.path.join(HERE, "..", "py_local.json")))
    sub = {}
    for sec, name, url, *_ in rows:
        m = re.match(r"https://github.com/([^/]+)/([^/#?]+)(?:/tree/[^/]+/(.*))?", url)
        if m:
            sub.setdefault(f"{m.group(1)}/{m.group(2)}", m.group(3))
    allres = []
    for entry in static:
        if only and entry["repo"] not in only:
            continue
        r = run_repo(entry, corpus_dir, sub.get(entry["repo"]))
        allres += r
        ok = sum(1 for x in r if x["result"].get("import_ok"))
        print(f"{entry['repo']:45} files={len(r)} import_ok={ok} events={sum(len(x['events']) for x in r)}", flush=True)
    json.dump(allres, open(sys.argv[3], "w"), indent=1)
