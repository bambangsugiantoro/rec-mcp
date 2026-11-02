"""RQ4: per-operation overhead of the effect broker (open + read of a small file).

Each configuration runs in its own process: baseline (no broker), audit (log only),
sandbox (scope check), rec (contract-instance check), rec_schema (intersection).
Reports p50/p95 latency per operation in microseconds over N timed operations after warm-up.
"""
import json
import os
import statistics
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
N, WARM = 20000, 2000

CHILD = r'''
import os, sys, time, json
sys.path.insert(0, sys.argv[2])
mode, W = sys.argv[1], sys.argv[3]
root = os.path.join(W, "notes"); target = os.path.join(root, "a.txt")
if mode != "baseline":
    import effect_broker as EB
    EB.install()
    if mode == "audit":
        EB.STATE["policy"] = None
    elif mode == "sandbox":
        EB.STATE["policy"] = EB.SandboxScope([os.path.realpath(W)], {"127.0.0.1:8080"})
    else:
        g = {"ROOT": root}
        sites = [{"kind": "fs.read", "status": "exact", "term_raw": ["join", [["cfg", "ROOT"], ["arg", "name"]]]}]
        rec = EB.RECPolicy(sites, {"name": "a.txt"}, g, [os.path.realpath(W)], {"127.0.0.1:8080"})
        EB.STATE["policy"] = rec if mode == "rec" else EB.Intersect(rec, EB.RECPolicy(sites, {"name": "a.txt"}, g, [os.path.realpath(W)], {"127.0.0.1:8080"}))
times = []
for i in range(%d + %d):
    t0 = time.perf_counter_ns()
    with open(target) as f:
        f.read()
    t1 = time.perf_counter_ns()
    if i >= %d:
        times.append(t1 - t0)
    if mode != "baseline" and len(EB.STATE["log"]) > 1000:
        EB.STATE["log"].clear()
print(json.dumps(times))
''' % (N, WARM, WARM)


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def main():
    W = tempfile.mkdtemp(prefix="rq4_")
    os.makedirs(os.path.join(W, "notes"))
    open(os.path.join(W, "notes", "a.txt"), "w").write("x" * 256)
    child = os.path.join(W, "child.py")
    open(child, "w").write(CHILD)
    res = {}
    for mode in ["baseline", "audit", "sandbox", "rec", "rec_schema"]:
        runs = []
        for rep in range(3):   # three independent processes per configuration
            out = subprocess.run([sys.executable, child, mode, os.path.join(HERE, "..", "broker"), W],
                                 capture_output=True, text=True, timeout=300)
            runs += json.loads(out.stdout)
        us = [t / 1000 for t in runs]
        res[mode] = {"n": len(us), "p50_us": round(pct(us, 0.5), 2), "p95_us": round(pct(us, 0.95), 2), "mean_us": round(statistics.mean(us), 2)}
    base = res["baseline"]
    for m, r in res.items():
        r["added_p50_us"] = round(r["p50_us"] - base["p50_us"], 2)
        r["added_p95_us"] = round(r["p95_us"] - base["p95_us"], 2)
    res["_machine"] = {"cpus": os.cpu_count(), "python": sys.version.split()[0], "platform": sys.platform,
                       "note": "cloud container; open+read of a 256-byte file; 3 processes x 20,000 timed ops per configuration"}
    json.dump(res, open(os.path.join(HERE, "..", "results", "rq4_overhead.json"), "w"), indent=1)
    for m, r in res.items():
        print(m, r)


if __name__ == "__main__":
    main()
