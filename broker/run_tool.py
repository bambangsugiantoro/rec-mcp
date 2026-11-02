"""Invoke MCP tool functions directly under the audit shim.

usage: run_tool.py <repo_root> <rel_file> <out.json> <tool1,tool2,...> <args.json>

Runs inside an isolated sandbox prepared by the caller (no network namespace,
temporary HOME and working directory). Each tool is called with generated
probe arguments; every resolved effect object is logged.
"""
import asyncio
import importlib
import inspect
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(1, os.path.join(HERE, "vendor"))
sys.path.insert(0, HERE)
import audit_shim  # noqa: E402

repo_root, rel_file, out_path, tools_csv, args_path = sys.argv[1:6]
probes = json.load(open(args_path))
sys.path.insert(0, repo_root)
if os.path.isdir(os.path.join(repo_root, "src")):
    sys.path.insert(0, os.path.join(repo_root, "src"))
mod_name = rel_file[:-3].replace(os.sep, ".")
if mod_name.startswith("src."):
    mod_name = mod_name[4:]
result = {"module": mod_name, "import_ok": False, "calls": []}
try:
    audit_shim.install()
    mod = importlib.import_module(mod_name)
    result["import_ok"] = True
except BaseException as e:
    result["import_error"] = f"{type(e).__name__}: {str(e)[:200]}"
    mod = None

if mod is not None:
    for tool in tools_csv.split(","):
        fn = getattr(mod, tool, None)
        fn = getattr(fn, "fn", fn)           # some decorators wrap in an object with .fn
        if fn is None or not callable(fn):
            result["calls"].append({"tool": tool, "status": "not found"})
            continue
        for i, args in enumerate(probes.get(tool, [{}])):
            audit_shim.begin(tool)
            rec = {"tool": tool, "probe": i, "args": args}
            try:
                r = fn(**args)
                if inspect.isawaitable(r):
                    r = asyncio.run(asyncio.wait_for(r, 8))
                rec["status"] = "ok"
            except BaseException as e:   # tools may raise on probes; that is still informative
                rec["status"] = f"raised {type(e).__name__}"
                rec["error"] = str(e)[:160]
            audit_shim.end()
            result["calls"].append(rec)
audit_shim.dump(out_path + ".events.json")
with open(out_path, "w") as f:
    json.dump(result, f, indent=1)
