"""REC effect broker: audit and enforcement modes.

The broker interposes on file and network operations inside the tool process.
In enforce mode each operation is checked against the active policy *before*
it happens, using the resolved object (realpath; host:port), and denied with
PermissionError if the policy rejects it.

Policies (used by the RQ2 benchmark and the RQ4 overhead measurement):
  NoDefense, ToolAllowlist, ArgPolicy, SandboxScope, RECPolicy (+ ablation flags)
"""
from __future__ import annotations

import builtins
import os
import shutil
import socket
import pathlib
from urllib.parse import urlsplit

_real = {"open": builtins.open, "realpath": os.path.realpath}
STATE = {"policy": None, "log": [], "resolve": True}


def resolve_obj(p):
    p = os.fspath(p)
    if STATE["resolve"]:
        return _real["realpath"](p)
    return os.path.normpath(os.path.join(os.getcwd(), p))   # ablation A2: string-level check only


def _check(kind, requested, obj):
    pol = STATE["policy"]
    allowed = True if pol is None else pol.allow(kind, obj)
    STATE["log"].append({"kind": kind, "requested": str(requested), "object": obj, "allowed": allowed})
    if not allowed:
        raise PermissionError(f"REC broker: {kind} on {obj} outside authorized effects")


def _fs(fn, kind, idx=0, mode_idx=None):
    def w(*a, **k):
        target = a[idx] if len(a) > idx else next(iter(k.values()), None)
        kd = kind
        if mode_idx is not None:
            mode = a[mode_idx] if len(a) > mode_idx else k.get("mode", "r")
            kd = "fs.write" if isinstance(mode, str) and any(c in mode for c in "wax+") else "fs.read"
        if isinstance(target, int):
            return fn(*a, **k)
        _check(kd, target, resolve_obj(target))
        return fn(*a, **k)
    w.__wrapped__ = fn
    return w


_installed = False


def install():
    global _installed
    if _installed:
        return
    _installed = True
    builtins.open = _fs(builtins.open, "fs.read", 0, 1)
    for name, kind in [("remove", "fs.delete"), ("unlink", "fs.delete"), ("rmdir", "fs.delete"), ("listdir", "fs.list"),
                       ("makedirs", "fs.write"), ("mkdir", "fs.write"), ("rename", "fs.write"), ("replace", "fs.write")]:
        setattr(os, name, _fs(getattr(os, name), kind))
    for name, kind, idx in [("rmtree", "fs.delete", 0), ("copy", "fs.write", 1), ("copy2", "fs.write", 1),
                            ("copyfile", "fs.write", 1), ("move", "fs.write", 1)]:
        setattr(shutil, name, _fs(getattr(shutil, name), kind, idx))
    P = pathlib.Path
    for name, kind in [("read_text", "fs.read"), ("read_bytes", "fs.read"), ("write_text", "fs.write"),
                       ("write_bytes", "fs.write"), ("unlink", "fs.delete"), ("touch", "fs.write"), ("iterdir", "fs.list")]:
        orig = getattr(P, name)

        def mk(orig=orig, kind=kind):
            def m(self, *a, **k):
                _check(kind, self, resolve_obj(self))
                return orig(self, *a, **k)
            return m
        setattr(P, name, mk())
    orig_gai = socket.getaddrinfo

    def gai(host, port, *a, **k):
        _check("http.request", f"{host}:{port}", f"{host}:{port}")
        return orig_gai(host, port, *a, **k)
    socket.getaddrinfo = gai


# ---------------------------------------------------------------- policies
def _under(obj, root):
    root = root.rstrip(os.sep)
    return obj == root or obj.startswith(root + os.sep)


class NoDefense:
    name = "none"
    def allow(self, kind, obj): return True


class ToolAllowlist(NoDefense):
    name = "allowlist"           # the tool is on the list, so every effect of the call proceeds


class SandboxScope:
    """Directory/host confinement for the whole session (no per-call precision)."""
    name = "sandbox"
    def __init__(self, roots, hosts): self.roots, self.hosts = roots, hosts
    def allow(self, kind, obj):
        if kind == "http.request":
            return obj.rsplit(":", 1)[0] in self.hosts
        return any(_under(obj, r) for r in self.roots)


class ArgPolicy:
    """Schema-level argument checks applied before the call; effects are then unrestricted."""
    name = "argpolicy"
    def __init__(self, hosts): self.hosts = hosts
    def check_args(self, args):
        for k, v in args.items():
            if not isinstance(v, str):
                continue
            if v.startswith(("http://", "https://")):
                if (urlsplit(v).hostname or "") not in self.hosts:
                    return False
            elif any(t in k.lower() for t in ("path", "file", "name", "dir")):
                if v.startswith("/") or ".." in v.replace("\\", "/").split("/"):
                    return False
        return True
    def allow(self, kind, obj): return True


# ------------------------------------------------ REC: contract instances
def _getattr_chain(ns, dotted):
    parts = dotted.split(".")
    cur = ns.get(parts[0]) if isinstance(ns, dict) else getattr(ns, parts[0], None)
    for p in parts[1:]:
        if cur is None:
            return None
        cur = getattr(cur, p, None)
    return cur


def eval_term(t, args, g):
    """Return (candidates, prefixes): exact objects and directory prefixes permitted by term t.
    None means the term cannot be evaluated (fail closed)."""
    k = t[0]
    if k == "const":
        return ({str(t[1])}, set()) if t[1] is not None else None
    if k == "arg":
        name = t[1].split("[")[0].split(".")[0]
        v = args.get(name)
        if v is None:
            return None
        if "." in t[1] and "[" not in t[1]:
            v = getattr(v, t[1].split(".", 1)[1], None)
        return ({os.fspath(v) if isinstance(v, os.PathLike) else str(v)}, set()) if v is not None else None
    if k == "cfg":
        n = t[1]
        if n.startswith("env:"):
            v = os.environ.get(n[4:])
        elif n in ("Path.cwd", "os.getcwd"):
            v = os.getcwd()
        elif n in ("Path.home",):
            v = os.path.expanduser("~")
        elif n.startswith("generated:"):
            return None
        else:
            v = _getattr_chain(g, n.replace("self.", "", 1))
        return ({os.fspath(v) if isinstance(v, os.PathLike) else str(v)}, set()) if v is not None else None
    if k in ("join",):
        parts = [eval_term(x, args, g) for x in t[1]]
        if any(p is None for p in parts) or not parts:
            return None
        acc = {""}
        for cands, _ in parts:
            nxt = set()
            for a in acc:
                for c in cands:
                    nxt.add(a + c)                                   # string concatenation (f-string, +)
                    nxt.add(os.path.join(a, c) if a else c)          # path join (Path /, os.path.join)
            acc = set(list(nxt)[:256])
        return acc, set()
    if k == "derive":
        inner = eval_term(t[2], args, g)
        if inner is None:
            return None
        c, p = inner
        op = t[1]
        if op in ("resolve", "absolute", "str", "fspath", "expanduser"):
            return c, p
        if op == "lstrip":
            return c | {x.lstrip("/") for x in c}, p
        if op in ("parent", "dirname"):
            return {os.path.dirname(x) for x in c}, p
        if op in ("name", "basename"):
            return {os.path.basename(x) for x in c}, p
        return None
    if k == "union":
        out_c, out_p = set(), set()
        for x in t[1]:
            r = eval_term(x, args, g)
            if r is None:
                return None
            out_c |= r[0]; out_p |= r[1]
        return out_c, out_p
    return None


def base_dir(t, args, g):
    """Trusted directory a path term is anchored in (join with cfg/abs-const first part)."""
    if t[0] == "join" and t[1]:
        first = t[1][0]
        if first[0] in ("cfg", "const"):
            r = eval_term(first, args, g)
            if r and len(r[0]) == 1:
                b = next(iter(r[0]))
                if b.startswith("/") or first[0] == "cfg":
                    return os.path.abspath(b)
        return base_dir(first, args, g)
    if t[0] == "derive" and t[1] in ("resolve", "absolute", "str", "fspath"):
        return base_dir(t[2], args, g)
    return None


class RECPolicy:
    """Per-call contract instance from implementation-derived relations, intersected with the authorization scope."""
    name = "rec"

    def __init__(self, sites, args, module_globals, scope_roots, scope_hosts, confine=True):
        self.scope = SandboxScope(scope_roots, scope_hosts)
        self.rules = []          # (kind, exact objects, prefixes, confinement dir)
        for s in sites:
            raw = s.get("term_raw")
            if raw is None:
                continue
            if s["status"] == "stored":
                b = base_dir(raw, args, module_globals)
                if b:
                    self.rules.append((s["kind"], set(), {b}, b if confine else None))
                continue
            r = eval_term(raw, args, module_globals)
            if r is None:
                continue                                  # ⊥: fail closed for this site
            cands, prefixes = r
            if s["kind"] == "http.request":
                hosts = set()
                for c in cands:
                    u = urlsplit(c if "://" in c else "http://" + c)
                    if u.hostname:
                        hosts.add(f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}")
                self.rules.append((s["kind"], hosts, set(), None))
            else:
                objs = {_real["realpath"](os.path.abspath(c)) if STATE["resolve"] else os.path.normpath(os.path.abspath(c)) for c in cands}
                b = base_dir(raw, args, module_globals) if confine else None
                self.rules.append((s["kind"], objs, prefixes, b))

    def allow(self, kind, obj):
        if not self.scope.allow(kind, obj):
            return False
        for k, objs, prefixes, confine in self.rules:
            if k != kind and not (k == "fs.read" and kind == "fs.read") and not (k == "fs.write" and kind == "fs.write"):
                continue
            if confine and not _under(obj, _real["realpath"](confine) if STATE["resolve"] else confine):
                continue
            if obj in objs or any(_under(obj, p) for p in prefixes):
                return True
        return False


class Intersect:
    """Allow an effect only if every component policy allows it (e.g. REC ∩ schema-implied relations)."""
    name = "intersect"
    def __init__(self, *pols): self.pols = pols
    def allow(self, kind, obj): return all(p.allow(kind, obj) for p in self.pols)
