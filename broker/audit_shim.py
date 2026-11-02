"""REC broker, audit mode: records the resolved effect object of every supported
sensitive operation while a tool call is active. Nothing is blocked.

Recorded per event: tool, kind, api, requested target, resolved object
(os.path.realpath for files; scheme://host:port for network), outcome.
"""
import builtins
import io
import json
import os
import shutil
import socket
import pathlib
import time

_ACTIVE = {"tool": None}
_LOG = []
_real_realpath = os.path.realpath


def _resolve_path(p):
    try:
        if isinstance(p, int):
            return f"fd:{p}"
        return _real_realpath(os.fspath(p))
    except Exception:
        return str(p)


def _rec(kind, api, requested, resolved):
    if _ACTIVE["tool"] is None:
        return
    _LOG.append({"tool": _ACTIVE["tool"], "kind": kind, "api": api,
                 "requested": str(requested)[:300], "resolved": str(resolved)[:300], "t": time.time()})


def _wrap_fs(fn, kind, api, idx=0, mode_idx=None):
    def w(*a, **k):
        target = a[idx] if len(a) > idx else next(iter(k.values()), None)
        kd = kind
        if mode_idx is not None:
            mode = a[mode_idx] if len(a) > mode_idx else k.get("mode", "r")
            kd = "fs.write" if isinstance(mode, str) and any(c in mode for c in "wax+") else "fs.read"
        _rec(kd, api, target, _resolve_path(target))
        return fn(*a, **k)
    w.__wrapped__ = fn
    return w


def install():
    builtins.open = _wrap_fs(builtins.open, "fs.read", "open", 0, 1)
    io.open = builtins.open
    for name, kind in [("remove", "fs.delete"), ("unlink", "fs.delete"), ("rmdir", "fs.delete"),
                       ("listdir", "fs.list"), ("scandir", "fs.list"), ("makedirs", "fs.write"),
                       ("mkdir", "fs.write"), ("rename", "fs.write"), ("replace", "fs.write")]:
        if hasattr(os, name):
            setattr(os, name, _wrap_fs(getattr(os, name), kind, "os." + name))
    for name, kind, idx in [("rmtree", "fs.delete", 0), ("copy", "fs.write", 1), ("copy2", "fs.write", 1),
                            ("copyfile", "fs.write", 1), ("move", "fs.write", 1), ("copytree", "fs.write", 1)]:
        setattr(shutil, name, _wrap_fs(getattr(shutil, name), kind, "shutil." + name, idx))
    P = pathlib.Path
    for name, kind in [("read_text", "fs.read"), ("read_bytes", "fs.read"), ("write_text", "fs.write"),
                       ("write_bytes", "fs.write"), ("unlink", "fs.delete"), ("mkdir", "fs.write"),
                       ("touch", "fs.write"), ("iterdir", "fs.list"), ("rmdir", "fs.delete")]:
        orig = getattr(P, name)

        def make(orig=orig, kind=kind, name=name):
            def m(self, *a, **k):
                _rec(kind, "Path." + name, self, _resolve_path(self))
                return orig(self, *a, **k)
            return m
        setattr(P, name, make())
    orig_conn = socket.socket.connect

    def connect(self, address):
        _rec("http.request", "socket.connect", address, f"tcp://{address[0]}:{address[1]}" if isinstance(address, tuple) else address)
        return orig_conn(self, address)
    socket.socket.connect = connect
    orig_gai = socket.getaddrinfo

    def gai(host, port, *a, **k):
        _rec("http.request", "getaddrinfo", f"{host}:{port}", f"dns://{host}:{port}")
        return orig_gai(host, port, *a, **k)
    socket.getaddrinfo = gai


def begin(tool):
    _ACTIVE["tool"] = tool


def end():
    _ACTIVE["tool"] = None


def dump(path):
    with builtins.open.__wrapped__(path, "w") as f:
        json.dump(_LOG, f, indent=1)
