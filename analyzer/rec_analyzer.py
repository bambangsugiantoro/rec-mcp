"""REC pilot analyzer: derive argument-to-resource relations for MCP tools.

For every MCP tool function (decorated with ``@<x>.tool`` / ``@tool``) the
analyzer finds security-sensitive operation sites (file and HTTP APIs), follows
the target argument backwards through assignments and first-party helper
functions, and expresses it as a term in the REC relation language:

    arg(x) | cfg(name) | const(v) | join(a, b, ...) | derive(op, t) | union(t...) | BOT(reason)

A site whose term contains BOT is "failed" (fail-closed). The analyzer also
emits *candidate* divergence signals for RQ0. These are heuristics for
triage only: they are NOT ground truth and must be confirmed by annotators.
"""
from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import dataclass, field, asdict

MAX_DEPTH = 3

# --- sensitive-API catalogue -------------------------------------------------
# name -> (kind, index of target positional arg, keyword name of target)
FUNC_SINKS = {
    "open": ("fs.open", 0, "file"),
    "io.open": ("fs.open", 0, "file"),
    "aiofiles.open": ("fs.open", 0, "file"),
    "os.remove": ("fs.delete", 0, "path"),
    "os.unlink": ("fs.delete", 0, "path"),
    "os.rmdir": ("fs.delete", 0, "path"),
    "os.listdir": ("fs.list", 0, "path"),
    "os.scandir": ("fs.list", 0, "path"),
    "os.walk": ("fs.list", 0, "top"),
    "os.makedirs": ("fs.write", 0, "name"),
    "os.mkdir": ("fs.write", 0, "path"),
    "os.rename": ("fs.write", 0, "src"),
    "os.replace": ("fs.write", 0, "src"),
    "shutil.rmtree": ("fs.delete", 0, "path"),
    "shutil.copy": ("fs.write", 1, "dst"),
    "shutil.copy2": ("fs.write", 1, "dst"),
    "shutil.copyfile": ("fs.write", 1, "dst"),
    "shutil.copytree": ("fs.write", 1, "dst"),
    "shutil.move": ("fs.write", 1, "dst"),
    "glob.glob": ("fs.list", 0, "pathname"),
    "requests.get": ("http.request", 0, "url"),
    "requests.post": ("http.request", 0, "url"),
    "requests.put": ("http.request", 0, "url"),
    "requests.delete": ("http.request", 0, "url"),
    "requests.patch": ("http.request", 0, "url"),
    "requests.head": ("http.request", 0, "url"),
    "requests.request": ("http.request", 1, "url"),
    "httpx.get": ("http.request", 0, "url"),
    "httpx.post": ("http.request", 0, "url"),
    "httpx.put": ("http.request", 0, "url"),
    "httpx.delete": ("http.request", 0, "url"),
    "httpx.request": ("http.request", 1, "url"),
    "urllib.request.urlopen": ("http.request", 0, "url"),
    "urlopen": ("http.request", 0, "url"),
}
# methods on a Path-like receiver
PATH_METHODS = {
    "read_text": "fs.read", "read_bytes": "fs.read", "open": "fs.open",
    "write_text": "fs.write", "write_bytes": "fs.write", "touch": "fs.write",
    "mkdir": "fs.write", "unlink": "fs.delete", "rmdir": "fs.delete",
    "iterdir": "fs.list", "glob": "fs.list", "rglob": "fs.list",
    "rename": "fs.write", "replace": "fs.write",
}
# methods on an HTTP client object (session.get(url) etc.)
CLIENT_METHODS = {"get": 0, "post": 0, "put": 0, "delete": 0, "patch": 0, "head": 0, "request": 1, "stream": 1}
CLIENT_HINTS = ("session", "client", "http", "requests", "httpx")
CLIENT_EXACT = {"session", "client", "http", "requests", "httpx", "http_client", "async_client", "aclient", "s"}
CLIENT_SUFFIX = ("_session", "_client", "client", "session")
CLIENT_EXCLUDE = ("sessions", "map", "info", "cache", "dict", "store", "registry", "db", "redis", "mongo", "sql", "vector", "chroma", "qdrant", "pinecone", "openai", "anthropic", "llm")


def is_http_client(recv: str) -> bool:
    last = recv.split(".")[-1].lower()
    if any(x in recv.lower() for x in CLIENT_EXCLUDE):
        return False
    return last in CLIENT_EXACT or last.endswith(CLIENT_SUFFIX)

PATH_CTORS = {"Path", "pathlib.Path", "PurePath", "os.path.join", "os.path.abspath",
              "os.path.normpath", "os.path.realpath", "os.path.expanduser", "posixpath.join"}
DERIVE_FUNCS = {"os.path.basename", "os.path.dirname", "str", "os.fspath", "urljoin", "urllib.parse.urljoin"}
CONTAINMENT_HINTS = ("is_relative_to", "commonpath", "startswith", "realpath", "resolve", "relative_to",
                     "validate_path", "safe_path", "check_path", "_validate", "ensure_within", "within")
GENERATED_FUNCS = {"os.getpid", "int", "len", "max", "min", "uuid4", "uuid.uuid4", "time.time", "time.time_ns", "datetime.now", "now", "utcnow", "isoformat", "strftime", "hex", "token_hex", "secrets.token_hex", "random", "randint", "hash", "sha256", "hexdigest", "mkstemp", "mkdtemp", "gettempdir", "tempfile.gettempdir", "tempfile.mkdtemp"}
NON_SHIPPED = {"tests", "test", "examples", "example", "scripts", "validation", "benchmarks", "benchmark", "docs", "evals", "fixtures"}
READONLY_PREFIXES = ("get_", "read_", "list_", "search_", "find_", "show_", "describe_", "query_", "fetch_", "view_", "count_", "stat")


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func) + "()"
    return ""


# --- terms -------------------------------------------------------------------
def T(kind, *args):
    return (kind,) + tuple(args)


def term_str(t) -> str:
    k = t[0]
    if k == "arg":
        return f"arg({t[1]})"
    if k == "cfg":
        return f"cfg({t[1]})"
    if k == "const":
        return f"const({t[1]!r})"
    if k == "BOT":
        return f"⊥[{t[1]}]"
    if k == "join":
        return "join(" + ", ".join(term_str(x) for x in t[1]) + ")"
    if k == "derive":
        return f"derive({t[1]}, {term_str(t[2])})"
    if k == "union":
        return "union(" + ", ".join(term_str(x) for x in t[1]) + ")"
    return str(t)


def has_bot(t) -> bool:
    if t[0] == "BOT":
        return True
    if t[0] in ("join", "union"):
        return any(has_bot(x) for x in t[1])
    if t[0] == "derive":
        return has_bot(t[2])
    return False


def base_prefix(t):
    """Leftmost trusted directory of a path term: cfg(...) or an absolute const."""
    k = t[0]
    if k == "cfg":
        return t
    if k == "const":
        return t if isinstance(t[1], str) and t[1].startswith(("/", "~")) else None
    if k == "join" and t[1]:
        return base_prefix(t[1][0])
    if k == "derive" and t[1] in ("resolve", "absolute", "expanduser", "parent", "with_suffix", "with_name", "str", "fspath"):
        return base_prefix(t[2])
    return None


def classify(t):
    """exact: fully derived relation; stored(d): name part comes from state under trusted dir d; failed: ⊥."""
    if not has_bot(t):
        return "exact", None
    b = base_prefix(t)
    if b is not None and not has_bot(b):
        return "stored", b
    return "failed", None


def args_in(t) -> set:
    if t[0] == "arg":
        return {t[1]}
    if t[0] in ("join", "union"):
        return set().union(*[args_in(x) for x in t[1]]) if t[1] else set()
    if t[0] == "derive":
        return args_in(t[2])
    return set()


# --- module index ------------------------------------------------------------
@dataclass
class Site:
    repo: str
    file: str
    tool: str
    line: int
    kind: str
    api: str
    term: str
    status: str            # exact | stored | failed
    args_used: list
    via_helper: bool
    containment_check: bool
    signals: list = field(default_factory=list)
    stored_base: str = ""
    term_raw: object = None


class Repo:
    def __init__(self, root: str):
        self.root = root
        self.funcs: dict[str, ast.FunctionDef] = {}   # simple name -> def (first-party)
        self.func_src: dict[str, str] = {}
        self.module_assigns: dict[str, ast.AST] = {}  # module-level NAME = expr
        self.tools: list[tuple[str, ast.FunctionDef]] = []
        self.parse_errors = 0
        self.lowlevel_servers = 0
        self.lowlevel_dispatch: list[str] = []
        self.defs_by_file: dict[str, dict] = {}       # rel -> {name: def}
        self.imports_by_file: dict[str, dict] = {}    # rel -> {alias: (module, name or None, level)}
        self.module_to_file: dict[str, str] = {}      # dotted module -> rel
        self.name_count: dict[str, int] = {}
        for d, dirs, fs in os.walk(root):
            dirs[:] = [x for x in dirs if x not in (".git", ".venv", "venv", "node_modules", "site-packages", "build", "dist")]
            for f in fs:
                if f.endswith(".py"):
                    self._load(os.path.join(d, f))

    def _load(self, path):
        try:
            src = open(path, encoding="utf-8", errors="ignore").read()
            mod = ast.parse(src)
        except Exception:
            self.parse_errors += 1
            return
        rel = os.path.relpath(path, self.root)
        mod_name = rel[:-3].replace(os.sep, ".")
        if mod_name.endswith(".__init__"):
            mod_name = mod_name[:-9]
        for cand in (mod_name, mod_name[4:] if mod_name.startswith("src.") else None):
            if cand:
                self.module_to_file.setdefault(cand, rel)
        defs, imps = {}, {}
        for node in ast.walk(mod):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(node.name, node)
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    imps[a.asname or a.name] = (node.module or "", a.name, node.level)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    imps[a.asname or a.name.split(".")[0]] = (a.name, None, 0)
        self.defs_by_file[rel] = defs
        self.imports_by_file[rel] = imps
        for n in defs:
            self.name_count[n] = self.name_count.get(n, 0) + 1
        if "@server.call_tool" in src or ".call_tool()" in src:
            self.lowlevel_servers += 1
        for node in mod.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tg in tgts:
                    if isinstance(tg, ast.Name) and node.value is not None:
                        self.module_assigns.setdefault(tg.id, node.value)
        is_test = any(part.startswith("test") or part in NON_SHIPPED for part in rel.lower().split(os.sep)[:-1]) or os.path.basename(rel).startswith(("test_", "conftest"))
        if is_test:
            return   # non-shipped code: excluded from tool and helper index
        dyn = set()
        for node in ast.walk(mod):
            # dynamic registration: x.tool(...)(f) or x.add_tool(f)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Call) and dotted(node.func.func).endswith(".tool") and node.args and isinstance(node.args[0], ast.Name):
                    dyn.add(node.args[0].id)
                if dotted(node.func).endswith(".add_tool") and node.args and isinstance(node.args[0], ast.Name):
                    dyn.add(node.args[0].id)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(node.name, node)
                self.func_src.setdefault(node.name, rel)
                if node.name == "call_tool" and any(dotted(d.func if isinstance(d, ast.Call) else d).endswith("call_tool") for d in node.decorator_list):
                    self.lowlevel_dispatch.append(rel)
        for node in ast.walk(mod):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not is_test:
                if self._is_tool(node) or node.name in dyn:
                    self.tools.append((rel, node))

    def _module_file(self, module, level, from_rel):
        if level:
            pkg = os.path.dirname(from_rel).replace(os.sep, ".")
            parts = pkg.split(".") if pkg else []
            if level > 1:
                parts = parts[: len(parts) - (level - 1)]
            module = ".".join([x for x in parts + ([module] if module else []) if x])
        for cand in (module, "src." + module):
            if cand in self.module_to_file:
                return self.module_to_file[cand]
        return None

    def resolve(self, fname: str, from_rel: str):
        """Resolve a called name to (def, rel) using same-file defs, explicit imports, then a unique name."""
        if not fname:
            return None
        parts = fname.split(".")
        short = parts[-1]
        defs = self.defs_by_file.get(from_rel, {})
        imps = self.imports_by_file.get(from_rel, {})
        if len(parts) == 1 or parts[0] in ("self", "cls"):
            if short in defs:
                return defs[short], from_rel
        if len(parts) == 1 and short in imps:
            module, name, level = imps[short]
            f = self._module_file(module, level, from_rel)
            if f and name in self.defs_by_file.get(f, {}):
                return self.defs_by_file[f][name], f
            f2 = self._module_file((module + "." + name) if module else name, level, from_rel)  # imported submodule
            if f2 is None:
                return None
        if len(parts) == 2 and parts[0] in imps:
            module, name, level = imps[parts[0]]
            target = (f"{module}.{name}" if module else name) if name else module
            f = self._module_file(target, level, from_rel)
            if f and short in self.defs_by_file.get(f, {}):
                return self.defs_by_file[f][short], f
        simple = len(parts) == 1 or (len(parts) == 2 and parts[0] in ("self", "cls"))
        if simple and self.name_count.get(short, 0) == 1 and short in self.funcs:   # unique fallback, plain calls only
            return self.funcs[short], self.func_src[short]
        return None

    @staticmethod
    def _is_tool(fn) -> bool:
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            name = dotted(target)
            if name == "tool" or name.endswith(".tool"):
                return True
        return False


class ToolAnalyzer:
    def __init__(self, repo: Repo, repo_name: str):
        self.repo = repo
        self.repo_name = repo_name
        self.cur_file = ""

    # evaluate an expression to a term under an environment
    def ev(self, node, env, depth, stack):
        if node is None:
            return T("BOT", "none")
        if isinstance(node, ast.Constant):
            return T("const", node.value if isinstance(node.value, (str, int, float, bool)) or node.value is None else "?")
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in self.repo.module_assigns and depth <= MAX_DEPTH:
                v = self.repo.module_assigns[node.id]
                inner = self.ev(v, {}, depth + 1, stack)
                if inner[0] == "const":
                    return inner
                return T("cfg", node.id)
            if node.id.isupper():
                return T("cfg", node.id)
            return T("BOT", f"unknown name {node.id}")
        if isinstance(node, ast.Attribute):
            d = dotted(node)
            if d.startswith(("self.", "cls.", "config.", "settings.", "cfg.")) or d.split(".")[0] in self.repo.module_assigns:
                return T("cfg", d)
            base = self.ev(node.value, env, depth, stack)
            if base[0] == "arg":                      # pydantic params model: params.doc_id
                return T("arg", f"{base[1]}.{node.attr}")
            if base[0] == "cfg":
                return T("cfg", f"{base[1]}.{node.attr}")
            if node.attr in ("parent", "name", "stem", "suffix"):
                return T("derive", node.attr, base)
            return T("BOT", f"attribute {d}")
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(T("const", v.value))
                elif isinstance(v, ast.FormattedValue):
                    parts.append(self.ev(v.value, env, depth, stack))
            return T("join", tuple(parts))
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            return T("join", (self.ev(node.left, env, depth, stack), self.ev(node.right, env, depth, stack)))
        if isinstance(node, ast.IfExp):
            return T("union", (self.ev(node.body, env, depth, stack), self.ev(node.orelse, env, depth, stack)))
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            return T("union", tuple(self.ev(v, env, depth, stack) for v in node.values))
        if isinstance(node, ast.Await):
            return self.ev(node.value, env, depth, stack)
        if isinstance(node, ast.Call):
            fname = dotted(node.func)
            short = fname.split(".")[-1]
            if fname in PATH_CTORS or short in ("Path", "PurePath"):
                return T("join", tuple(self.ev(a, env, depth, stack) for a in node.args)) if node.args else T("cfg", "cwd")
            if fname in DERIVE_FUNCS:
                return T("derive", short, self.ev(node.args[0], env, depth, stack) if node.args else T("BOT", "noarg"))
            if isinstance(node.func, ast.Attribute):
                meth = node.func.attr
                if meth in ("resolve", "absolute", "expanduser", "strip", "lower", "lstrip", "rstrip", "replace", "with_suffix", "with_name", "format", "joinpath", "encode", "decode"):
                    recv = self.ev(node.func.value, env, depth, stack)
                    if meth == "joinpath":
                        return T("join", (recv,) + tuple(self.ev(a, env, depth, stack) for a in node.args))
                    if meth == "format":
                        return T("join", (recv,) + tuple(self.ev(a, env, depth, stack) for a in node.args))
                    return T("derive", meth, recv)
                if meth == "get" and dotted(node.func.value) in ("os.environ", "environ"):
                    return T("cfg", "env:" + (node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else "?"))
            if fname in GENERATED_FUNCS or short in GENERATED_FUNCS:
                return T("cfg", "generated:" + short)
            if fname in ("Path.cwd", "pathlib.Path.cwd", "os.getcwd", "Path.home", "pathlib.Path.home"):
                return T("cfg", fname)
            if fname in ("os.getenv", "getenv"):
                return T("cfg", "env:" + (node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else "?"))
            # first-party helper: inline return expression with parameter binding
            resolved = self.repo.resolve(fname, self.cur_file) if depth < MAX_DEPTH and short not in stack else None
            if resolved is not None:
                fn, fn_rel = resolved
                params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
                benv = {}
                for p, a in zip(params, node.args):
                    benv[p] = self.ev(a, env, depth, stack)
                for kw in node.keywords:
                    if kw.arg:
                        benv[kw.arg] = self.ev(kw.value, env, depth, stack)
                for p in params:
                    benv.setdefault(p, T("const", "default"))
                saved = self.cur_file
                self.cur_file = fn_rel
                rets = self._returns(fn, benv, depth + 1, stack | {short})
                self.cur_file = saved
                if rets:
                    return rets[0] if len(rets) == 1 else T("union", tuple(rets))
            return T("BOT", f"call {fname or '?'}")
        if isinstance(node, ast.Subscript):
            base = self.ev(node.value, env, depth, stack)
            key = node.slice.value if isinstance(node.slice, ast.Constant) else "?"
            if base[0] in ("arg", "cfg"):
                return T(base[0], f"{base[1]}[{key}]")
            return T("BOT", "subscript")
        return T("BOT", type(node).__name__)

    def _returns(self, fn, env, depth, stack):
        env = dict(env)
        out = []
        for st in ast.walk(fn):
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                env[st.targets[0].id] = self.ev(st.value, env, depth, stack)
            elif isinstance(st, ast.Return) and st.value is not None:
                out.append(self.ev(st.value, env, depth, stack))
        return out[:4]

    def _containment(self, fn, helpers_seen) -> bool:
        src = ast.unparse(fn)
        if any(h in src for h in CONTAINMENT_HINTS):
            return True
        for name in helpers_seen:
            if name in self.repo.funcs and any(h in ast.unparse(self.repo.funcs[name]) for h in CONTAINMENT_HINTS):
                return True
        return False

    def analyze(self, rel, fn):
        params = [a.arg for a in fn.args.args + fn.args.kwonlyargs if a.arg not in ("self", "cls", "ctx", "context")]
        env = {p: T("arg", p) for p in params}
        sites: list[Site] = []
        helpers: set[str] = set()
        self._scan(fn, env, sites, rel, fn.name, 0, helpers, frozenset([fn.name]), params)
        contained = self._containment(fn, helpers)
        for s in sites:
            s.containment_check = contained
            s.signals = self._signals(fn, s, params)
        return params, sites

    def _scan(self, fn, env, sites, rel, tool, depth, helpers, stack, params):
        saved_file = self.cur_file
        self.cur_file = rel
        env = dict(env)
        for st in ast.walk(fn):
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                env[st.targets[0].id] = self.ev(st.value, env, depth, stack)
            elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                env[st.target.id] = self.ev(st.value, env, depth, stack)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for it in st.items:
                    if isinstance(it.optional_vars, ast.Name):
                        env[it.optional_vars.id] = T("BOT", "handle")
            elif isinstance(st, ast.For) and isinstance(st.target, ast.Name):
                env[st.target.id] = T("BOT", "loop var")
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            fname = dotted(call.func)
            hit = None
            if fname in FUNC_SINKS:
                kind, idx, kw = FUNC_SINKS[fname]
                tnode = call.args[idx] if len(call.args) > idx else next((k.value for k in call.keywords if k.arg == kw), None)
                if kind == "fs.open":
                    mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
                    m = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else "r"
                    kind = "fs.write" if any(c in m for c in "wax+") else "fs.read"
                hit = (kind, fname, tnode)
            elif isinstance(call.func, ast.Attribute):
                meth = call.func.attr
                recv_name = dotted(call.func.value).lower()
                one_arg_only = meth in ("replace", "rename") and len(call.args) != 1
                if meth in PATH_METHODS and not one_arg_only and not any(h in recv_name for h in CLIENT_HINTS):
                    recv = self.ev(call.func.value, env, depth, stack)
                    str_like = recv[0] == "derive" and recv[1] in ("lower", "strip", "lstrip", "rstrip", "replace", "format", "encode", "decode")
                    if not str_like and (recv[0] != "BOT" or "path" in recv_name or "file" in recv_name or "dir" in recv_name):
                        kind = PATH_METHODS[meth]
                        if meth == "open":
                            mode = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "mode"), None)
                            m = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else "r"
                            kind = "fs.write" if any(c in m for c in "wax+") else "fs.read"
                        sites.append(self._site(rel, tool, call, kind, "Path." + meth, recv, depth > 0, params))
                        continue
                if meth in CLIENT_METHODS and is_http_client(dotted(call.func.value)):
                    idx = CLIENT_METHODS[meth]
                    tnode = call.args[idx] if len(call.args) > idx else next((k.value for k in call.keywords if k.arg == "url"), None)
                    hit = ("http.request", recv_name + "." + meth, tnode)
            if hit:
                kind, api, tnode = hit
                term = self.ev(tnode, env, depth, stack)
                sites.append(self._site(rel, tool, call, kind, api, term, depth > 0, params))
                continue
            # descend into first-party helpers that are called with tool-derived args
            short = fname.split(".")[-1]
            resolved = self.repo.resolve(fname, rel) if depth < MAX_DEPTH and short not in stack else None
            if resolved is not None:
                helper, helper_rel = resolved
                hp = [a.arg for a in helper.args.args if a.arg not in ("self", "cls")]
                benv = {p: self.ev(a, env, depth, stack) for p, a in zip(hp, call.args)}
                for kw in call.keywords:
                    if kw.arg:
                        benv[kw.arg] = self.ev(kw.value, env, depth, stack)
                for p in hp:
                    benv.setdefault(p, T("const", "default"))
                helpers.add(short)
                self._scan(helper, benv, sites, helper_rel, tool, depth + 1, helpers, stack | {short}, params)
                self.cur_file = rel
        self.cur_file = saved_file

    def _site(self, rel, tool, call, kind, api, term, via_helper, params):
        status, base = classify(term)
        st = Site(self.repo_name, rel, tool, call.lineno, kind, api, term_str(term),
                  status, sorted(args_in(term)), via_helper, False)
        st.term_raw = term
        if base is not None:
            st.stored_base = term_str(base)
            st.term = f"stored({st.stored_base})  <- {st.term}"
        return st

    def _signals(self, fn, s: Site, params):
        """Candidate divergence signals for RQ0 triage (heuristic, unconfirmed)."""
        sig = []
        name = fn.name.lower()
        if s.status == "exact" and s.args_used and s.kind.startswith("fs.") and not s.containment_check:
            sig.append("arg-controlled path without containment check")
        if s.status == "exact" and not s.args_used and s.kind in ("fs.write", "fs.delete"):
            sig.append("writes object not named by any argument")
        if s.kind in ("fs.write", "fs.delete") and name.startswith(READONLY_PREFIXES):
            sig.append("write/delete in tool named as read-only")
        if s.kind == "http.request" and s.status == "exact" and s.args_used and "const(" not in s.term.split(",")[0]:
            sig.append("argument controls request URL/host")
        return sig


def analyze_repo(root, name):
    repo = Repo(root)
    ta = ToolAnalyzer(repo, name)
    tools, sites = [], []
    for rel, fn in repo.tools:
        try:
            params, ss = ta.analyze(rel, fn)
        except RecursionError:
            params, ss = [], []
        doc = (ast.get_docstring(fn) or "").strip().split("\n")[0][:160]
        seen, uniq = set(), []
        for s in ss:
            key = (s.file, s.line, s.kind, s.term)
            if key not in seen:
                seen.add(key); uniq.append(s)
        tools.append({"repo": name, "file": rel, "tool": fn.name, "params": params, "doc": doc, "n_sites": len(uniq)})
        sites += [asdict(s) for s in uniq]
    return {"repo": name, "n_tools": len(repo.tools), "parse_errors": repo.parse_errors,
            "lowlevel_server_files": repo.lowlevel_servers, "lowlevel_dispatch": repo.lowlevel_dispatch, "tools": tools, "sites": sites}


if __name__ == "__main__":
    out = analyze_repo(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else os.path.basename(sys.argv[1]))
    json.dump(out, sys.stdout, indent=1, ensure_ascii=False)
