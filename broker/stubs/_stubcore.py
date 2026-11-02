"""Minimal stand-ins for the MCP SDK so tool functions can be imported and called directly."""
class _Any:
    def __init__(self, *a, **k): pass
    def __call__(self, *a, **k): return _Any()
    def __getattr__(self, n): return _Any()

class FastMCP:
    def __init__(self, *a, **k): self.name = a[0] if a else "stub"
    def _deco(self, *a, **k):
        if a and callable(a[0]) and not k:
            return a[0]
        return lambda f: f
    tool = _deco; resource = _deco; prompt = _deco
    def add_tool(self, f, *a, **k): return f
    def run(self, *a, **k): pass
    def __getattr__(self, n): return _Any()
Context = _Any

import sys as _sys, types as _types, importlib.abc as _abc, importlib.machinery as _mach


class _AnyModule(_types.ModuleType):
    __path__ = []          # behave like a package so deeper submodules resolve too

    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        return FastMCP if n in ("FastMCP", "MCPServer") else _Any


class _StubFinder(_abc.MetaPathFinder, _abc.Loader):
    """Any not-yet-stubbed submodule of mcp/fastmcp becomes a permissive stub module."""
    PREFIXES = ("mcp.", "fastmcp.")

    def find_spec(self, name, path=None, target=None):
        if name.startswith(self.PREFIXES) and name not in _sys.modules:
            return _mach.ModuleSpec(name, self, is_package=True)
        return None

    def create_module(self, spec):
        return _AnyModule(spec.name)

    def exec_module(self, module):
        pass


if not any(isinstance(f, _StubFinder) for f in _sys.meta_path):
    _sys.meta_path.append(_StubFinder())
