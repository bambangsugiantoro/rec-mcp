import sys, types
from _stubcore import _Any, FastMCP, Context
class _AnyModule(types.ModuleType):
    def __getattr__(self, n): return _Any
def _mk(name):
    m = _AnyModule(name); sys.modules[name] = m; return m
for n in ["mcp.types", "mcp.server.stdio", "mcp.server.models", "mcp.server.lowlevel", "mcp.shared", "mcp.shared.exceptions",
          "mcp.server.fastmcp.exceptions", "mcp.server.fastmcp.utilities", "mcp.server.fastmcp.prompts", "mcp.server.fastmcp.resources", "mcp.client", "mcp.client.stdio"]:
    _mk(n)
ClientSession = _Any; StdioServerParameters = _Any
