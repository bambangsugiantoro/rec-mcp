import sys, types
from _stubcore import FastMCP, Context, _Any
class _AnyModule(types.ModuleType):
    def __getattr__(self, n): return _Any
for n in ["fastmcp.exceptions", "fastmcp.server", "fastmcp.server.dependencies", "fastmcp.tools", "fastmcp.resources", "fastmcp.prompts", "fastmcp.utilities", "fastmcp.utilities.types"]:
    sys.modules[n] = _AnyModule(n)
Image = _Any
