from fastmcp import FastMCP
from .paths import note_path
from . import other
mcp = FastMCP("x")
@mcp.tool
def read_note(name: str) -> str:
    return open(note_path(name)).read()
@mcp.tool
def write_note(name: str, data: str) -> str:
    other.save(note_path(name), data)
    return "ok"
