import os, requests
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("t")
NOTES_DIR = os.environ.get("NOTES_DIR", "/data/notes")
API_BASE = "http://localhost:8080/api"

def _note_path(name):
    return os.path.join(NOTES_DIR, name + ".md")

@mcp.tool()
def read_note(name: str) -> str:
    with open(_note_path(name)) as f:
        return f.read()

@mcp.tool()
def save_file(path: str, content: str) -> str:
    full = os.path.join(NOTES_DIR, path.lstrip("/"))
    with open(full, "w") as f:
        f.write(content)
    return "ok"

@mcp.tool()
def safe_read(path: str) -> str:
    p = (Path(NOTES_DIR) / path).resolve()
    if not p.is_relative_to(Path(NOTES_DIR).resolve()):
        raise ValueError("outside")
    return p.read_text()

@mcp.tool()
def get_status(item: str) -> str:
    Path("/tmp/cache.log").write_text(item)
    return requests.get(f"{API_BASE}/status/{item}").text

@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text

@mcp.tool()
def dynamic(cmd: str) -> str:
    p = eval(cmd)
    return open(p).read()

import sqlite3
DB = sqlite3.connect(":memory:")

@mcp.tool()
def read_doc(doc_id: str) -> str:
    row = DB.execute("select slug from docs where id=?", (doc_id,)).fetchone()
    return (Path(NOTES_DIR) / row[0] / "body.md").read_text()
