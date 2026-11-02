"""Build independent annotation workbooks for RQ0/RQ1.

Pair A (schema-only): sees tool name, parameters, docstring and the README link,
never code. Pair B (code): sees tool name and source location, never analyzer
output. One workbook per annotator, so the two members of a pair cannot see
each other's answers. A private key file maps IDs to analyzer output for the
researchers only.
"""
import json
import os
import random
import re
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.utils import get_column_letter

SEED, N, PER_REPO = 20261103, 60, 3
static = json.load(open("results/expanded_raw_v2.json"))
rows = json.load(open("py_local.json"))
sub = {}
for sec, name, url, *_ in rows:
    m = re.match(r"https://github.com/([^/]+)/([^/#?]+)(?:/tree/[^/]+/(.*))?", url)
    if m:
        sub.setdefault(f"{m.group(1)}/{m.group(2)}", m.group(3))

cands = []
for r in static:
    for t in r["tools"]:
        if t["n_sites"]:
            cands.append((r["repo"], r["commit"], t))
rng = random.Random(SEED)
rng.shuffle(cands)
picked, per = [], {}
for repo, commit, t in cands:
    if per.get(repo, 0) >= PER_REPO:
        continue
    per[repo] = per.get(repo, 0) + 1
    picked.append((repo, commit, t))
    if len(picked) == N:
        break
picked.sort(key=lambda x: (x[0], x[2]["tool"]))

ARIAL = "Arial"
H = Font(name=ARIAL, bold=True, color="FFFFFF", size=10)
HF = PatternFill("solid", start_color="1F3864")
INF = PatternFill("solid", start_color="FFF2CC")   # cells annotators fill in
B = Font(name=ARIAL, size=10)
thin = Side(style="thin", color="BFBFBF")
BD = Border(left=thin, right=thin, top=thin, bottom=thin)
WR = Alignment(wrap_text=True, vertical="top")

GUIDE_COMMON = [
    ("Tujuan", "Anotasi ini membuat ground truth untuk studi REC. Kerjakan sendiri; jangan berdiskusi dengan anotator lain sampai semua baris selesai."),
    ("Bahasa relasi", "Tulis objek yang disentuh tool dengan konstruktor: arg(x) = nilai argumen x; cfg(N) = konfigurasi/konstanta N; const('...') = nilai tetap; join(a, b) = gabungan path/URL; under(d) = objek apa pun di bawah folder d; stored(d) = objek di bawah folder d yang namanya diambil dari data tersimpan (DB/indeks); union(a, b) = salah satu. Contoh: join(cfg(NOTES_DIR), arg(name), const('.md'))."),
    ("Jenis operasi", "fs.read, fs.write, fs.delete, fs.list, http.request. Satu baris per operasi/objek yang berbeda."),
    ("Sel kuning", "Hanya sel berlatar kuning yang diisi. Kolom lain jangan diubah."),
    ("Ragu-ragu", "Jika tidak yakin, tetap isi tebakan terbaik dan beri Keyakinan rendah (1–2) serta catatan."),
    ("Waktu", "Perkiraan 5–8 menit per tool. Total sekitar 5–8 jam per anotator; boleh dicicil."),
]
GUIDE_A = [("Peran Anda: Pasangan A (schema saja)",
            "Anda HANYA boleh membaca nama tool, parameter, deskripsi di lembar ini, dan README repositori (tautan disediakan). JANGAN membuka file kode sumber. Pertanyaan: 'Berdasarkan informasi ini saja, file atau host apa yang akan disentuh tool ini, untuk nilai argumen apa pun?'")]
GUIDE_B = [("Peran Anda: Pasangan B (kode)",
            "Buka file sumber pada commit yang ditautkan. Telusuri fungsi tool dan helper yang dipanggilnya. Untuk setiap operasi file/HTTP yang dapat dijangkau, isi satu baris: lokasi (file:baris), jenis operasi, relasi objek, apakah bisa diekspresikan dengan bahasa relasi, apakah objek itu tersirat dari deskripsi/schema, dan apakah divergensinya disengaja (benign-by-design, mis. cache/log/lock yang terdokumentasi) atau relevan keamanan. Tersedia 3 baris per tool; sisipkan baris jika perlu.")]


def guide_sheet(wb, extra):
    g = wb.active
    g.title = "Panduan"
    g.column_dimensions["A"].width = 30
    g.column_dimensions["B"].width = 110
    g["A1"] = "Panduan Anotasi REC (RQ0/RQ1)"
    g["A1"].font = Font(name=ARIAL, bold=True, size=13)
    r = 3
    for k, v in extra + GUIDE_COMMON:
        g.cell(r, 1, k).font = Font(name=ARIAL, bold=True, size=10)
        c = g.cell(r, 2, v)
        c.font = B
        c.alignment = WR
        r += 1
    g.cell(r + 1, 1, "Contoh baris terisi").font = Font(name=ARIAL, bold=True, size=10)
    g.cell(r + 1, 2, "Tool read_note(name): fs.read | join(cfg(NOTES_DIR), arg(name), const('.md')) | Ya (bisa diekspresikan) | Tersirat dari deskripsi: Ya | Keyakinan 5").font = B


def header(ws, cols, widths):
    ws.append(cols)
    for c in ws[1]:
        c.font = H
        c.fill = HF
        c.alignment = Alignment(wrap_text=True, vertical="center")
        c.border = BD
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "C2"


def dv(ws, formula, rng_):
    v = DataValidation(type="list", formula1=formula, allow_blank=True)
    ws.add_data_validation(v)
    v.add(rng_)


def gh(repo, commit, path=""):
    s = sub.get(repo) or ""
    p = "/".join(x for x in (s, path) if x)
    return f"https://github.com/{repo}/blob/{commit}/{p}" if p else f"https://github.com/{repo}/tree/{commit}"


def build_A(name):
    wb = Workbook()
    guide_sheet(wb, GUIDE_A)
    ws = wb.create_sheet("Anotasi_A")
    cols = ["ID", "Repo", "Tool", "Parameter", "Deskripsi (docstring baris pertama)", "README (commit)",
            "Jenis operasi yang diharapkan", "Relasi objek yang diharapkan", "Menyentuh objek yang tidak disebut argumen?", "Keyakinan (1-5)", "Catatan"]
    header(ws, cols, [8, 26, 22, 26, 44, 14, 22, 46, 18, 11, 30])
    for i, (repo, commit, t) in enumerate(picked, 1):
        ws.append([f"T{i:03d}", repo, t["tool"], ", ".join(t["params"]), t["doc"] or "(tidak ada deskripsi)",
                   "Buka README", "", "", "", "", ""])
        r = ws.max_row
        c = ws.cell(r, 6)
        c.hyperlink = gh(repo, commit, "README.md")
        c.font = Font(name=ARIAL, size=10, color="0563C1", underline="single")
        for col in range(1, 12):
            cell = ws.cell(r, col)
            cell.border = BD
            cell.alignment = WR
            if col != 6:
                cell.font = B
            if col >= 7:
                cell.fill = INF
    n = ws.max_row
    dv(ws, '"Ya,Tidak,Tidak tahu"', f"I2:I{n}")
    dv(ws, '"1,2,3,4,5"', f"J2:J{n}")
    wb.save(name)


def build_B(name):
    wb = Workbook()
    guide_sheet(wb, GUIDE_B)
    ws = wb.create_sheet("Anotasi_B")
    cols = ["ID", "Repo", "Tool", "File tool (commit)", "Lokasi operasi (file:baris)", "Jenis operasi", "Relasi objek",
            "Bisa diekspresikan?", "Tersirat dari deskripsi/schema?", "Sifat divergensi", "Keyakinan (1-5)", "Catatan"]
    header(ws, cols, [8, 26, 22, 18, 24, 14, 46, 13, 16, 20, 11, 30])
    for i, (repo, commit, t) in enumerate(picked, 1):
        for k in range(3):
            ws.append([f"T{i:03d}", repo, t["tool"], "Buka file" if k == 0 else "", "", "", "", "", "", "", "", ""])
            r = ws.max_row
            if k == 0:
                c = ws.cell(r, 4)
                c.hyperlink = gh(repo, commit, t["file"])
                c.font = Font(name=ARIAL, size=10, color="0563C1", underline="single")
            for col in range(1, 13):
                cell = ws.cell(r, col)
                cell.border = BD
                cell.alignment = WR
                if col != 4:
                    cell.font = B
                if col >= 5:
                    cell.fill = INF
    n = ws.max_row
    dv(ws, '"fs.read,fs.write,fs.delete,fs.list,http.request"', f"F2:F{n}")
    dv(ws, '"Ya,Tidak"', f"H2:H{n}")
    dv(ws, '"Ya,Tidak,Sebagian"', f"I2:I{n}")
    dv(ws, '"Tidak ada divergensi,Benign-by-design,Relevan keamanan,Tidak tahu"', f"J2:J{n}")
    dv(ws, '"1,2,3,4,5"', f"K2:K{n}")
    wb.save(name)


os.makedirs("annotation", exist_ok=True)
build_A("annotation/Anotasi_A1_SchemaOnly.xlsx")
build_A("annotation/Anotasi_A2_SchemaOnly.xlsx")
build_B("annotation/Anotasi_B1_Kode.xlsx")
build_B("annotation/Anotasi_B2_Kode.xlsx")
key = [{"id": f"T{i:03d}", "repo": repo, "commit": commit, "tool": t["tool"], "file": t["file"], "params": t["params"]}
       for i, (repo, commit, t) in enumerate(picked, 1)]
json.dump({"seed": SEED, "n": len(key), "per_repo_cap": PER_REPO, "tools": key}, open("annotation/KUNCI_peneliti_saja.json", "w"), indent=1)
print("tools", len(key), "repos", len({k['repo'] for k in key}))
