---
title: "Panduan Pelatihan Anotator — Studi REC (RQ0/RQ1)"
subtitle: "Informatics Department, UIN Sunan Kalijaga · versi 1 November 2026"
---

# 1. Alur kerja (wajib urut)

1. Baca panduan ini (±30 menit).
2. Kerjakan **Latihan Kalibrasi** sesuai pasangan Anda: `Latihan_Kalibrasi_A.xlsx` untuk Pasangan A, `Latihan_Kalibrasi_B.xlsx` untuk Pasangan B. Ada 6 tool, sekitar 45 menit.
3. Cocokkan jawaban Anda dengan `Kunci_Latihan.xlsx`. Baca penjelasan untuk setiap jawaban yang berbeda. Kalau perlu, ulangi tool yang salah.
4. Kerjakan formulir sebenarnya: `Anotasi_A?_SchemaOnly.xlsx` atau `Anotasi_B?_Kode.xlsx`, berisi 60 tool. Boleh dicicil; catat waktu mulai dan selesai di kolom Catatan baris terakhir.
5. **Jangan berdiskusi** dengan anotator lain dan jangan melihat file mereka sampai semua orang selesai.

Tool di latihan sengaja **berbeda** dari 60 tool di formulir. Kunci latihan tidak membantu menjawab formulir; tujuannya menyamakan cara berpikir.

# 2. Apa yang sedang kita ukur

Agen AI memanggil *tool* MCP, misalnya `read_note(name)`. Pertanyaan kita: **file atau host apa yang benar-benar disentuh tool itu?** Kita juga ingin tahu apakah objek itu sesuai dengan yang dijanjikan nama, parameter, dan deskripsinya.

- **Pasangan A (schema saja)** menjawab: *"Dari nama, parameter, deskripsi, dan README saja, objek apa yang saya harapkan disentuh?"* Jangan membuka kode.
- **Pasangan B (kode)** menjawab: *"Dari kodenya, objek apa yang benar-benar disentuh?"* Ikuti fungsi tool sampai ke operasi file/HTTP, termasuk lewat fungsi pembantu (helper).

Perbedaan jawaban A dan B itulah yang disebut **divergensi**. Jadi A tidak boleh "menebak isi kode", dan B tidak boleh "menebak dari deskripsi".

# 3. Mengenali tool MCP di kode (Pasangan B)

Tool Python biasanya ditandai dekorator:

```python
@mcp.tool()                 # atau @mcp.tool, @server.tool(), @app.tool()
def read_note(name: str) -> str:
    """Read a note by name."""     # ← deskripsi (docstring)
    ...
```

- **Parameter** adalah argumen fungsi (`name`). `ctx`/`context` bukan argumen dari agen, jadi abaikan.
- **Operasi sensitif** yang dicari: membaca/menulis/menghapus/mendaftar file, dan permintaan HTTP.

| Kode yang dicari | Jenis operasi |
|---|---|
| `open(p)`, `open(p, "r")`, `Path(p).read_text()`, `read_bytes()` | fs.read |
| `open(p, "w"/"a"/"x")`, `write_text`, `write_bytes`, `mkdir`, `os.makedirs`, `touch`, `shutil.copy/move` (tujuan), `os.rename/replace` | fs.write |
| `os.remove`, `os.unlink`, `Path.unlink`, `shutil.rmtree`, `rmdir` | fs.delete |
| `os.listdir`, `os.scandir`, `Path.iterdir`, `glob` | fs.list |
| `requests.get/post/...`, `httpx...`, `client.get(url)`, `urlopen` | http.request |

**Menelusuri helper.** Jika tool memanggil `ncbi_client.get_related_articles(...)`, buka definisi fungsi itu. Di GitHub: klik nama fungsi, atau tekan `t`/`/` lalu cari `def get_related_articles`. Telusuri **paling dalam 3 tingkat**. Kalau lebih dalam, tulis di Catatan.

# 4. Menulis relasi objek

Relasi menjawab: *untuk nilai argumen apa pun, objek mana yang mungkin disentuh?*

| Konstruktor | Artinya | Contoh kode → relasi |
|---|---|---|
| `arg(x)` | Nilai argumen `x` apa adanya | `open(path)` → `arg(path)` |
| `cfg(N)` | Konfigurasi/konstanta/variabel lingkungan bernama N | `NOTES_DIR = os.getenv(...)` → `cfg(NOTES_DIR)` |
| `const('…')` | Nilai tetap di kode | `"main.typ"` → `const('main.typ')` |
| `join(a, b, …)` | Path/URL yang digabung | `os.path.join(NOTES_DIR, name + ".md")` → `join(cfg(NOTES_DIR), arg(name), const('.md'))` |
| `under(d)` | Objek apa pun di bawah folder d | `for f in Path(d).glob("*.cache")` → `under(cfg(d))` |
| `stored(d)` | Objek di bawah folder d, namanya diambil dari data tersimpan (DB/indeks/hash) | `Path(CACHE)/f"{md5(q)}.cache"` → `stored(cfg(CACHE))` |
| `union(a, b)` | Salah satu dari beberapa kemungkinan (if/else) | `p = a if x else b` → `union(…, …)` |

Untuk **HTTP**, cukup tulis host dan pola path. Contoh: `requests.get(f"{BASE}/event-types")` dengan `BASE = "https://api.cal.com/v2"` → `join(const('https://api.cal.com/v2'), const('/event-types'))`.

**Bisa diekspresikan?** Tulis *Tidak* kalau objeknya ditentukan oleh hal yang tidak cocok dengan konstruktor di atas, misalnya `eval`, nama dari loop dinamis, atau path yang dibangun dari hasil perintah lain. Tetap jelaskan di Catatan.

**Nilai sementara.** `tempfile.mkdtemp()`/`mkstemp()` → tulis `cfg(tempdir)`. Contoh: `join(cfg(tempdir), const('main.typ'))`.

# 5. Menentukan "tersirat dari deskripsi/schema" (Pasangan B)

Tanya: *"Seandainya saya hanya membaca nama, parameter, dan deskripsi, apakah saya akan menduga objek ini disentuh?"*

- **Ya**: deskripsi atau parameter jelas menyebutnya. Contoh: `receipt_path: Where to create the receipt JSON` → menulis ke `arg(receipt_path)`.
- **Sebagian**: jenisnya tersirat tetapi objek persisnya tidak. Contoh: tool "search" yang juga menulis cache.
- **Tidak**: tidak ada petunjuk sama sekali. Contoh: tool `get_*` yang ternyata menghapus file.

# 6. Sifat divergensi (Pasangan B)

| Pilihan | Gunakan bila |
|---|---|
| Tidak ada divergensi | Objek tersirat dari deskripsi/schema |
| Benign-by-design | Objek tambahan wajar dan terbatas di area milik tool: cache, log, lock, folder kerja/temp milik tool |
| Relevan keamanan | Objek tambahan di luar area tool, menyentuh rahasia/kredensial/konfigurasi, menghapus data pengguna, atau mengirim data ke host yang tidak disebut |
| Tidak tahu | Ragu, dan jelaskan di Catatan |

Path dari argumen **tanpa pembatasan folder** (misalnya `Path(receipt_path)` langsung) **bukan divergensi** kalau deskripsinya memang meminta path. Tetap tulis relasinya `arg(...)`, lalu catat "tanpa pembatasan folder" di Catatan.

# 7. Keyakinan (1–5)

5 = yakin penuh · 4 = hampir yakin · 3 = cukup · 2 = ragu · 1 = tebakan. Nilai rendah tidak dihukum dan justru membantu analisis.

# 8. Pertanyaan yang sering muncul

- **Tool tanpa operasi file/HTTP?** Pasangan B mengisi satu baris: Jenis operasi kosong, Catatan "tidak ada operasi sensitif".
- **Lebih dari 3 operasi?** Sisipkan baris (klik kanan → Insert) dengan ID yang sama.
- **Operasi di dalam `try/except` atau cabang `if`?** Tetap dihitung, karena operasi itu *mungkin* terjadi.
- **Kode di folder `tests/`, `scripts/`, `examples/`?** Abaikan; bukan bagian tool yang dirilis.
- **Boleh bertanya ke Claude?** Boleh untuk **konsep**, misalnya "apa arti `Path.resolve()`?" atau "bagaimana menulis relasi untuk if/else?". **Jangan** meminta jawaban untuk tool tertentu di formulir, karena itu membuat data tidak independen.

# 9. Kartu ringkas

**A:** baca nama + parameter + deskripsi + README → tulis objek yang *diharapkan*.
**B:** buka kode → ikuti sampai `open`/`Path`/`os`/`shutil`/`requests` → tulis objek yang *sebenarnya*, lalu nilai: tersirat? divergensi?
**Relasi:** `arg` · `cfg` · `const` · `join` · `under` · `stored` · `union`.
