"""スキャン PDF 資料の取得・ページ画像化・テキスト層トリアージ。

用途: bitsavers 等のスキャン PDF を .cache/sources/<id>/ に置き、
ページ画像（PNG）とテキスト層の有無の判定を行う。事実確認は
エージェントがページ画像を視覚的に読む方式で、OCR は使わない。

使い方:
  pdfsrc.py fetch <id> <url>     # 取得（sha256 を表示）
  pdfsrc.py info <id>            # ページ数とテキスト層の品質を表示
  pdfsrc.py render <id> [p1,p2]  # ページを PNG 化（省略時は全ページ）
  pdfsrc.py text <id> <page>     # テキスト層があれば表示
"""
import hashlib
import os
import sys
import urllib.request

import pymupdf as fitz

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
CACHE = os.path.join(ROOT, ".cache", "sources")


def pdf_path(id_: str) -> str:
    return os.path.join(CACHE, id_, "source.pdf")


def cmd_fetch(id_: str, url: str) -> None:
    d = os.path.join(CACHE, id_)
    os.makedirs(d, exist_ok=True)
    out = pdf_path(id_)
    if not os.path.exists(out):
        # bitsavers 等は既定の UA を弾くためブラウザ名乗りで取る
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as r, open(out, "wb") as f:
            f.write(r.read())
    h = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print(f"{id_}: {out} sha256 {h}")


def open_pdf(id_: str):
    return fitz.open(pdf_path(id_))


def cmd_info(id_: str) -> None:
    doc = open_pdf(id_)
    layers = []
    for i in range(len(doc)):
        t = doc[i].get_text().strip()
        layers.append(len(t))
    have = sum(1 for n in layers if n > 50)
    print(f"{id_}: {len(doc)} ページ、テキスト層あり {have} ページ")
    if len(doc) and have == 0:
        print("  画像のみのスキャン。render で画像化して視覚的に読む")


def cmd_render(id_: str, pages: str = "") -> None:
    doc = open_pdf(id_)
    d = os.path.join(CACHE, id_, "pages")
    os.makedirs(d, exist_ok=True)
    sel = range(len(doc)) if not pages else [int(p) - 1 for p in pages.split(",")]
    for i in sel:
        out = os.path.join(d, f"p{i + 1:03d}.png")
        if not os.path.exists(out):
            pix = doc[i].get_pixmap(dpi=200)
            pix.save(out)
        print(out)


def cmd_text(id_: str, page: str) -> None:
    doc = open_pdf(id_)
    print(doc[int(page) - 1].get_text())


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "fetch":
        cmd_fetch(sys.argv[2], sys.argv[3])
    elif cmd == "info":
        cmd_info(sys.argv[2])
    elif cmd == "render":
        cmd_render(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif cmd == "text":
        cmd_text(sys.argv[2], sys.argv[3])
