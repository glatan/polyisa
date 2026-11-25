#!/bin/sh
# pdfsrc の実行環境（venv + PyMuPDF）を .cache/pdfsrc-venv に作る。
set -e
V=.cache/pdfsrc-venv
[ -x "$V/bin/python" ] || python3 -m venv "$V"
"$V/bin/pip" install -q pymupdf
echo "usage: .cache/pdfsrc-venv/bin/python tools/pdfsrc/pdfsrc.py {fetch|info|render|text} ..."
