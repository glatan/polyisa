# pdfsrc — スキャン PDF 資料の読み取りパイプライン

bitsavers 等の画像スキャン PDF を、事実確認に使える形にする。

## 仕組み

1. `fetch`: PDF を `.cache/sources/<id>/source.pdf` に取得（sha256 を表示。
   著作権上リポジトリには入れず、`.cache/` は gitignore 済み）
2. `info`: ページ数とテキスト層の有無を判定。テキスト層があれば
   `text` で grep 的にページを特定できる
3. `render`: ページを 200 DPI の PNG 化（`.cache/sources/<id>/pages/pNNN.png`）
4. 事実の読み取りは OCR ではなく、エージェントがページ画像を `read`
   で視覚的に読む。タイプライタ字体・表組みに強く、前文の著作権表記の
   verbatim 確認（台帳の権利欄の要件）も画像直読みで確定する

## 使い方

    sh tools/pdfsrc/setup.sh   # venv + PyMuPDF（初回のみ）
    V=.cache/pdfsrc-venv/bin/python
    $V tools/pdfsrc/pdfsrc.py fetch <id> <url>
    $V tools/pdfsrc/pdfsrc.py info <id>
    $V tools/pdfsrc/pdfsrc.py render <id> [ページ,…]
    $V tools/pdfsrc/pdfsrc.py text <id> <ページ>

補助: bitsavers の画像のみスキャンと同じ冊子が archive.org にある場合、
OCR 層つきで品質が良いことがある。同じ版ならそちらを優先してよい。
