# 4.3BSD 形式（NFS_MAGIC 60012、1KB レコード）の dump 展開パーサ。
# BIN-DISTRO-BSD43RENO の rootdump.gz（dump(8) 形式。現行の restore(8) では
# 読めないため自前で復元する）からファイル木を取り出し、
# .testdata/bin-distro-bsd43reno/ の入力として使う。
# 使い方: python3 tools/testdata/bsd-dump-extract.py <rootdump.gz> <出力先>
import struct, gzip, os, sys

BLK = 1024
TS_INODE, TS_END, TS_ADDR = 2, 3, 4
MAGIC = (60011, 60012)


def main(src, outroot):
    data = gzip.open(src, 'rb').read()
    nrec = len(data) // BLK

    def is_hdr(b):
        return len(b) >= 32 and struct.unpack_from('<i', b, 24)[0] in MAGIC

    files = {}
    i = 0
    while i < nrec:
        b = data[i * BLK:(i + 1) * BLK]
        if not is_hdr(b) or struct.unpack_from('<i', b, 0)[0] != TS_INODE:
            i += 1
            continue
        ino = struct.unpack_from('<I', b, 20)[0]
        dinode = b[32:160]
        mode = struct.unpack_from('<H', dinode, 0)[0]
        size = struct.unpack_from('<I', dinode, 8)[0]
        i += 1
        while i < nrec:
            b2 = data[i * BLK:(i + 1) * BLK]
            if is_hdr(b2) and struct.unpack_from('<i', b2, 0)[0] == TS_ADDR:
                i += 1
            else:
                break
        buf = bytearray()
        need = (size + BLK - 1) // BLK
        while len(buf) < need * BLK and i < nrec:
            b2 = data[i * BLK:(i + 1) * BLK]
            if is_hdr(b2) and struct.unpack_from('<i', b2, 0)[0] in (TS_INODE, TS_END):
                break
            buf.extend(b2)
            i += 1
        files[ino] = (mode, size, bytes(buf[:size]))

    DIR, LNK, REG = 0o040000, 0o120000, 0o100000

    def dirents(buf):
        out, off = [], 0
        while off + 8 <= len(buf):
            ino, reclen, nlen = struct.unpack_from('<IHH', buf, off)
            if reclen < 8 or off + reclen > len(buf):
                break
            out.append((ino, buf[off + 8:off + 8 + nlen].split(b'\0')[0]))
            off += reclen
        return out

    def walk(ino, path):
        e = files.get(ino)
        if not e or (e[0] & 0o170000) != DIR:
            return
        for cino, name in dirents(e[2]):
            if name in (b'.', b'..'):
                continue
            nm = name.decode('ascii', 'replace')
            p = path + '/' + nm
            cf = files.get(cino)
            if not cf:
                continue
            kind = cf[0] & 0o170000
            if kind == DIR:
                walk(cino, p)
                continue
            # 正規ファイルのみ書き出す。デバイスノードはデータブロックを
            # 持たないため対象外、シンボリックリンクは link として張る。
            out = outroot + p
            os.makedirs(os.path.dirname(out), exist_ok=True)
            if kind == REG:
                open(out, 'wb').write(cf[2])
            elif kind == LNK:
                try:
                    os.symlink(cf[2].decode('ascii', 'replace'), out)
                except FileExistsError:
                    pass

    walk(2, '')
    print(len(files), 'inodes')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
