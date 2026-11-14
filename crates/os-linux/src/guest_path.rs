// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ゲストのパス文字列をホストのファイルシステム位置へ写す補助。
//!
//! `join_guest_path` はゲスト cwd 起点の連結、`resolve_guest_path` は
//! その上にゲストルート閉じ込め（chroot 相当）を重ねる。`..` でルートを
//! 抜ける解釈は拒否して `None` を返す。シンボリックリンク自体の解釈は
//! 各パーソナリティが持つ（絶対ターゲットはここへ回す）。

/// ゲスト cwd 相対で連結する。`path` が絶対か `cwd` が空なら `path` をそのまま返す。
pub fn join_guest_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') || cwd.is_empty() {
        return path.to_string();
    }
    if cwd == "/" {
        return format!("/{path}");
    }
    format!("{}/{}", cwd.trim_end_matches('/'), path)
}

/// ゲストパスをホストパスへ写す。`root` が空なら `join_guest_path` と同じ
/// （ルート閉じ込めなし）。`..` で `root` を上に抜ける解釈は `None`。
/// Ref: SRC-LINUX (7.3) の `fs/namei.c` 相当のパス正規化。
pub fn resolve_guest_path(root: &str, cwd: &str, path: &str) -> Option<String> {
    if root.is_empty() {
        return Some(join_guest_path(cwd, path));
    }
    let joined = join_guest_path(cwd, path);
    let mut parts: Vec<&str> = Vec::new();
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(comp),
        }
    }
    let root_trim = root.trim_end_matches('/');
    let mut out = String::from(root_trim);
    for part in parts {
        out.push('/');
        out.push_str(part);
    }
    Some(out)
}

/// `resolve_guest_path` にシンボリックリンクの追跡を重ねる。
///
/// 逐次ゲスト側のパス文字列を辿り、各段で `resolve_guest_path` へ写す。
/// リンクのターゲットが `/` で始まるならゲストの絶対パスとして root へ
/// 結び直す（chroot と同じ規則）。相対ターゲットはリンクの置かれたゲスト側
/// ディレクトリを基点に連結する。`..` が root を上に抜ける解釈は各段の
/// `resolve_guest_path` が拒否する。ループは 40 段で打ち切る。
pub fn resolve_guest_path_links(root: &str, cwd: &str, path: &str) -> Option<String> {
    let mut guest = join_guest_path(cwd, path);
    if !guest.starts_with('/') {
        guest = format!("/{guest}");
    }
    for _ in 0..40 {
        let host = resolve_guest_path(root, "/", &guest)?;
        let Ok(target) = std::fs::read_link(&host) else {
            return Some(host);
        };
        let t = target.to_string_lossy();
        if t.starts_with('/') {
            guest = t.into_owned();
        } else {
            // リンクの置かれたゲスト側ディレクトリが基点。`/a/b` の親は `/a`。
            let parent = match guest.rsplit_once('/') {
                Some(("", _)) | None => "/",
                Some((p, _)) => p,
            };
            guest = join_guest_path(parent, &t);
        }
    }
    resolve_guest_path(root, "/", &guest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_matches_join_without_root() {
        // root 空は join と同じ結果。振る舞い不変の担保。
        for (cwd, path) in [
            ("", "/etc/passwd"),
            ("", "rel"),
            ("/", "/etc/passwd"),
            ("/", "rel"),
            ("/a/b", "c"),
            ("/a/b", "/etc/passwd"),
            ("/a/b/", "c"),
        ] {
            assert_eq!(
                resolve_guest_path("", cwd, path),
                Some(join_guest_path(cwd, path)),
                "cwd={cwd:?} path={path:?}",
            );
        }
    }

    #[test]
    fn resolve_confines_under_root() {
        assert_eq!(
            resolve_guest_path("/jail", "/", "/etc/passwd"),
            Some("/jail/etc/passwd".to_string())
        );
        assert_eq!(
            resolve_guest_path("/jail/", "/a", "b/../c"),
            Some("/jail/a/c".to_string())
        );
        assert_eq!(resolve_guest_path("/jail", "/", ".."), None,);
        assert_eq!(resolve_guest_path("/jail", "/", "/../x"), None,);
        assert_eq!(resolve_guest_path("/jail", "/a", "../../x"), None,);
        assert_eq!(
            resolve_guest_path("/jail", "/", "."),
            Some("/jail".to_string()),
        );
    }
}
