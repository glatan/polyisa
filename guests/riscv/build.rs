//! `spec/` の ISADL 記述からコードを生成する。記述自体は参照資料の確認後に書く。

fn main() {
    // ISADL 記述の変更で再生成するための監視指定。生成本体は後の段階で足す。
    println!("cargo::rerun-if-changed=spec/");
}
