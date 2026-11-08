//! デコードキャッシュとジャンプキャッシュ。ブロックキーで引く。
//!
//! デコード済みステップの中身は意味論の結び付けの後に足す。
//! ここでは登録、検索、無効化の枠だけを提供する。

use super::BlockKey;
use std::collections::HashMap;

/// キャッシュされたブロックの殻。`len` はステップ数。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CachedBlock {
    pub key: BlockKey,
    pub len: u32,
}

/// ブロックの表と、仮想アドレスからの直接写像の表。
#[derive(Debug, Default)]
pub struct BlockCache {
    blocks: HashMap<BlockKey, CachedBlock>,
    jumps: HashMap<(u64, u32, u64), BlockKey>,
}

impl BlockCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ブロックを登録する。
    pub fn insert_block(&mut self, block: CachedBlock) {
        self.blocks.insert(block.key, block);
    }

    /// ブロックキーで引く。
    #[must_use]
    pub fn get_block(&self, key: &BlockKey) -> Option<CachedBlock> {
        self.blocks.get(key).copied()
    }

    /// ジャンプキャッシュに登録する。鍵は仮想アドレス、実行モード、CPU モデルの世代である。
    pub fn insert_jump(&mut self, virt: u64, mode: u32, model_gen: u64, key: BlockKey) {
        self.jumps.insert((virt, mode, model_gen), key);
    }

    /// ジャンプキャッシュを引く。
    #[must_use]
    pub fn get_jump(&self, virt: u64, mode: u32, model_gen: u64) -> Option<BlockKey> {
        self.jumps.get(&(virt, mode, model_gen)).copied()
    }

    /// ページフレームを含むブロックと、ジャンプキャッシュを無効化する。
    /// 自己書き換えコードと写像の変更で呼ぶ。
    pub fn invalidate_frame(&mut self, frame: u64) {
        self.blocks.retain(|k, _| k.frame != frame);
        self.jumps.retain(|_, k| k.frame != frame);
    }

    /// CPU モデルの世代が変わったときの無効化。該当する世代だけを消す。
    pub fn invalidate_model(&mut self, model_gen: u64) {
        self.blocks.retain(|k, _| k.model_gen != model_gen);
        self.jumps.retain(|(_, _, g), _| *g != model_gen);
    }

    /// すべて無効化する。
    pub fn invalidate_all(&mut self) {
        self.blocks.clear();
        self.jumps.clear();
    }

    /// 登録されているブロック数。
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(frame: u64, generation: u64) -> BlockKey {
        BlockKey {
            frame,
            offset: 0,
            mode: 0,
            model_gen: generation,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut c = BlockCache::new();
        let k = key(1, 0);
        c.insert_block(CachedBlock { key: k, len: 4 });
        assert_eq!(c.get_block(&k).map(|b| b.len), Some(4));
        c.insert_jump(0x1000, 0, 0, k);
        assert_eq!(c.get_jump(0x1000, 0, 0), Some(k));
        assert_eq!(c.get_jump(0x1000, 0, 1), None);
    }

    #[test]
    fn invalidate_frame_keeps_others() {
        let mut c = BlockCache::new();
        c.insert_block(CachedBlock {
            key: key(1, 0),
            len: 1,
        });
        c.insert_block(CachedBlock {
            key: key(2, 0),
            len: 1,
        });
        c.insert_jump(0x1000, 0, 0, key(1, 0));
        c.insert_jump(0x2000, 0, 0, key(2, 0));
        c.invalidate_frame(1);
        assert_eq!(c.block_count(), 1);
        assert_eq!(c.get_jump(0x1000, 0, 0), None);
        assert!(c.get_jump(0x2000, 0, 0).is_some());
    }

    #[test]
    fn invalidate_model() {
        let mut c = BlockCache::new();
        c.insert_block(CachedBlock {
            key: key(1, 0),
            len: 1,
        });
        c.insert_block(CachedBlock {
            key: key(1, 1),
            len: 1,
        });
        c.invalidate_model(0);
        assert_eq!(c.block_count(), 1);
    }
}
