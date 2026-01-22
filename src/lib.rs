pub mod block;
pub mod core;
pub mod utils;

pub use core::{noctahash, verify, NoctaHashCore};
pub use block::NoctaBlock;

pub const VERSION: u32 = 1;

pub const BLOCK_SIZE: usize = 1024;

pub const WORDS_PER_BLOCK: usize = 256;

pub const SYNC_POINTS: usize = 4;

pub const MIN_MEMORY_KB: usize = 8;

pub const MIN_TIME_COST: u32 = 1;

pub const MAX_TIME_COST: u32 = 1 << 24;

pub const MAX_PARALLELISM: u32 = 255;

pub const HASH_OUTPUT_LEN: usize = 32;

pub const ROTATION_CONSTANTS: [u32; 4] = [16, 12, 8, 7];
