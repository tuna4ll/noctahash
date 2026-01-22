use crate::{BLOCK_SIZE, WORDS_PER_BLOCK};

#[derive(Clone, Debug)]
pub struct NoctaBlock {
    data: [u8; BLOCK_SIZE],
}

impl NoctaBlock {
    pub fn new() -> Self {
        Self {
            data: [0u8; BLOCK_SIZE],
        }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut block = Self::new();
        let len = data.len().min(BLOCK_SIZE);
        block.data[..len].copy_from_slice(&data[..len]);
        block
    }

    pub fn from_words(words: &[u32]) -> Self {
        let mut block = Self::new();
        let len = words.len().min(WORDS_PER_BLOCK);
        for (i, &word) in words.iter().take(len).enumerate() {
            let offset = i * 4;
            block.data[offset] = (word & 0xFF) as u8;
            block.data[offset + 1] = ((word >> 8) & 0xFF) as u8;
            block.data[offset + 2] = ((word >> 16) & 0xFF) as u8;
            block.data[offset + 3] = ((word >> 24) & 0xFF) as u8;
        }
        block
    }

    pub fn get_word(&self, index: usize) -> u32 {
        if index >= WORDS_PER_BLOCK {
            return 0;
        }
        let offset = index * 4;
        (self.data[offset] as u32)
            | ((self.data[offset + 1] as u32) << 8)
            | ((self.data[offset + 2] as u32) << 16)
            | ((self.data[offset + 3] as u32) << 24)
    }

    pub fn set_word(&mut self, index: usize, value: u32) {
        if index >= WORDS_PER_BLOCK {
            return;
        }
        let offset = index * 4;
        self.data[offset] = (value & 0xFF) as u8;
        self.data[offset + 1] = ((value >> 8) & 0xFF) as u8;
        self.data[offset + 2] = ((value >> 16) & 0xFF) as u8;
        self.data[offset + 3] = ((value >> 24) & 0xFF) as u8;
    }

    pub fn xor(&self, other: &NoctaBlock) -> NoctaBlock {
        let mut result = Self::new();
        for i in 0..BLOCK_SIZE {
            result.data[i] = self.data[i] ^ other.data[i];
        }
        result
    }

    pub fn xor_inplace(&mut self, other: &NoctaBlock) {
        for i in 0..BLOCK_SIZE {
            self.data[i] ^= other.data[i];
        }
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn secure_zero(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.data);
    }
}

impl Default for NoctaBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoctaBlock {
    fn drop(&mut self) {
        self.secure_zero();
    }
}
