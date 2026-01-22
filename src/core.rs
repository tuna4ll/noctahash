
use crate::block::NoctaBlock;
use crate::utils::*;
use crate::*;
use std::error::Error;
use std::sync::{Arc, Barrier};
use std::thread;
use constant_time_eq::constant_time_eq;

pub struct NoctaHashCore {
    time_cost: u32,
    memory_cost_mb: u32,
    #[allow(dead_code)]
    memory_cost_kb: u32,
    parallelism: u32,
    blocks_per_lane: usize,
    total_blocks: usize,
    segment_length: usize,
    memory: Vec<Vec<NoctaBlock>>,
    initial_hash: Vec<u8>,
    counter: u64,
}

impl NoctaHashCore {
    pub fn new(time_cost: u32, memory_cost_mb: u32, parallelism: u32) -> Result<Self, Box<dyn Error>> {
        if time_cost < MIN_TIME_COST {
            return Err(format!("time_cost must be >= {}", MIN_TIME_COST).into());
        }
        if time_cost > MAX_TIME_COST {
            return Err(format!("time_cost must be <= {}", MAX_TIME_COST).into());
        }
        if parallelism < 1 || parallelism > MAX_PARALLELISM {
            return Err(format!("parallelism must be in [1, {}]", MAX_PARALLELISM).into());
        }

        let memory_cost_kb = memory_cost_mb * 1024;
        if memory_cost_kb < MIN_MEMORY_KB as u32 {
            return Err(format!("memory_cost_mb must result in >= {} KB", MIN_MEMORY_KB).into());
        }

        let total_bytes = (memory_cost_mb as usize) * 1024 * 1024;
        let mut total_blocks = total_bytes / BLOCK_SIZE;

        let min_blocks = (parallelism as usize) * SYNC_POINTS;
        if total_blocks < min_blocks {
            total_blocks = min_blocks;
        }

        let blocks_per_lane = total_blocks / (parallelism as usize);
        let mut total_blocks = blocks_per_lane * (parallelism as usize);

        let actual_memory_mb = (total_blocks * BLOCK_SIZE) / (1024 * 1024);
        if actual_memory_mb < memory_cost_mb as usize {
            let additional_blocks = ((memory_cost_mb as usize * 1024 * 1024) - (total_blocks * BLOCK_SIZE) + BLOCK_SIZE - 1) / BLOCK_SIZE;
            total_blocks += additional_blocks;
        }

        let blocks_per_lane = total_blocks / (parallelism as usize);
        let segment_length = (blocks_per_lane / SYNC_POINTS).max(1);

        Ok(Self {
            time_cost,
            memory_cost_mb,
            memory_cost_kb,
            parallelism,
            blocks_per_lane,
            total_blocks,
            segment_length,
            memory: Vec::new(),
            initial_hash: Vec::new(),
            counter: 0,
        })
    }

    fn compute_initial_hash(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut h0_input = Vec::new();
        
        const DOMAIN_PARAMS: &[u8] = b"NoctaHash|params";
        const DOMAIN_PASSWORD: &[u8] = b"NoctaHash|pwd";
        const DOMAIN_SALT: &[u8] = b"NoctaHash|salt";
        const DOMAIN_META: &[u8] = b"NoctaHash|meta";
        
        h0_input.extend_from_slice(DOMAIN_PARAMS);
        h0_input.extend_from_slice(&int_to_bytes(self.parallelism, 4));
        h0_input.extend_from_slice(&int_to_bytes(self.time_cost, 4));
        h0_input.extend_from_slice(&int_to_bytes(self.memory_cost_mb, 4));
        
        h0_input.extend_from_slice(DOMAIN_PASSWORD);
        h0_input.extend_from_slice(&int_to_bytes(password.len() as u32, 4));
        h0_input.extend_from_slice(password);
        
        h0_input.extend_from_slice(DOMAIN_SALT);
        h0_input.extend_from_slice(&int_to_bytes(salt.len() as u32, 4));
        h0_input.extend_from_slice(salt);
        
        h0_input.extend_from_slice(DOMAIN_META);
        h0_input.extend_from_slice(&int_to_bytes(HASH_OUTPUT_LEN as u32, 4));
        h0_input.extend_from_slice(&int_to_bytes(VERSION, 4));

        h_prime(&h0_input, 64)
    }

    fn allocate_memory(&mut self) {
        self.memory = vec![
            vec![NoctaBlock::new(); self.blocks_per_lane];
            self.parallelism as usize
        ];
    }

    #[allow(dead_code)]
    fn internal_prf(&self, input: &[u8], output_len: usize) -> Vec<u8> {
        let mut words = Vec::new();
        for chunk in input.chunks(4) {
            let mut word_bytes = [0u8; 4];
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            words.push(bytes_to_int(&word_bytes));
        }
        
        while words.len() % 4 != 0 {
            words.push(0);
        }
        
        const PRF_ROUNDS: usize = 7;
        for _round in 0..PRF_ROUNDS {
            for i in (0..words.len()).step_by(4) {
                if i + 3 < words.len() {
                    let (a, b, c, d) = self.g_mixing_function(words[i], words[i+1], words[i+2], words[i+3]);
                    words[i] = a;
                    words[i+1] = b;
                    words[i+2] = c;
                    words[i+3] = d;
                }
            }
        }
        
        let mut result = Vec::new();
        for word in words.iter().take((output_len + 3) / 4) {
            result.extend_from_slice(&word.to_le_bytes());
        }
        
        result[..output_len.min(result.len())].to_vec()
    }

    #[allow(dead_code)]
    fn g_mixing_function(&self, a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        let mut a = a;
        let mut b = b;
        let mut c = c;
        let mut d = d;

        const ROUNDS: usize = 2; // Argon2id uses 2 rounds in Blake2b
        
        const ROTS: [u32; 4] = [16, 12, 8, 7];
        
        for round in 0..ROUNDS {
            let rot_idx = round & 3;
            let rot1 = ROTS[rot_idx];
            let rot2 = ROTS[(rot_idx + 1) & 3];
            let rot3 = ROTS[(rot_idx + 2) & 3];
            let rot4 = ROTS[(rot_idx + 3) & 3];

            a = mod_add(a, b);
            d = rotate_right(d ^ a, rot1);
            c = mod_add(c, d);
            b = rotate_right(b ^ c, rot2);

            a = mod_add(a, b);
            d = rotate_right(d ^ a, rot3);
            c = mod_add(c, d);
            b = rotate_right(b ^ c, rot4);
        }

        a ^= d;
        b ^= c;
        c = mod_add(c, a);
        d = mod_add(d, b);

        (a, b, c, d)
    }

    #[allow(dead_code)]
    fn compression_function(&self, block_x: &NoctaBlock, block_y: &NoctaBlock, counter: u64) -> NoctaBlock {
        let mut r = block_x.xor(block_y);

        for _round_num in 0..1 {
            for matrix_idx in 0..16 {
                let base = matrix_idx * 16;
                let mut state = [0u32; 16];
                
                for i in 0..16 {
                    state[i] = r.get_word(base + i);
                }

                let (s0, s4, s8, s12) = self.g_mixing_function(state[0], state[4], state[8], state[12]);
                state[0] = s0; state[4] = s4; state[8] = s8; state[12] = s12;

                let (s1, s5, s9, s13) = self.g_mixing_function(state[1], state[5], state[9], state[13]);
                state[1] = s1; state[5] = s5; state[9] = s9; state[13] = s13;

                let (s2, s6, s10, s14) = self.g_mixing_function(state[2], state[6], state[10], state[14]);
                state[2] = s2; state[6] = s6; state[10] = s10; state[14] = s14;

                let (s3, s7, s11, s15) = self.g_mixing_function(state[3], state[7], state[11], state[15]);
                state[3] = s3; state[7] = s7; state[11] = s11; state[15] = s15;

                let (s0, s5, s10, s15) = self.g_mixing_function(state[0], state[5], state[10], state[15]);
                state[0] = s0; state[5] = s5; state[10] = s10; state[15] = s15;

                let (s1, s6, s11, s12) = self.g_mixing_function(state[1], state[6], state[11], state[12]);
                state[1] = s1; state[6] = s6; state[11] = s11; state[12] = s12;

                let (s2, s7, s8, s13) = self.g_mixing_function(state[2], state[7], state[8], state[13]);
                state[2] = s2; state[7] = s7; state[8] = s8; state[13] = s13;

                let (s3, s4, s9, s14) = self.g_mixing_function(state[3], state[4], state[9], state[14]);
                state[3] = s3; state[4] = s4; state[9] = s9; state[14] = s14;

                let (s0, s7, s10, s13) = self.g_mixing_function(state[0], state[7], state[10], state[13]);
                state[0] = s0; state[7] = s7; state[10] = s10; state[13] = s13;

                let (s1, s4, s11, s14) = self.g_mixing_function(state[1], state[4], state[11], state[14]);
                state[1] = s1; state[4] = s4; state[11] = s11; state[14] = s14;

                for i in 0..16 {
                    r.set_word(base + i, state[i]);
                }
            }
        }

        for matrix_idx in 0..16 {
            let base = matrix_idx * 16;
            let mut state = [0u32; 16];
            
            for i in 0..16 {
                state[i] = r.get_word(base + i);
            }

            const MIX_ROUNDS: usize = 2; // Fixed, simple, proven
            
            for _mix_round in 0..MIX_ROUNDS {
                for col in 0..4 {
                    let idx0 = col;
                    let idx1 = col + 4;
                    let idx2 = col + 8;
                    let idx3 = col + 12;
                    
                    let (s0, s1, s2, s3) = self.g_mixing_function(
                        state[idx0], state[idx1], state[idx2], state[idx3]
                    );
                    state[idx0] = s0;
                    state[idx1] = s1;
                    state[idx2] = s2;
                    state[idx3] = s3;
                }
            }

            for i in 0..16 {
                r.set_word(base + i, state[i]);
            }
        }

        let counter_low = counter as u32;
        let counter_high = (counter >> 32) as u32;
        
        const COUNTER_ROT1: u32 = 16;
        const COUNTER_ROT2: u32 = 12;
        
        for i in (0..WORDS_PER_BLOCK).step_by(8) {
            let word = r.get_word(i);
            let mixed = mod_add(word, counter_low) ^ rotate_left(counter_high, COUNTER_ROT1);
            r.set_word(i, mixed);
            
            if i + 4 < WORDS_PER_BLOCK {
                let word2 = r.get_word(i + 4);
                let mixed2 = mod_add(word2, counter_high) ^ rotate_right(counter_low, COUNTER_ROT2);
                r.set_word(i + 4, mixed2);
            }
        }

        r
    }

    #[allow(dead_code)]
    fn compute_index_independent(&self, pass_num: u32, lane: u32, segment: usize, index: usize) -> (u32, usize) {
        let mut seed_input = Vec::new();
        seed_input.extend_from_slice(&int_to_bytes(pass_num, 4));
        seed_input.extend_from_slice(&int_to_bytes(lane, 4));
        seed_input.extend_from_slice(&int_to_bytes(segment as u32, 4));
        seed_input.extend_from_slice(&int_to_bytes(index as u32, 4));
        seed_input.extend_from_slice(&int_to_bytes(self.total_blocks as u32, 4));
        seed_input.extend_from_slice(&self.initial_hash[..32.min(self.initial_hash.len())]);

        let seed = Self::internal_prf_static(&seed_input, 32, self.parallelism);
        let pseudo_rand = bytes_to_int(&seed[..4]) as u64 | ((bytes_to_int(&seed[4..8]) as u64) << 32);

        let ref_lane = if pass_num == 0 && segment == 0 {
            lane
        } else {
            (pseudo_rand % (self.parallelism as u64)) as u32
        };

        let global_index = segment * self.segment_length + index;
        let ref_index = if pass_num == 0 {
            if segment == 0 {
                let available = (index as i32 - 1).max(1) as usize;
                ((pseudo_rand >> 32) % (available as u64)) as usize
            } else {
                let available = if ref_lane == lane {
                    segment * self.segment_length
                } else {
                    segment * self.segment_length
                };
                ((pseudo_rand >> 32) % (available.max(1) as u64)) as usize
            }
        } else {
            let available = if ref_lane == lane {
                segment * self.segment_length
            } else {
                self.blocks_per_lane
            };
            let mut ref_idx = ((pseudo_rand >> 32) % (available as u64)) as usize;
            if ref_lane == lane && ref_idx >= global_index {
                ref_idx = (ref_idx + 1) % available;
            }
            ref_idx
        };

        (ref_lane, ref_index.min(self.blocks_per_lane - 1))
    }

    #[allow(dead_code)]
    fn compute_index_dependent(&self, current_block: &NoctaBlock, lane: u32, global_index: usize, segment: usize, segment_length: usize) -> (u32, usize) {
        let block_data = current_block.to_bytes();
        
        let w0 = bytes_to_int(&block_data[0..4]);
        let w1 = bytes_to_int(&block_data[4..8]);
        let w2 = bytes_to_int(&block_data[8..12]);
        let w3 = bytes_to_int(&block_data[12..16]);
        let w4 = bytes_to_int(&block_data[16..20]);
        let w5 = bytes_to_int(&block_data[20..24]);
        let w6 = bytes_to_int(&block_data[24..28]);
        let w7 = bytes_to_int(&block_data[28..32]);

        let mix_low = mod_add(w0, rotate_left(w1, 13)) ^ mod_add(w2, rotate_left(w3, 17));
        let mix_high = mod_add(w4, rotate_left(w5, 7)) ^ mod_add(w6, rotate_left(w7, 23));
        
        let mut internal_state = ((mix_high as u64) << 32) | (mix_low as u64);
        
        let high_part = (internal_state >> 32) as u32;
        let low_part = internal_state as u32;
        let mixed = mod_add(low_part, high_part);
        internal_state = ((mixed as u64) << 32) | ((mixed ^ low_part) as u64);
        
        let cross_mix = mod_add(w0, w4) ^ mod_add(w1, w5) ^ mod_add(w2, w6) ^ mod_add(w3, w7);
        internal_state = internal_state.wrapping_add((cross_mix as u64) << 16);
        internal_state = internal_state ^ ((internal_state >> 32) as u64);

        let ref_lane = (internal_state % (self.parallelism as u64)) as u32;

        let (available, ref_index) = if ref_lane == lane {
            let available = if segment == 0 {
                global_index.max(1)
            } else {
                segment * segment_length
            };
            if available == 0 {
                (1, 0)
            } else {
                let index_seed = ((internal_state >> 16) ^ internal_state) % (available as u64);
                (available, index_seed as usize)
            }
        } else {
            let available = self.blocks_per_lane.max(1);
            if available == 0 {
                (1, 0)
            } else {
                let index_seed = ((internal_state >> 16) ^ internal_state) % (available as u64);
                (available, index_seed as usize)
            }
        };

        let safe_ref_index = if available > 0 {
            ref_index.min(available - 1)
        } else {
            0
        };

        (ref_lane, safe_ref_index)
    }

    fn initialize_first_blocks(&mut self) {
        for lane in 0..(self.parallelism as usize) {
            let mut block_input = Vec::with_capacity(self.initial_hash.len() + 8);
            block_input.extend_from_slice(&self.initial_hash);
            block_input.extend_from_slice(&int_to_bytes(0, 4));
            block_input.extend_from_slice(&int_to_bytes(lane as u32, 4));
            let block_hash = h_prime(&block_input, BLOCK_SIZE);
            self.memory[lane][0] = NoctaBlock::from_bytes(&block_hash);

            block_input.clear();
            block_input.extend_from_slice(&self.initial_hash);
            block_input.extend_from_slice(&int_to_bytes(1, 4));
            block_input.extend_from_slice(&int_to_bytes(lane as u32, 4));
            let block_hash = h_prime(&block_input, BLOCK_SIZE);
            self.memory[lane][1] = NoctaBlock::from_bytes(&block_hash);
        }
    }

    #[allow(dead_code)]
    fn fill_segment(&mut self, pass_num: u32, lane: usize, segment: usize) {
        let mut start_index = segment * self.segment_length;

        if pass_num == 0 && segment == 0 {
            start_index = 2;
        }

        if start_index == 0 {
            start_index = 1;
        }

        let segment_end = ((segment + 1) * self.segment_length).min(self.blocks_per_lane);
        
        for i in start_index..segment_end {
            if i == 0 {
                continue;
            }

            let global_index = i;
            let use_dependent = if pass_num == 0 {
                let independent_threshold = self.blocks_per_lane / 2;
                i >= independent_threshold
            } else {
                true
            };

            let (ref_lane, ref_index) = if use_dependent {
                let prev_block = &self.memory[lane][i - 1];
                self.compute_index_dependent(prev_block, lane as u32, global_index, segment, self.segment_length)
            } else {
                self.compute_index_independent(pass_num, lane as u32, segment, i)
            };

            let ref_index = ref_index.min(self.blocks_per_lane - 1);
            
            let prev_block = &self.memory[lane][i - 1];
            let ref_block = &self.memory[ref_lane as usize][ref_index];

            let mixed_counter = self.counter 
                ^ ((lane as u64) << 32)
                ^ ((pass_num as u64) << 16)
                ^ (segment as u64);
            self.counter += 1;
            let mut new_block = self.compression_function(prev_block, ref_block, mixed_counter);

            if pass_num > 0 {
                new_block.xor_inplace(&self.memory[lane][i]);
            }

            self.memory[lane][i] = new_block;
        }
    }

    fn fill_segment_threaded(
        my_lane: &mut Vec<NoctaBlock>,
        other_lanes: &Arc<Vec<Arc<Vec<NoctaBlock>>>>,
        pass_num: u32,
        lane: usize,
        segment: usize,
        blocks_per_lane: usize,
        segment_length: usize,
        parallelism: u32,
        initial_hash: &[u8],
        total_blocks: usize,
    ) {
        let mut start_index = segment * segment_length;

        if pass_num == 0 && segment == 0 {
            start_index = 2;
        }

        if start_index == 0 {
            start_index = 1;
        }

        let segment_end = ((segment + 1) * segment_length).min(blocks_per_lane);
        
        for i in start_index..segment_end {
            if i == 0 {
                continue;
            }

            let global_index = i;
            let use_dependent = if pass_num == 0 {
                let independent_threshold = blocks_per_lane / 2;
                i >= independent_threshold
            } else {
                true
            };

            let (ref_lane, ref_index) = {
                let prev_block_bytes = my_lane[i - 1].to_bytes();
                
                if use_dependent {
                    const DOMAIN_MEM_IDX: &[u8] = b"NoctaHash|mem_idx";
                    
                    let mut prf_input = Vec::new();
                    prf_input.extend_from_slice(DOMAIN_MEM_IDX);
                    prf_input.extend_from_slice(prev_block_bytes);
                    
                    let counter_value = ((lane as u64) << 48)
                        | ((pass_num as u64) << 32)
                        | ((segment as u64) << 16)
                        | (i as u64);
                    prf_input.extend_from_slice(&counter_value.to_le_bytes());
                    prf_input.extend_from_slice(&int_to_bytes(lane as u32, 4));
                    
                    let prf_output = Self::internal_prf_static(&prf_input, 64, parallelism);
                    
                    let pseudo_rand = bytes_to_int(&prf_output[0..4]) as u64 
                        | ((bytes_to_int(&prf_output[4..8]) as u64) << 32);
                    
                    let ref_lane = (pseudo_rand % (parallelism as u64)) as u32;
                    let (available, ref_index) = if ref_lane == lane as u32 {
                        let available = if segment == 0 {
                            global_index.max(1)
                        } else {
                            segment * segment_length
                        };
                        if available == 0 {
                            (1, 0)
                        } else {
                            let index_seed = (pseudo_rand >> 32) % (available as u64);
                            (available, index_seed as usize)
                        }
                    } else {
                        let available = if segment == 0 {
                            1
                        } else {
                            segment * segment_length
                        };
                        if available == 0 {
                            (1, 0)
                        } else {
                            let index_seed = (pseudo_rand >> 32) % (available as u64);
                            (available, index_seed as usize)
                        }
                    };
                    let safe_ref_index = if available > 0 {
                        ref_index.min(available - 1)
                    } else {
                        0
                    };
                    (ref_lane, safe_ref_index)
                } else {
                    const DOMAIN_MEM_IDX_INDEP: &[u8] = b"NoctaHash|mem_idx_indep";
                    
                    let mut seed_input = Vec::new();
                    seed_input.extend_from_slice(DOMAIN_MEM_IDX_INDEP);
                    seed_input.extend_from_slice(&int_to_bytes(pass_num, 4));
                    seed_input.extend_from_slice(&int_to_bytes(lane as u32, 4));
                    seed_input.extend_from_slice(&int_to_bytes(segment as u32, 4));
                    seed_input.extend_from_slice(&int_to_bytes(i as u32, 4));
                    seed_input.extend_from_slice(&int_to_bytes(total_blocks as u32, 4));
                    seed_input.extend_from_slice(&initial_hash[..32.min(initial_hash.len())]);

                    let seed = Self::internal_prf_static(&seed_input, 64, parallelism);
                    let pseudo_rand = bytes_to_int(&seed[..4]) as u64 | ((bytes_to_int(&seed[4..8]) as u64) << 32);

                    let ref_lane = if pass_num == 0 && segment == 0 {
                        lane as u32
                    } else {
                        (pseudo_rand % (parallelism as u64)) as u32
                    };

                    let _global_idx = segment * segment_length + i;
                    let ref_index = if pass_num == 0 {
                        if segment == 0 {
                            let available = (i as i32 - 1).max(1) as usize;
                            ((pseudo_rand >> 32) % (available as u64)) as usize
                        } else {
                            let available = if ref_lane == lane as u32 {
                                segment * segment_length
                            } else {
                                segment * segment_length
                            };
                            ((pseudo_rand >> 32) % (available.max(1) as u64)) as usize
                        }
                    } else {
                        let available = segment * segment_length;
                        let mut ref_idx = ((pseudo_rand >> 32) % (available.max(1) as u64)) as usize;
                        if available > 0 && ref_idx >= available {
                            ref_idx = ref_idx % available;
                        }
                        ref_idx
                    };
                    (ref_lane, ref_index.min(blocks_per_lane - 1))
                }
            };

            let ref_index = ref_index.min(blocks_per_lane - 1);
            
            let prev_block = &my_lane[i - 1];
            let ref_block = if ref_lane as usize == lane {
                &my_lane[ref_index]
            } else {
                &other_lanes[ref_lane as usize][ref_index]
            };

            let counter_value = ((lane as u64) << 48)
                | ((pass_num as u64) << 32)
                | ((segment as u64) << 16)
                | (i as u64);
            let mixed_counter = counter_value
                ^ ((lane as u64) << 32)
                ^ ((pass_num as u64) << 16)
                ^ (segment as u64);

            let mut new_block = Self::compression_function_static(prev_block, ref_block, mixed_counter);

            if pass_num > 0 {
                new_block.xor_inplace(&my_lane[i]);
            }
            my_lane[i] = new_block;
        }
    }
    
    fn compression_function_static(block_x: &NoctaBlock, block_y: &NoctaBlock, counter: u64) -> NoctaBlock {
        let mut r = block_x.xor(block_y);

        for _round_num in 0..1 {
            for matrix_idx in 0..16 {
                let base = matrix_idx * 16;
                let mut state = [0u32; 16];
                
                for i in 0..16 {
                    state[i] = r.get_word(base + i);
                }

                let (s0, s4, s8, s12) = Self::g_mixing_function_static(state[0], state[4], state[8], state[12]);
                state[0] = s0; state[4] = s4; state[8] = s8; state[12] = s12;

                let (s1, s5, s9, s13) = Self::g_mixing_function_static(state[1], state[5], state[9], state[13]);
                state[1] = s1; state[5] = s5; state[9] = s9; state[13] = s13;

                let (s2, s6, s10, s14) = Self::g_mixing_function_static(state[2], state[6], state[10], state[14]);
                state[2] = s2; state[6] = s6; state[10] = s10; state[14] = s14;

                let (s3, s7, s11, s15) = Self::g_mixing_function_static(state[3], state[7], state[11], state[15]);
                state[3] = s3; state[7] = s7; state[11] = s11; state[15] = s15;

                let (s0, s5, s10, s15) = Self::g_mixing_function_static(state[0], state[5], state[10], state[15]);
                state[0] = s0; state[5] = s5; state[10] = s10; state[15] = s15;

                let (s1, s6, s11, s12) = Self::g_mixing_function_static(state[1], state[6], state[11], state[12]);
                state[1] = s1; state[6] = s6; state[11] = s11; state[12] = s12;

                let (s2, s7, s8, s13) = Self::g_mixing_function_static(state[2], state[7], state[8], state[13]);
                state[2] = s2; state[7] = s7; state[8] = s8; state[13] = s13;

                let (s3, s4, s9, s14) = Self::g_mixing_function_static(state[3], state[4], state[9], state[14]);
                state[3] = s3; state[4] = s4; state[9] = s9; state[14] = s14;

                let (s0, s7, s10, s13) = Self::g_mixing_function_static(state[0], state[7], state[10], state[13]);
                state[0] = s0; state[7] = s7; state[10] = s10; state[13] = s13;

                let (s1, s4, s11, s14) = Self::g_mixing_function_static(state[1], state[4], state[11], state[14]);
                state[1] = s1; state[4] = s4; state[11] = s11; state[14] = s14;

                for i in 0..16 {
                    r.set_word(base + i, state[i]);
                }
            }
        }

        for matrix_idx in 0..16 {
            let base = matrix_idx * 16;
            let mut state = [0u32; 16];
            
            for i in 0..16 {
                state[i] = r.get_word(base + i);
            }

            const MIX_ROUNDS: usize = 2;
            
            for _mix_round in 0..MIX_ROUNDS {
                for col in 0..4 {
                    let idx0 = col;
                    let idx1 = col + 4;
                    let idx2 = col + 8;
                    let idx3 = col + 12;
                    
                    let (s0, s1, s2, s3) = Self::g_mixing_function_static(
                        state[idx0], state[idx1], state[idx2], state[idx3]
                    );
                    state[idx0] = s0;
                    state[idx1] = s1;
                    state[idx2] = s2;
                    state[idx3] = s3;
                }
            }

            for i in 0..16 {
                r.set_word(base + i, state[i]);
            }
        }

        let counter_low = counter as u32;
        let counter_high = (counter >> 32) as u32;
        
        const COUNTER_ROT1: u32 = 16;
        const COUNTER_ROT2: u32 = 12;
        
        for i in (0..WORDS_PER_BLOCK).step_by(8) {
            let word = r.get_word(i);
            let mixed = mod_add(word, counter_low) ^ rotate_left(counter_high, COUNTER_ROT1);
            r.set_word(i, mixed);
            
            if i + 4 < WORDS_PER_BLOCK {
                let word2 = r.get_word(i + 4);
                let mixed2 = mod_add(word2, counter_high) ^ rotate_right(counter_low, COUNTER_ROT2);
                r.set_word(i + 4, mixed2);
            }
        }

        r
    }
    
    fn internal_prf_static(input: &[u8], output_len: usize, _parallelism: u32) -> Vec<u8> {
        let mut words = Vec::new();
        for chunk in input.chunks(4) {
            let mut word_bytes = [0u8; 4];
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            words.push(bytes_to_int(&word_bytes));
        }
        
        while words.len() % 4 != 0 {
            words.push(0);
        }
        
        const PRF_ROUNDS: usize = 7;
        for _round in 0..PRF_ROUNDS {
            for i in (0..words.len()).step_by(4) {
                if i + 3 < words.len() {
                    let (a, b, c, d) = Self::g_mixing_function_static(words[i], words[i+1], words[i+2], words[i+3]);
                    words[i] = a;
                    words[i+1] = b;
                    words[i+2] = c;
                    words[i+3] = d;
                }
            }
        }
        
        let mut result = Vec::new();
        for word in words.iter().take((output_len + 3) / 4) {
            result.extend_from_slice(&word.to_le_bytes());
        }
        
        result[..output_len.min(result.len())].to_vec()
    }
    
    fn g_mixing_function_static(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        let mut a = a;
        let mut b = b;
        let mut c = c;
        let mut d = d;

        const ROUNDS: usize = 2;
        const ROTS: [u32; 4] = [16, 12, 8, 7];
        
        for round in 0..ROUNDS {
            let rot_idx = round & 3;
            let rot1 = ROTS[rot_idx];
            let rot2 = ROTS[(rot_idx + 1) & 3];
            let rot3 = ROTS[(rot_idx + 2) & 3];
            let rot4 = ROTS[(rot_idx + 3) & 3];

            a = mod_add(a, b);
            d = rotate_right(d ^ a, rot1);
            c = mod_add(c, d);
            b = rotate_right(b ^ c, rot2);

            a = mod_add(a, b);
            d = rotate_right(d ^ a, rot3);
            c = mod_add(c, d);
            b = rotate_right(b ^ c, rot4);
        }

        a ^= d;
        b ^= c;
        c = mod_add(c, a);
        d = mod_add(d, b);

        (a, b, c, d)
    }

    fn fill_memory(&mut self) -> Result<(), Box<dyn Error>> {
        let lanes: Vec<Vec<NoctaBlock>> = std::mem::take(&mut self.memory);
        let parallelism = self.parallelism as usize;
        let time_cost = self.time_cost;
        let blocks_per_lane = self.blocks_per_lane;
        let segment_length = self.segment_length;
        let total_blocks = self.total_blocks;
        let initial_hash = Arc::new(self.initial_hash.clone());
        
        let barrier = Arc::new(Barrier::new(parallelism));
        
        let handles: Vec<_> = (0..parallelism).map(|lane| {
            let mut my_lane = lanes[lane].clone();
            
            let initial_lanes_arc: Arc<Vec<Arc<Vec<NoctaBlock>>>> = Arc::new(
                lanes.iter()
                    .map(|l| Arc::new(l.clone()))
                    .collect()
            );
            let mut current_lanes_ref = Arc::clone(&initial_lanes_arc);
            
            let barrier_clone = Arc::clone(&barrier);
            let initial_hash_clone = Arc::clone(&initial_hash);
            let blocks_per_lane_clone = blocks_per_lane;
            let segment_length_clone = segment_length;
            let parallelism_clone = self.parallelism;
            let total_blocks_clone = total_blocks;
            
            thread::spawn(move || {
                for pass_num in 0..time_cost {
                    for segment in 0..SYNC_POINTS {
                        Self::fill_segment_threaded(
                            &mut my_lane,           // Exclusive mutable access to own lane
                            &current_lanes_ref,     // Immutable access to all lanes (from previous segments)
                            pass_num,
                            lane,
                            segment,
                            blocks_per_lane_clone,
                            segment_length_clone,
                            parallelism_clone,
                            &initial_hash_clone,
                            total_blocks_clone,
                        );
                        
                        barrier_clone.wait();
                        
                        if segment < SYNC_POINTS - 1 {
                            let mut new_lanes = Vec::with_capacity(parallelism_clone as usize);
                            for l in 0..parallelism_clone as usize {
                                if l == lane {
                                    new_lanes.push(Arc::new(my_lane.clone()));
                                } else {
                                    new_lanes.push(Arc::clone(&current_lanes_ref[l]));
                                }
                            }
                            current_lanes_ref = Arc::new(new_lanes);
                        }
                    }
                }
                
                my_lane
            })
        }).collect();
        
        let mut collected_lanes = Vec::new();
        for (idx, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(lane) => collected_lanes.push(lane),
                Err(e) => {
                    return Err(format!(
                        "Thread {} panicked during execution: {:?}. This may indicate a bug in the algorithm or insufficient system resources.",
                        idx,
                        e
                    ).into());
                }
            }
        }
        self.memory = collected_lanes;
        Ok(())
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        let mut final_block = NoctaBlock::new();
        for lane in 0..(self.parallelism as usize) {
            let last_block = &self.memory[lane][self.blocks_per_lane - 1];
            final_block.xor_inplace(last_block);
        }

        let full_block_data = final_block.to_bytes();
        
        const DOMAIN_FINAL: &[u8] = b"NoctaHash|final";
        
        let mut hash_input = Vec::with_capacity(DOMAIN_FINAL.len() + full_block_data.len() + 12);
        hash_input.extend_from_slice(DOMAIN_FINAL);
        hash_input.extend_from_slice(&full_block_data);
        hash_input.extend_from_slice(&int_to_bytes(self.time_cost, 4));
        hash_input.extend_from_slice(&int_to_bytes(self.memory_cost_mb, 4));
        hash_input.extend_from_slice(&int_to_bytes(self.parallelism, 4));
        
        let min_output_len = 64; // 512 bits minimum
        let result = h_prime(&hash_input, min_output_len.max(HASH_OUTPUT_LEN));

        result[..HASH_OUTPUT_LEN].to_vec()
    }

    pub fn compute(&mut self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.initial_hash = self.compute_initial_hash(password, salt);
        self.counter = 0;

        self.allocate_memory();
        self.initialize_first_blocks();
        self.fill_memory()?; // PRODUCTION: Handle thread panics gracefully
        let result = self.finalize();

        for lane in &mut self.memory {
            for block in lane {
                block.secure_zero();
            }
        }
        self.memory.clear();
        self.initial_hash.clear();

        Ok(result)
    }
}

pub fn noctahash(
    password: &str,
    salt: Option<&[u8]>,
    time_cost: u32,
    memory_cost_mb: u32,
    parallelism: u32,
    encoding: &str,
) -> Result<String, Box<dyn Error>> {
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }

        let salt_bytes = if let Some(s) = salt {
            if s.len() < 16 {
                return Err("Salt must be at least 16 bytes (recommended: 32 bytes)".into());
            }
            s.to_vec()
        } else {
            use rand::RngCore;
            let mut salt = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            salt
        };

    let password_bytes = password.as_bytes();

    let mut hasher = NoctaHashCore::new(time_cost, memory_cost_mb, parallelism)?;
    let raw_hash = hasher.compute(password_bytes, &salt_bytes)?;

    let (salt_encoded, hash_encoded) = if encoding == "hex" {
        (hex::encode(&salt_bytes), hex::encode(&raw_hash))
    } else {
        use base64::{Engine as _, engine::general_purpose};
        let engine = general_purpose::STANDARD;
        (engine.encode(&salt_bytes), engine.encode(&raw_hash))
    };

    Ok(format!(
        "$noctahash$v={}$t={},m={},p={}${}${}",
        VERSION, time_cost, memory_cost_mb, parallelism, salt_encoded, hash_encoded
    ))
}

pub fn verify(password: &str, hash_string: &str) -> bool {
    if password.is_empty() || hash_string.is_empty() {
        return false;
    }

    if !hash_string.starts_with("$noctahash$") {
        return false;
    }
    
    let version_start = "$noctahash$v=".len();
    let version_end = match hash_string[version_start..].find('$') {
        Some(pos) => version_start + pos,
        None => return false,
    };
    
    let version: u32 = match hash_string[version_start..version_end].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    
    if version != VERSION {
        return false;
    }
    
    let params_start = version_end + 1;
    let params_end = match hash_string[params_start..].find('$') {
        Some(pos) => params_start + pos,
        None => return false,
    };
    
    let mut time_cost: Option<u32> = None;
    let mut memory_cost_mb: Option<u32> = None;
    let mut parallelism: Option<u32> = None;
    
    for param in hash_string[params_start..params_end].split(',') {
        let kv: Vec<&str> = param.split('=').collect();
        if kv.len() != 2 {
            return false; // Invalid format
        }
        
        match kv[0] {
            "t" => {
                if time_cost.is_some() {
                    return false; // Duplicate parameter
                }
                time_cost = kv[1].parse().ok();
                if time_cost.is_none() {
                    return false; // Invalid value
                }
            }
            "m" => {
                if memory_cost_mb.is_some() {
                    return false; // Duplicate parameter
                }
                memory_cost_mb = kv[1].parse().ok();
                if memory_cost_mb.is_none() {
                    return false; // Invalid value
                }
            }
            "p" => {
                if parallelism.is_some() {
                    return false; // Duplicate parameter
                }
                parallelism = kv[1].parse().ok();
                if parallelism.is_none() {
                    return false; // Invalid value
                }
            }
            _ => return false, // Unknown parameter
        }
    }
    
    let time_cost = match time_cost {
        Some(t) => t,
        None => return false,
    };
    let memory_cost_mb = match memory_cost_mb {
        Some(m) => m,
        None => return false,
    };
    let parallelism = match parallelism {
        Some(p) => p,
        None => return false,
    };
    
    let salt_start = params_end + 1;
    let salt_end = match hash_string[salt_start..].find('$') {
        Some(pos) => salt_start + pos,
        None => return false,
    };
    
    let salt_str = &hash_string[salt_start..salt_end];
    let hash_str = &hash_string[salt_end + 1..];

    let (salt, expected_hash) = if is_hex_string(salt_str) && is_hex_string(hash_str) {
        match (hex::decode(salt_str), hex::decode(hash_str)) {
            (Ok(s), Ok(h)) => (s, h),
            _ => return false,
        }
    } else {
        use base64::{Engine as _, engine::general_purpose};
        let engine = general_purpose::STANDARD;
        match (engine.decode(salt_str), engine.decode(hash_str)) {
            (Ok(s), Ok(h)) => (s, h),
            _ => return false,
        }
    };

    let mut hasher = match NoctaHashCore::new(time_cost, memory_cost_mb, parallelism) {
        Ok(h) => h,
        Err(_) => return false,
    };

    let computed_hash = match hasher.compute(password.as_bytes(), &salt) {
        Ok(h) => h,
        Err(_) => return false,
    };

    constant_time_eq(&computed_hash, &expected_hash)
}

fn is_hex_string(s: &str) -> bool {
    if s.len() % 2 != 0 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}
