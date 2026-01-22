pub fn int_to_bytes(n: u32, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    for i in 0..length {
        bytes[i] = ((n >> (i * 8)) & 0xFF) as u8;
    }
    bytes
}

pub fn bytes_to_int(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().take(4).enumerate() {
        result |= (byte as u32) << (i * 8);
    }
    result
}

pub fn rotate_right(value: u32, shift: u32) -> u32 {
    value.rotate_right(shift)
}

pub fn rotate_left(value: u32, shift: u32) -> u32 {
    value.rotate_left(shift)
}

pub fn mod_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

pub fn h_prime(data: &[u8], output_len: usize) -> Vec<u8> {
    let min_output_len = 64.max(output_len);
    
    let mut words = Vec::new();
    for chunk in data.chunks(4) {
        let mut word_bytes = [0u8; 4];
        word_bytes[..chunk.len()].copy_from_slice(chunk);
        words.push(bytes_to_int(&word_bytes));
    }
    
    while words.len() % 16 != 0 {
        words.push(0);
    }
    
    const H_PRIME_ROUNDS: usize = 7;
    
    for _round in 0..H_PRIME_ROUNDS {
        for i in (0..words.len()).step_by(4) {
            if i + 3 < words.len() {
                let (a, b, c, d) = h_prime_quarter_round(words[i], words[i+1], words[i+2], words[i+3]);
                words[i] = a;
                words[i+1] = b;
                words[i+2] = c;
                words[i+3] = d;
            }
        }
        
        for col_start in (0..words.len()).step_by(16) {
            if col_start + 15 < words.len() {
                for col in 0..4 {
                    let idx0 = col_start + col;
                    let idx1 = col_start + col + 4;
                    let idx2 = col_start + col + 8;
                    let idx3 = col_start + col + 12;
                    
                    let (a, b, c, d) = h_prime_quarter_round(
                        words[idx0], words[idx1], words[idx2], words[idx3]
                    );
                    words[idx0] = a;
                    words[idx1] = b;
                    words[idx2] = c;
                    words[idx3] = d;
                }
            }
        }
    }
    
    let mut result = Vec::new();
    for word in words.iter().take((min_output_len + 3) / 4) {
        result.extend_from_slice(&word.to_le_bytes());
    }
    
    result[..output_len.min(result.len())].to_vec()
}

fn h_prime_quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    const ROT1: u32 = 16;
    const ROT2: u32 = 12;
    const ROT3: u32 = 8;
    const ROT4: u32 = 7;
    
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;
    
    a = mod_add(a, b);
    d = rotate_right(d ^ a, ROT1);
    c = mod_add(c, d);
    b = rotate_right(b ^ c, ROT2);
    
    a = mod_add(a, b);
    d = rotate_right(d ^ a, ROT3);
    c = mod_add(c, d);
    b = rotate_right(b ^ c, ROT4);
    
    (a, b, c, d)
}
