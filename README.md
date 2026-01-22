# NoctaHash

Memory-hard password hashing algorithm implemented in Rust.

## Overview

NoctaHash is a production-grade password hashing system designed to resist GPU, ASIC, and side-channel attacks. It features memory-hardness, time-hardness, and true parallel execution with deterministic results.

## Features

- Memory-hardness: Resists GPU/ASIC attacks
- Time-hardness: Configurable computation time
- Hybrid mixing: Data-independent and data-dependent phases
- True parallelism: Multi-threaded execution
- Constant-time operations: Side-channel resistant
- Secure memory management: Automatic zeroization

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
noctahash = "0.1.0"
```

## Usage

```rust
use noctahash::{noctahash, verify};

// Create hash
let hash = noctahash("password", None, 3, 64, 4, "base64")?;

// Verify password
let is_valid = verify("password", &hash);
```

### Custom Salt

```rust
let salt = b"your_32_byte_salt_here";
let hash = noctahash("password", Some(salt), 3, 64, 4, "base64")?;
```

## Parameters

- **time_cost** (1-16777216): Number of iterations
- **memory_cost_mb** (≥1): Memory usage in megabytes
- **parallelism** (1-255): Number of parallel lanes
- **encoding**: "base64" or "hex"

### Recommended Settings

| Use Case | time_cost | memory_mb | parallelism |
|----------|-----------|------------|-------------|
| Development | 1 | 16 | 2 |
| Production | 3 | 64 | 4 |
| High Security | 4 | 128 | 4 |

## Hash Format

```
$noctahash$v=1$t=3,m=64,p=4$<salt>$<hash>
```

## CLI

```bash
cargo build --release
./target/release/noctahash <password> [time_cost] [memory_mb] [parallelism]
```

## Security

- Minimum salt length: 16 bytes (recommended: 32 bytes)
- Constant-time comparison
- Secure memory zeroization
- Domain separation for PRF inputs
- Fixed rotation constants (no data-dependent rotations)

## Performance

Typical performance on modern hardware:
- `t=3, m=64, p=4`: ~500ms
- `t=2, m=32, p=2`: ~150ms
- `t=1, m=16, p=1`: ~50ms

## API

### Functions

- `noctahash(password, salt, time_cost, memory_mb, parallelism, encoding)` - Create hash
- `verify(password, hash_string)` - Verify password
- `NoctaHashCore::new(time_cost, memory_mb, parallelism)` - Create core instance
- `NoctaHashCore::compute(password, salt)` - Compute raw hash

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## License

MIT

## Author

**Tuna4L** - [GitHub](https://github.com/Tuna4LL)
