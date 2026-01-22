use noctahash::{noctahash, verify};
use std::env;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: noctahash <password> [time_cost] [memory_mb] [parallelism]");
        println!("Example: noctahash mypassword 3 64 4");
        return;
    }
    
    let password = &args[1];
    let time_cost = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let memory_mb = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(64);
    let parallelism = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(4);
    
    println!("NoctaHash - Rust Implementation");
    println!("Parameters: time_cost={}, memory_mb={}, parallelism={}", time_cost, memory_mb, parallelism);
    println!("\nCreating hash...");
    
    let start = Instant::now();
    match noctahash(password, None, time_cost, memory_mb, parallelism, "base64") {
        Ok(hash) => {
            let elapsed = start.elapsed();
            println!("Hash created in {:.2}ms", elapsed.as_secs_f64() * 1000.0);
            println!("Hash: {}", hash);
            
            println!("\nVerifying...");
            let verify_start = Instant::now();
            let is_valid = verify(password, &hash);
            let verify_elapsed = verify_start.elapsed();
            println!("Verification: {} ({:.2}ms)", if is_valid { "OK" } else { "FAILED" }, verify_elapsed.as_secs_f64() * 1000.0);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
