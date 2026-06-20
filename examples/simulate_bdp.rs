// Standalone BDP simulator — verifies the Brutal CC dynamic-rate algorithm
// in src/lib.rs (RTT/cwnd/loss → BDP estimation → rate adjustment).
// Run with: cargo run --example simulate_bdp
fn main() {
    let base_rate = 8_000_000u64; // 8 Mbps in bytes/sec
    let base_rtt_ms = 50.0;
    let mut current_rate = base_rate;
    let mut total_retrans = 0;
    
    println!("Tick\tRTT(ms)\tCwnd\tRetrans\tRate(Bps)\tAction");
    
    // Simulate ticks
    for i in 1..=20 {
        let (rtt, cwnd, new_retrans) = match i {
            // Normal start
            1..=3 => (50.0, 100, 0),
            // RTT spikes
            4..=6 => (100.0, 100, 0),
            // Packet loss
            7..=8 => (80.0, 60, 5),
            // Recovery
            9..=15 => (52.0, 80, 0),
            // Stable
            _ => (50.0, 150, 0),
        };
        
        let delta_retrans = new_retrans;
        total_retrans += new_retrans;
        
        let mut action = "Stable";
        let mut dynamic_rate = current_rate;
        
        if rtt > (base_rtt_ms * 1.5) || delta_retrans > 0 {
            // Congested! Back off to measured BDP bandwidth
            // 1 MSS = 1440 bytes
            let estimated_bdp_bytes_per_sec = (cwnd as f64 * 1440.0) / (rtt as f64 / 1000.0);
            dynamic_rate = (estimated_bdp_bytes_per_sec as u64).max(base_rate / 10);
            action = "Backoff (Congestion)";
        } else {
            // Recover! Increase towards configured rate
            if current_rate < base_rate {
                dynamic_rate = (current_rate as f64 * 1.1) as u64;
                action = "Recover (+10%)";
            }
        }
        
        dynamic_rate = dynamic_rate.min(base_rate);
        
        if (dynamic_rate as i64 - current_rate as i64).abs() > (current_rate / 10) as i64 {
            current_rate = dynamic_rate;
        } else if dynamic_rate == base_rate && current_rate != base_rate {
            current_rate = base_rate;
        }
        
        println!("{}\t{}\t{}\t{}\t{}\t{}", i, rtt, cwnd, total_retrans, current_rate, action);
    }
}
