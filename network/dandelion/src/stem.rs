//! Stem phase implementation details
//! 
//! This file is optional - you can keep all logic in lib.rs
//! Showing modular structure for future extension

/// Stem phase configuration
pub struct StemPhaseConfig {
    pub min_hops: u32,
    pub max_hops: u32,
}

impl Default for StemPhaseConfig {
    fn default() -> Self {
        Self {
            min_hops: 2,
            max_hops: 4,
        }
    }
}

/// Randomize hop count between min and max
pub fn randomize_stem_hops(config: &StemPhaseConfig) -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    
    let range = config.max_hops - config.min_hops + 1;
    config.min_hops + ((nanos as u32) % range)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_randomize_hops() {
        let config = StemPhaseConfig {
            min_hops: 2,
            max_hops: 4,
        };

        for _ in 0..10 {
            let hops = randomize_stem_hops(&config);
            assert!(hops >= 2 && hops <= 4);
        }
    }
}