//! Event monitoring handler

use crate::commands::MonitorOpts;
use crate::rpc::RpcClient;
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

/// Handle monitor command
pub async fn handle_monitor(
    opts: MonitorOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    println!("\n Event Monitor");

    let client = RpcClient::new(rpc_endpoint);
    let interval = Duration::from_secs(opts.interval);

    println!("Monitoring: {} (refresh: {}s)\n", rpc_endpoint, opts.interval);

    // Display header
    println!("{:<20} {:<40} {:<15}", "Event", "Details", "Time");
    println!("{}", "─".repeat(75));

    loop {
        // Get latest events
        let events = match &opts.event {
            Some(event_type) => client.get_events_by_type(event_type).await?,
            None if opts.all => client.get_all_events().await?,
            None => client.get_recent_events().await?,
        };

        for event in events {
            println!(
                "{:<20} {:<40} {:<15}",
                &event.event_type[..20.min(event.event_type.len())],
                &event.details[..40.min(event.details.len())],
                event.timestamp
            );
        }

        // Check for blocks
        let block_info = client.get_latest_block().await?;
        println!("\n Chain Status:");
        println!("  Latest block: {}", block_info.number);
        println!("  Timestamp: {}", block_info.timestamp);
        println!("  Finalized: {}", block_info.finalized);
        println!();

        // Wait for next refresh
        println!("(Refreshing in {}s - press Ctrl+C to stop)\n", opts.interval);
        sleep(interval).await;

        // Clear screen (simple approach)
        print!("\x1B[2J\x1B[1;1H");
    }
}

/// Event information
#[derive(serde::Serialize, Clone)]
pub struct EventInfo {
    pub event_type: String,
    pub details: String,
    pub timestamp: String,
}

/// Block information
#[derive(serde::Serialize, Clone)]
pub struct BlockInfo {
    pub number: u32,
    pub timestamp: u64,
    pub finalized: bool,
}