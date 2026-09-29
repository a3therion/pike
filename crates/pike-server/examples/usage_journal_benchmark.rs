//! Local FULL-sync commit cost, independent of the network relay benchmark.
use pike_server::usage_journal::UsageJournal;
use std::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let folder = std::env::temp_dir().join(format!("pike-journal-bench-{}", uuid::Uuid::new_v4()));
    let journal = UsageJournal::open(&folder.join("usage.sqlite3"), "https://benchmark.invalid")?;
    let owner = uuid::Uuid::new_v4().to_string();
    let tunnel = uuid::Uuid::new_v4().to_string();
    let mut timings = Vec::with_capacity(1000);
    let start = Instant::now();
    for _ in 0..1000 {
        let now = Instant::now();
        journal
            .record(tunnel.clone(), owner.clone(), 1024, 1024)
            .await?;
        timings.push(now.elapsed().as_secs_f64() * 1000.0);
    }
    let elapsed = start.elapsed().as_secs_f64();
    timings.sort_by(f64::total_cmp);
    let batch = journal.batch().await?;
    anyhow::ensure!(batch.iter().map(|r| r.request_count).sum::<u64>() == 1000);
    println!(
        "{}",
        serde_json::json!({
            "observations":1000,"mode":"SQLite WAL synchronous=FULL, sequential, local temp filesystem",
            "p50Ms":timings[499],"p95Ms":timings[949],"p99Ms":timings[989],
            "commitsPerSecond":1000.0/elapsed,"seconds":elapsed
        })
    );
    drop(journal);
    std::fs::remove_dir_all(folder)?;
    Ok(())
}
