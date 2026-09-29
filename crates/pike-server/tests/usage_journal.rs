use pike_server::usage_journal::UsageJournal;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};
const OWNER: &str = "12345678-1234-1234-1234-123456789abc";
const TUNNEL: &str = "87654321-1234-1234-1234-123456789abc";
const SINK: &str = "https://usage.example.test";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pike-journal-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("usage.sqlite3")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[tokio::test]
async fn restart_preserves_unfrozen_and_frozen_usage_and_does_not_rebill() {
    let fixture = Fixture::new();
    let journal = UsageJournal::open(&fixture.db(), SINK).unwrap();
    journal
        .record(TUNNEL.into(), OWNER.into(), 3, 7)
        .await
        .unwrap();
    drop(journal);
    let journal = UsageJournal::open(&fixture.db(), SINK).unwrap();
    let first = journal.batch().await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].request_count, 1);
    drop(journal);
    let journal = UsageJournal::open(&fixture.db(), SINK).unwrap();
    assert_eq!(journal.batch().await.unwrap(), first);
    journal
        .record(TUNNEL.into(), OWNER.into(), 5, 9)
        .await
        .unwrap();
    assert_eq!(journal.batch().await.unwrap(), first);
    journal.acknowledge(&first).await.unwrap();
    drop(journal);
    let journal = UsageJournal::open(&fixture.db(), SINK).unwrap();
    let second = journal.batch().await.unwrap();
    assert_eq!(second[0].bytes_in, 5);
    assert_ne!(second[0].report_id, first[0].report_id);
    journal.acknowledge(&second).await.unwrap();
    drop(journal);
    assert!(UsageJournal::open(&fixture.db(), SINK)
        .unwrap()
        .batch()
        .await
        .unwrap()
        .is_empty());
}
#[tokio::test]
async fn concurrent_connections_keep_every_committed_observation() {
    let fixture = Fixture::new();
    let a = Arc::new(UsageJournal::open(&fixture.db(), SINK).unwrap());
    let b = Arc::new(UsageJournal::open(&fixture.db(), SINK).unwrap());
    let mut tasks = Vec::new();
    for i in 0..100 {
        let journal = if i % 2 == 0 { a.clone() } else { b.clone() };
        tasks.push(tokio::spawn(async move {
            journal
                .record(TUNNEL.into(), OWNER.into(), 1, 2)
                .await
                .unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let reports = a.batch().await.unwrap();
    assert_eq!(reports.iter().map(|r| r.request_count).sum::<u64>(), 100);
    assert_eq!(reports.iter().map(|r| r.bytes_out).sum::<u64>(), 200);
    assert_eq!(a.batch().await.unwrap(), b.batch().await.unwrap());
}
#[tokio::test]
async fn invalid_identity_owner_and_overflow_cannot_mutate_committed_counts() {
    let journal = UsageJournal::memory(SINK).unwrap();
    assert!(journal
        .record("runtime-not-a-uuid".into(), OWNER.into(), 3, 7)
        .await
        .is_err());
    journal
        .record(TUNNEL.into(), OWNER.into(), 3, 7)
        .await
        .unwrap();
    assert!(journal
        .record(TUNNEL.into(), uuid::Uuid::new_v4().to_string(), 3, 7)
        .await
        .is_err());
    assert!(journal
        .record(TUNNEL.into(), OWNER.into(), 9_007_199_254_740_992, 7)
        .await
        .is_err());
    assert!(!journal.is_healthy());
    let batch = journal.batch().await.unwrap();
    assert_eq!(batch[0].request_count, 1);
    assert_eq!(batch[0].bytes_in, 3);
}
#[test]
fn mismatched_sink_and_corrupt_database_fail_closed() {
    let fixture = Fixture::new();
    drop(UsageJournal::open(&fixture.db(), SINK).unwrap());
    assert!(UsageJournal::open(&fixture.db(), "https://different.example.test").is_err());
    let bad = fixture.0.join("corrupt.sqlite3");
    std::fs::write(&bad, b"not a database").unwrap();
    assert!(UsageJournal::open(&bad, SINK).is_err());
}
#[tokio::test]
async fn sigkill_recovers_committed_rows_on_both_sides_of_batch_freezing() {
    for freeze in [false, true] {
        let fixture = Fixture::new();
        let marker = fixture.0.join("ready.json");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "journal_crash_child"])
            .env("PIKE_TEST_JOURNAL", fixture.db())
            .env("PIKE_TEST_READY", &marker)
            .env("PIKE_TEST_FREEZE", if freeze { "1" } else { "0" })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = false;
        for _ in 0..200 {
            if marker.exists() {
                ready = true;
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "fixture exited before readiness"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            panic!("crash fixture failed to become ready");
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let journal = UsageJournal::open(&fixture.db(), SINK).unwrap();
        let batch = journal.batch().await.unwrap();
        assert_eq!(batch[0].bytes_in, 37);
        assert_eq!(batch[0].bytes_out, 73);
        assert_eq!(batch[0].request_count, 1);
        if freeze {
            let expected: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
            assert_eq!(
                batch[0].report_id,
                expected[0]["report_id"].as_str().unwrap()
            );
        }
        journal.acknowledge(&batch).await.unwrap();
        assert!(journal.batch().await.unwrap().is_empty());
    }
}
#[test]
#[ignore = "subprocess fixture: invoked by the SIGKILL test"]
fn journal_crash_child() {
    let Some(path) = std::env::var_os("PIKE_TEST_JOURNAL") else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let journal = UsageJournal::open(std::path::Path::new(&path), SINK).unwrap();
        journal
            .record(TUNNEL.into(), OWNER.into(), 0, 0)
            .await
            .unwrap();
        journal
            .record_delta(TUNNEL.into(), OWNER.into(), 37, 0, 0)
            .await
            .unwrap();
        journal
            .record_delta(TUNNEL.into(), OWNER.into(), 0, 73, 0)
            .await
            .unwrap();
        let contents = if std::env::var("PIKE_TEST_FREEZE").unwrap() == "1" {
            serde_json::to_vec(&journal.batch().await.unwrap()).unwrap()
        } else {
            b"[]".to_vec()
        };
        std::fs::write(std::env::var_os("PIKE_TEST_READY").unwrap(), contents).unwrap();
        std::future::pending::<()>().await;
    });
}

#[tokio::test]
async fn minute_buckets_and_backlog_cap_preserve_existing_records() {
    let fixture = Fixture::new();
    let journal = UsageJournal::open(&fixture.db(), SINK).unwrap();
    let connection = rusqlite::Connection::open(fixture.db()).unwrap();
    connection
        .execute(
            "INSERT INTO counters VALUES(?1,?2,3,7,1,60,0)",
            rusqlite::params![TUNNEL, OWNER],
        )
        .unwrap();
    journal
        .record(TUNNEL.into(), OWNER.into(), 5, 9)
        .await
        .unwrap();
    let batch = journal.batch().await.unwrap();
    assert_eq!(batch.len(), 2);
    assert!(batch.iter().any(|r| r.timestamp == 60 && r.bytes_in == 3));
    assert_eq!(batch.iter().map(|r| r.bytes_out).sum::<u64>(), 16);
    assert!(journal
        .record(TUNNEL.into(), uuid::Uuid::new_v4().to_string(), 1, 1)
        .await
        .is_err());
    journal.acknowledge(&batch).await.unwrap();
    connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<20000) INSERT INTO counters SELECT printf('00000000-0000-0000-0000-%012d',x), '12345678-1234-1234-1234-123456789abc',0,0,1,60,0 FROM n;").unwrap();
    assert!(journal
        .record(TUNNEL.into(), OWNER.into(), 1, 1)
        .await
        .is_err());
    assert!(!journal.is_healthy());
    assert_eq!(journal.batch().await.unwrap().len(), 500);
}
#[test]
fn future_schema_fails_closed() {
    let fixture = Fixture::new();
    let connection = rusqlite::Connection::open(fixture.db()).unwrap();
    connection.pragma_update(None, "user_version", 3).unwrap();
    assert!(UsageJournal::open(&fixture.db(), SINK).is_err());
}
