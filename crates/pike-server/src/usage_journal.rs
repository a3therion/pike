//! Transactional usage outbox. Only committed observations are billable; retries
//! retain their identity across relay restarts and ambiguous remote acknowledgements.
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

const MAX_REPORTS: i64 = 20_000;
const BATCH_SIZE: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageReport {
    pub report_id: String,
    pub tunnel_id: String,
    pub user_id: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub request_count: u64,
    pub timestamp: u64,
    #[serde(default)]
    pub quota_accounted: bool,
}

pub struct UsageJournal {
    connection: Arc<Mutex<Connection>>,
    writers: Arc<Semaphore>,
    healthy: Arc<AtomicBool>,
}

impl UsageJournal {
    /// Uses SQLite WAL + FULL synchronization. The caller must keep this path on
    /// persistent storage; opening an unrelated sink against it fails closed.
    pub fn open(path: &Path, sink: &str) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        Self::initialize(Connection::open(path)?, sink)
    }

    pub fn memory(sink: &str) -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?, sink)
    }

    fn initialize(connection: Connection, sink: &str) -> Result<Self> {
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        anyhow::ensure!(
            version <= 2,
            "usage journal schema is newer than this relay"
        );
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA wal_autocheckpoint=128; PRAGMA journal_size_limit=8388608;
            CREATE TABLE IF NOT EXISTS destination (id INTEGER PRIMARY KEY CHECK(id=1), sink TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS counters (
                tunnel_id TEXT NOT NULL, user_id TEXT NOT NULL,
                bytes_in INTEGER NOT NULL CHECK(bytes_in BETWEEN 0 AND 9007199254740991), bytes_out INTEGER NOT NULL CHECK(bytes_out BETWEEN 0 AND 9007199254740991),
                request_count INTEGER NOT NULL CHECK(request_count BETWEEN 0 AND 9007199254740991), timestamp INTEGER NOT NULL, PRIMARY KEY(tunnel_id,timestamp));
            CREATE TABLE IF NOT EXISTS outbox (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL UNIQUE,
                tunnel_id TEXT NOT NULL, user_id TEXT NOT NULL,
                bytes_in INTEGER NOT NULL CHECK(bytes_in BETWEEN 0 AND 9007199254740991), bytes_out INTEGER NOT NULL CHECK(bytes_out BETWEEN 0 AND 9007199254740991),
                request_count INTEGER NOT NULL CHECK(request_count BETWEEN 0 AND 9007199254740991), timestamp INTEGER NOT NULL);")?;
        if version < 2 {
            connection.execute_batch("BEGIN IMMEDIATE;
                ALTER TABLE counters RENAME TO counters_v1;
                CREATE TABLE counters (
                    tunnel_id TEXT NOT NULL, user_id TEXT NOT NULL,
                    bytes_in INTEGER NOT NULL CHECK(bytes_in >= 0), bytes_out INTEGER NOT NULL CHECK(bytes_out >= 0),
                    request_count INTEGER NOT NULL CHECK(request_count BETWEEN 0 AND 9007199254740991),
                    timestamp INTEGER NOT NULL, quota_accounted INTEGER NOT NULL CHECK(quota_accounted IN (0,1)),
                    CHECK(bytes_in + bytes_out <= 9007199254740991), PRIMARY KEY(tunnel_id,timestamp,quota_accounted));
                INSERT INTO counters SELECT *, 0 FROM counters_v1;
                DROP TABLE counters_v1;
                ALTER TABLE outbox ADD COLUMN quota_accounted INTEGER NOT NULL DEFAULT 0 CHECK(quota_accounted IN (0,1));
                CREATE TABLE quota_identity(id INTEGER PRIMARY KEY CHECK(id=1), relay_id TEXT NOT NULL);
                CREATE TABLE quota_local(user_id TEXT PRIMARY KEY NOT NULL, state TEXT NOT NULL);
                PRAGMA user_version=2; COMMIT;")?;
        }
        connection.execute(
            "INSERT OR IGNORE INTO quota_identity VALUES(1,?)",
            [uuid::Uuid::new_v4().to_string()],
        )?;
        let sink = sink.trim_end_matches('/');
        connection.execute(
            "INSERT OR IGNORE INTO destination(id,sink) VALUES(1,?)",
            [sink],
        )?;
        let existing: String =
            connection.query_row("SELECT sink FROM destination WHERE id=1", [], |row| {
                row.get(0)
            })?;
        anyhow::ensure!(
            existing == sink,
            "usage journal belongs to a different control plane"
        );
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            writers: Arc::new(Semaphore::new(64)),
            healthy: Arc::new(AtomicBool::new(true)),
        })
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    pub(crate) async fn execute<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self.writers.clone().acquire_owned().await?;
        let connection = self.connection.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut connection = connection
                .lock()
                .map_err(|_| anyhow::anyhow!("usage journal lock poisoned"))?;
            work(&mut connection)
        })
        .await
        .context("usage journal worker failed")?;
        self.healthy.store(result.is_ok(), Ordering::Release);
        result
    }

    /// Persist a completed observation before it is eligible for reporting.
    pub async fn record(
        &self,
        tunnel_id: String,
        user_id: String,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Result<()> {
        self.record_delta(tunnel_id, user_id, bytes_in, bytes_out, 1)
            .await
    }

    /// Byte-stream observations do not count each buffer as a request. A TCP,
    /// TLS or WebSocket opening counts once; each public UDP datagram counts once.
    pub async fn record_delta(
        &self,
        tunnel_id: String,
        user_id: String,
        bytes_in: u64,
        bytes_out: u64,
        request_count: u64,
    ) -> Result<()> {
        let observation = Observation {
            tunnel_id,
            user_id,
            bytes_in,
            bytes_out,
            request_count,
            timestamp: chrono::Utc::now().timestamp().max(0) as u64,
            quota_accounted: false,
        };
        self.execute(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            observation.record(&tx)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Freeze counters and report IDs in one transaction before any network send.
    /// Existing pending rows always win, so retries cannot absorb newer traffic.
    pub async fn batch(&self) -> Result<Vec<UsageReport>> {
        self.execute(|connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM outbox)", [], |row| row.get(0))?;
            if !pending {
                let rows = {
                    let mut statement = tx.prepare("SELECT tunnel_id,user_id,bytes_in,bytes_out,request_count,timestamp,quota_accounted FROM counters ORDER BY tunnel_id LIMIT 500")?;
                    let rows = statement.query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,u64>(2)?,row.get::<_,u64>(3)?,row.get::<_,u64>(4)?,row.get::<_,u64>(5)?,row.get::<_,bool>(6)?)))?;
                    rows.collect::<rusqlite::Result<Vec<_>>>()?
                };
                for (tunnel,user,incoming,outgoing,count,timestamp,accounted) in rows {
                    tx.execute("INSERT INTO outbox(report_id,tunnel_id,user_id,bytes_in,bytes_out,request_count,timestamp,quota_accounted) VALUES(?,?,?,?,?,?,?,?)",
                        params![uuid::Uuid::new_v4().to_string(),tunnel,user,incoming,outgoing,count,timestamp,accounted])?;
                    tx.execute("DELETE FROM counters WHERE tunnel_id=? AND timestamp=? AND quota_accounted=?", params![tunnel,timestamp,accounted])?;
                }
            }
            let reports = {
                let mut statement = tx.prepare("SELECT report_id,tunnel_id,user_id,bytes_in,bytes_out,request_count,timestamp,quota_accounted FROM outbox ORDER BY sequence LIMIT ?")?;
                let rows = statement.query_map([BATCH_SIZE], |row| Ok(UsageReport {
                    report_id:row.get(0)?,tunnel_id:row.get(1)?,user_id:row.get(2)?,bytes_in:row.get(3)?,bytes_out:row.get(4)?,request_count:row.get(5)?,timestamp:row.get(6)?,quota_accounted:row.get(7)?,
                }))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.commit()?;
            Ok(reports)
        }).await
    }

    /// Only called after a complete remote acknowledgement. A crash before this
    /// commit simply resends the same IDs; the Worker deduplicates those reports.
    pub async fn acknowledge(&self, reports: &[UsageReport]) -> Result<()> {
        let ids: Vec<_> = reports
            .iter()
            .map(|report| report.report_id.clone())
            .collect();
        self.execute(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for id in ids {
                tx.execute("DELETE FROM outbox WHERE report_id=?", [id])?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }
}

/// Shared transaction boundary for ordinary observations and quota consumption.
pub(crate) struct Observation {
    pub tunnel_id: String,
    pub user_id: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub request_count: u64,
    pub timestamp: u64,
    pub quota_accounted: bool,
}

impl Observation {
    pub fn record(&self, tx: &rusqlite::Transaction<'_>) -> Result<()> {
        uuid::Uuid::parse_str(&self.tunnel_id)
            .context("canonical tunnel UUID required for usage")?;
        uuid::Uuid::parse_str(&self.user_id).context("canonical owner UUID required for usage")?;
        let owner: Option<String> = tx.query_row(
            "SELECT user_id FROM counters WHERE tunnel_id=?1 UNION SELECT user_id FROM outbox WHERE tunnel_id=?1 LIMIT 1",
            [&self.tunnel_id], |row| row.get(0)).optional()?;
        anyhow::ensure!(
            owner.as_ref().is_none_or(|owner| *owner == self.user_id),
            "usage owner cannot change"
        );
        let minute = (self.timestamp / 60) * 60;
        let queued: i64 = tx.query_row(
            "SELECT (SELECT count(*) FROM counters)+(SELECT count(*) FROM outbox)",
            [],
            |row| row.get(0),
        )?;
        anyhow::ensure!(queued < MAX_REPORTS || tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM counters WHERE tunnel_id=? AND timestamp=? AND quota_accounted=?)",
            params![self.tunnel_id, minute, self.quota_accounted], |row| row.get::<_, bool>(0))?, "usage journal backlog limit reached");
        tx.execute("INSERT INTO counters VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(tunnel_id,timestamp,quota_accounted) DO UPDATE SET bytes_in=bytes_in+excluded.bytes_in,
            bytes_out=bytes_out+excluded.bytes_out, request_count=request_count+excluded.request_count",
            params![self.tunnel_id,self.user_id,i64::try_from(self.bytes_in)?,i64::try_from(self.bytes_out)?,
                i64::try_from(self.request_count)?,minute,self.quota_accounted])?;
        Ok(())
    }
}
