use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{CreditClock, Grant, Reservation};
use crate::usage_journal::{Observation, UsageJournal};

#[derive(Clone, Serialize, Deserialize)]
pub(super) enum State {
    Pending(Reservation),
    Active {
        grant: Grant,
        bytes: u64,
        requests: u64,
    },
    Sealed {
        grant: Grant,
        bytes: u64,
        requests: u64,
    },
}

impl State {
    pub fn id(&self) -> &str {
        match self {
            Self::Pending(request) => &request.id,
            Self::Active { grant, .. } | Self::Sealed { grant, .. } => &grant.request.id,
        }
    }
}

fn read(connection: &Connection, user: &str) -> Result<Option<State>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT state FROM quota_local WHERE user_id=?",
            [user],
            |row| row.get(0),
        )
        .optional()?;
    json.map(|json| serde_json::from_str(&json).context("invalid durable quota state"))
        .transpose()
}

fn write(connection: &Connection, user: &str, state: &State) -> Result<()> {
    connection.execute("INSERT INTO quota_local VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET state=excluded.state",
        params![user,serde_json::to_string(state)?])?;
    Ok(())
}

impl UsageJournal {
    pub(super) async fn relay_identity(&self) -> Result<String> {
        self.execute(|db| {
            Ok(db.query_row(
                "SELECT relay_id FROM quota_identity WHERE id=1",
                [],
                |row| row.get(0),
            )?)
        })
        .await
    }

    pub(super) async fn quota_users(&self) -> Result<Vec<String>> {
        self.execute(|db| {
            let mut statement = db.prepare("SELECT user_id FROM quota_local ORDER BY user_id")?;
            let users = statement
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(users)
        })
        .await
    }

    pub(super) async fn quota_state(&self, user: String) -> Result<Option<State>> {
        self.execute(move |db| read(db, &user)).await
    }

    pub(super) async fn quota_pending(&self, request: Reservation) -> Result<()> {
        self.execute(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if read(&tx, &request.user_id)?.is_none() {
                let count: i64 =
                    tx.query_row("SELECT count(*) FROM quota_local", [], |row| row.get(0))?;
                anyhow::ensure!(count < 20_000, "quota recovery backlog limit reached");
                write(&tx, &request.user_id, &State::Pending(request.clone()))?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub(super) async fn quota_accept(&self, grant: Grant) -> Result<bool> {
        self.execute(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if !matches!(read(&tx, &grant.request.user_id)?, Some(State::Pending(ref request)) if *request == grant.request) {
                return Ok(false);
            }
            let state = State::Active { bytes: grant.bytes, requests: grant.requests, grant: grant.clone() };
            write(&tx, &grant.request.user_id, &state)?;
            tx.commit()?;
            Ok(true)
        }).await
    }

    pub(super) async fn quota_forget(&self, user: String, id: String) -> Result<()> {
        self.execute(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if read(&tx, &user)?.is_some_and(|state| state.id() == id) {
                tx.execute("DELETE FROM quota_local WHERE user_id=?", [&user])?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Seal under the same write lock used by consumption. After this commits,
    /// even an already queued/deadline-cancelled consumer cannot spend the grant.
    pub(super) async fn quota_seal(&self, user: String) -> Result<()> {
        self.execute(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(State::Active {
                grant,
                bytes,
                requests,
            }) = read(&tx, &user)?
            {
                write(
                    &tx,
                    &user,
                    &State::Sealed {
                        grant,
                        bytes,
                        requests,
                    },
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub(super) async fn quota_consume(
        &self,
        id: String,
        clock: CreditClock,
        mut observation: Observation,
    ) -> Result<bool> {
        self.execute(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let Some(State::Active {
                grant,
                mut bytes,
                mut requests,
            }) = read(&tx, &observation.user_id)?
            else {
                return Ok(false);
            };
            let needed = observation
                .bytes_in
                .checked_add(observation.bytes_out)
                .context("quota observation overflow")?;
            if grant.request.id != id
                || !clock.valid()
                || bytes < needed.max(u64::from(observation.request_count > 0))
                || requests < observation.request_count
            {
                return Ok(false);
            }
            bytes -= needed;
            requests -= observation.request_count;
            observation.timestamp = clock.timestamp();
            observation.quota_accounted = true;
            observation.record(&tx)?;
            write(
                &tx,
                &observation.user_id,
                &State::Active {
                    grant,
                    bytes,
                    requests,
                },
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await
    }
}
