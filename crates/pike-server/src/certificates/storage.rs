//! One locked, private directory; each certificate/key pair is one atomic file.
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(super) struct Storage {
    root: PathBuf,
    _lock: File,
}
impl Storage {
    pub fn open(root: &Path) -> Result<Self> {
        ensure!(
            cfg!(unix),
            "ACME storage currently requires Unix filesystem permissions"
        );
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder
            .create(root)
            .context("create ACME state directory")?;
        let meta = std::fs::symlink_metadata(root)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "ACME state must be a real directory"
        );
        #[cfg(unix)]
        ensure!(
            meta.permissions().mode() & 0o777 == 0o700,
            "ACME state directory must have mode 0700"
        );
        let path = root.join("lock");
        reject_link(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let lock = options.open(path)?;
        FileExt::try_lock_exclusive(&lock)
            .context("ACME state is already used by another relay")?;
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
        })
    }
    pub fn certificate_name(host: &str) -> String {
        format!("certificate-{:x}.json", Sha256::digest(host.as_bytes()))
    }
    pub fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.path(name)?;
        reject_link(&path)?;
        let mut input = match File::open(&path) {
            Ok(input) => input,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let meta = input.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= 131_072,
            "ACME state is not a bounded regular file"
        );
        #[cfg(unix)]
        ensure!(
            meta.permissions().mode() & 0o777 == 0o600,
            "ACME secret files must have mode 0600"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut input)
            .take(131_073)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 131_072, "ACME state exceeds limit");
        Ok(Some(
            serde_json::from_slice(&bytes).context("invalid ACME state")?,
        ))
    }
    pub fn write(&self, name: &str, value: &impl Serialize) -> Result<()> {
        let destination = self.path(name)?;
        reject_link(&destination)?;
        let bytes = serde_json::to_vec(value)?;
        ensure!(bytes.len() <= 131_072, "ACME state exceeds limit");
        let temporary = self.root.join(format!(".pending-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, destination)?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                && name != "."
                && name != "..",
            "invalid ACME state filename"
        );
        Ok(self.root.join(name))
    }
}
fn reject_link(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "ACME state file must not be a symlink or special file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
