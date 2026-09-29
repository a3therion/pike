use super::*;

fn config() -> AcmeConfig {
    AcmeConfig {
        directory_url: "https://acme.example.com/directory".into(),
        contact_email: "operator@example.com".into(),
        terms_of_service_agreed: true,
        storage_dir: "/unused".into(),
        shared: None,
        directory_ca_path: None,
        certificate_ca_path: None,
        renew_before_secs: renew_default(),
        retry_secs: retry_default(),
    }
}

#[test]
fn configuration_requires_explicit_consent_and_secure_directory() {
    let mut value = config();
    assert!(value.validate().is_ok());
    value.terms_of_service_agreed = false;
    assert!(value.validate().is_err());
    value.terms_of_service_agreed = true;
    for url in [
        "http://acme.example.com",
        "https://user:pass@acme.example.com",
        "https://acme.example.com/#fragment",
        "https://acme.example.com/?secret=key",
    ] {
        value.directory_url = url.into();
        assert!(value.validate().is_err(), "{url}");
    }
    value = config();
    value.retry_secs = 0;
    assert!(value.validate().is_err());
}

#[tokio::test]
async fn challenges_are_exact_and_cannot_replace_existing_proofs() {
    let store = Certificates::disabled();
    let lease = store
        .authorize(
            "one.example.com",
            "owner",
            VisitorGate::unrestricted(),
            None,
        )
        .unwrap();
    let proof = |value: &str| Challenge {
        authority: lease.entry.authority.clone(),
        token: "token".into(),
        value: value.into(),
    };
    let guard = store.challenges.publish(proof("first")).unwrap();
    assert!(store.challenges.publish(proof("replacement")).is_err());
    assert_eq!(
        store.challenge("one.example.com", "token").await.as_deref(),
        Some("first")
    );
    assert!(store.challenge("two.example.com", "token").await.is_none());
    assert!(store
        .challenge("one.example.com", "different")
        .await
        .is_none());
    drop(guard);
    assert!(store.challenge("one.example.com", "token").await.is_none());
}

#[tokio::test]
async fn withdrawal_hides_challenges_and_old_cleanup_preserves_new_owner() {
    let store = Certificates::disabled();
    let lease = store
        .authorize("one.example.com", "old", VisitorGate::unrestricted(), None)
        .unwrap();
    let old = lease.entry.authority.clone();
    let proof = store
        .challenges
        .publish(Challenge {
            authority: old.clone(),
            token: "old-token".into(),
            value: "old-proof".into(),
        })
        .unwrap();
    assert!(store
        .authorize("one.example.com", "new", VisitorGate::unrestricted(), None)
        .is_err());
    drop(lease);
    assert!(store
        .challenge("one.example.com", "old-token")
        .await
        .is_none());
    old.cancelled().await;
    let replacement = store
        .authorize("one.example.com", "new", VisitorGate::unrestricted(), None)
        .unwrap();
    assert!(store
        .challenges
        .publish(Challenge {
            authority: old,
            token: "late".into(),
            value: "late-proof".into()
        })
        .is_err());
    drop(proof);
    assert!(replacement.entry.authority.active());
    assert_eq!(
        store.status("one.example.com").await.unwrap().state,
        "unconfigured"
    );
}

#[tokio::test]
async fn domain_and_visitor_revocation_each_cancel_certificate_authority() {
    let store = Certificates::disabled();
    let domains =
        crate::domain_grants::DomainGrants::from_operator(&["one.example.com".into()], "pike.test")
            .unwrap();
    let gate = VisitorGate::unrestricted();
    let lease = store
        .authorize(
            "one.example.com",
            "owner",
            gate.clone(),
            Some(domains.hosts().next().unwrap().1.clone()),
        )
        .unwrap();
    domains.close();
    lease.entry.authority.cancelled().await;
    assert!(!lease.entry.authority.active());
    assert!(store.status("one.example.com").await.is_none());
    drop(lease);
    let lease = store
        .authorize("one.example.com", "owner", gate.clone(), None)
        .unwrap();
    gate.close();
    lease.entry.authority.cancelled().await;
    assert!(!lease.entry.authority.active());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("pike-acme-storage-{}", uuid::Uuid::new_v4())))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn storage_replaces_atomically_and_excludes_second_writer() {
    let dir = Directory::new();
    let storage = storage::Storage::open(&dir.0).unwrap();
    assert!(storage::Storage::open(&dir.0).is_err());
    storage
        .write("account.json", &serde_json::json!({"key": "first"}))
        .unwrap();
    storage
        .write("account.json", &serde_json::json!({"key": "second"}))
        .unwrap();
    assert_eq!(
        storage
            .read::<serde_json::Value>("account.json")
            .unwrap()
            .unwrap()["key"],
        "second"
    );
    assert!(storage.write("../outside.json", &0).is_err());
    assert!(storage.write("account.json", &"a".repeat(131_073)).is_err());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    drop(storage);
    assert!(storage::Storage::open(&dir.0).is_ok());
}

#[cfg(unix)]
#[test]
fn storage_rejects_symlinks_and_permissive_secret_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = Directory::new();
    let storage = storage::Storage::open(&dir.0).unwrap();
    assert_eq!(
        std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    storage.write("secret.json", &"key").unwrap();
    let file = dir.0.join("secret.json");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    symlink(&file, dir.0.join("linked.json")).unwrap();
    assert!(storage.read::<String>("linked.json").is_err());
    assert!(storage.write("linked.json", &"replacement").is_err());
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(storage.read::<String>("secret.json").is_err());
    drop(storage);
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(storage::Storage::open(&dir.0).is_err());
}
