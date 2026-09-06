//! App startup coverage for the shared process-local keyring boundary.
use crate::database::SecureStorage;
use std::sync::Arc;

struct RestoreDefaultStore(Option<Arc<keyring_core::CredentialStore>>);

impl Drop for RestoreDefaultStore {
    fn drop(&mut self) {
        keyring_core::unset_default_store();
        if let Some(previous) = self.0.take() {
            keyring_core::set_default_store(previous);
        }
    }
}

#[tokio::test]
async fn process_local_storage_does_not_initialize_or_replace_the_platform_store() {
    let _guard = crate::TEST_KEYRING_LOCK.lock().await;
    let previous = keyring_core::unset_default_store();
    let _restore = RestoreDefaultStore(previous);
    let missing =
        SecureStorage::new_with_process_local_keyring(tempfile::tempdir().unwrap().path())
            .err()
            .expect("an explicitly installed process-local store is required");
    assert!(missing.to_string().contains("no default store"));

    let store: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new().unwrap();
    let expected_id = store.id();
    keyring_core::set_default_store(store);
    let temporary = tempfile::tempdir().unwrap();
    let _storage = SecureStorage::new_with_process_local_keyring(temporary.path())
        .expect("the process-local store must support app storage startup");

    let selected = keyring_core::get_default_store().expect("store must remain installed");
    assert_eq!(selected.id(), expected_id);
    assert!(matches!(
        selected.persistence(),
        keyring_core::CredentialPersistence::ProcessOnly
    ));
}
