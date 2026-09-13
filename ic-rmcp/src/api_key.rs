//! Self-service API-key management for MCP canisters.
//!
//! The module stores only SHA-256 hashes of API keys. A raw key is returned
//! exactly once by [`create_my_api_key`]; callers should treat it like a
//! password and never persist it in canister state or logs.

use candid::{CandidType, Principal};
use ic_cdk::management_canister::raw_rand;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

/// The hexadecimal SHA-256 digest used as the storage key for an API key.
pub type HashedApiKey = String;

/// Metadata associated with one API key.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct ApiKeyInfo {
    /// Principal represented by the key.
    pub principal: Principal,
    /// Application-defined permissions granted to the key.
    pub scopes: Vec<String>,
    /// Human-readable label for the key.
    pub name: String,
    /// Creation time in IC nanoseconds.
    pub created: i64,
}

/// Key metadata returned to its owner. The raw key is intentionally absent.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct ApiKeyMetadata {
    pub hashed_key: HashedApiKey,
    pub info: ApiKeyInfo,
}

/// Errors returned by API-key operations.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum ApiKeyError {
    /// The management canister could not provide secure randomness.
    Randomness(String),
    /// The caller tried to revoke a key owned by another principal.
    Unauthorized,
}

impl fmt::Display for ApiKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Randomness(error) => write!(formatter, "randomness request failed: {error}"),
            Self::Unauthorized => formatter.write_str("you can only revoke your own API keys"),
        }
    }
}

/// Mutable API-key store.
pub struct ApiKeyState {
    /// Administrative owner retained for applications that also expose
    /// owner-gated key management. Self-service operations do not use it.
    pub owner: Principal,
    api_keys: HashMap<HashedApiKey, ApiKeyInfo>,
}

/// Handle used by the free functions in this module.
pub struct ApiKeyContext {
    state: Rc<RefCell<ApiKeyState>>,
}

impl ApiKeyContext {
    /// Creates an empty API-key store.
    pub fn new(owner: Principal) -> Self {
        Self {
            state: Rc::new(RefCell::new(ApiKeyState {
                owner,
                api_keys: HashMap::new(),
            })),
        }
    }
}

/// Creates an empty API-key context.
pub fn init(owner: Principal) -> ApiKeyContext {
    ApiKeyContext::new(owner)
}

/// Creates a key for `caller` using IC-provided cryptographic randomness.
///
/// The returned hexadecimal value is the only raw-key representation produced
/// by this module. The store receives only its SHA-256 digest and metadata.
/// `caller` must come from a verified canister call context (normally
/// `ic_cdk::caller()`), never from client-supplied request data.
///
/// Testing the `raw_rand` failure branch requires PocketIC-style integration
/// infrastructure that can inject a management-canister failure. Unit tests
/// use the deterministic internal helper so they do not make an inter-canister
/// call.
pub async fn create_my_api_key(
    context: &ApiKeyContext,
    caller: Principal,
    name: impl Into<String>,
    scopes: Vec<String>,
) -> Result<String, ApiKeyError> {
    let random_bytes = raw_rand()
        .await
        .map_err(|error| ApiKeyError::Randomness(error.to_string()))?;
    create_api_key_from_random(
        context,
        caller,
        name,
        scopes,
        &random_bytes,
        ic_cdk::api::time() as i64,
    )
}

/// Lists only the metadata belonging to `caller`.
///
/// `caller` must come from a verified canister call context (normally
/// `ic_cdk::caller()`), never from client-supplied request data.
pub fn list_my_api_keys(context: &ApiKeyContext, caller: Principal) -> Vec<ApiKeyMetadata> {
    let mut metadata: Vec<_> = context
        .state
        .borrow()
        .api_keys
        .iter()
        .filter(|(_, info)| info.principal == caller)
        .map(|(hashed_key, info)| ApiKeyMetadata {
            hashed_key: hashed_key.clone(),
            info: info.clone(),
        })
        .collect();
    metadata.sort_by(|left, right| left.hashed_key.cmp(&right.hashed_key));
    metadata
}

/// Revokes a key if it belongs to `caller`.
///
/// Revoking an unknown key is idempotent. A key belonging to another
/// principal returns [`ApiKeyError::Unauthorized`] and remains untouched.
/// `caller` must come from a verified canister call context (normally
/// `ic_cdk::caller()`), never from client-supplied request data.
pub fn revoke_my_api_key(
    context: &ApiKeyContext,
    caller: Principal,
    hashed_key: &str,
) -> Result<(), ApiKeyError> {
    let mut state = context.state.borrow_mut();
    match state.api_keys.get(hashed_key) {
        Some(info) if info.principal != caller => Err(ApiKeyError::Unauthorized),
        Some(_) => {
            state.api_keys.remove(hashed_key);
            Ok(())
        }
        None => Ok(()),
    }
}

fn create_api_key_from_random(
    context: &ApiKeyContext,
    caller: Principal,
    name: impl Into<String>,
    scopes: Vec<String>,
    random_bytes: &[u8],
    created: i64,
) -> Result<String, ApiKeyError> {
    let raw_key = hex::encode(random_bytes);
    let hashed_key = hex::encode(Sha256::digest(random_bytes));
    let info = ApiKeyInfo {
        principal: caller,
        scopes,
        name: name.into(),
        created,
    };

    context.state.borrow_mut().api_keys.insert(hashed_key, info);
    Ok(raw_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(text: &str) -> Principal {
        Principal::from_text(text).unwrap()
    }

    #[test]
    fn lifecycle_keeps_raw_keys_out_of_metadata_and_enforces_ownership() {
        let owner = principal("2vxsx-fae");
        let other = principal("rrkah-fqaaa-aaaaa-aaaaq-cai");
        let context = init(owner);
        let raw_key = create_api_key_from_random(
            &context,
            owner,
            "Analytics service",
            vec!["read:usage".to_string(), "write:usage".to_string()],
            &[1, 2, 3, 4],
            123,
        )
        .unwrap();

        assert_eq!(raw_key, "01020304");
        let metadata = list_my_api_keys(&context, owner);
        assert_eq!(metadata.len(), 1);
        assert_ne!(metadata[0].hashed_key, raw_key);
        assert_eq!(metadata[0].info.principal, owner);
        assert_eq!(metadata[0].info.created, 123);
        assert!(list_my_api_keys(&context, other).is_empty());

        let hashed_key = metadata[0].hashed_key.clone();
        assert_eq!(
            revoke_my_api_key(&context, other, &hashed_key),
            Err(ApiKeyError::Unauthorized)
        );
        assert_eq!(list_my_api_keys(&context, owner).len(), 1);
        assert_eq!(revoke_my_api_key(&context, owner, &hashed_key), Ok(()));
        assert!(list_my_api_keys(&context, owner).is_empty());
        assert_eq!(revoke_my_api_key(&context, owner, &hashed_key), Ok(()));
    }

    #[test]
    fn each_random_value_produces_a_distinct_hashed_key() {
        let owner = principal("2vxsx-fae");
        let context = init(owner);
        let first =
            create_api_key_from_random(&context, owner, "first", vec![], &[0; 32], 1).unwrap();
        let second =
            create_api_key_from_random(&context, owner, "second", vec![], &[1; 32], 2).unwrap();

        assert_ne!(first, second);
        assert_eq!(list_my_api_keys(&context, owner).len(), 2);
    }
}
