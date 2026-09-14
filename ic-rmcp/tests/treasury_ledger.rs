//! Integration test for the `treasury` module against a real ICRC-1 ledger
//! canister running inside PocketIC.
//!
//! This test needs external artifacts that are not part of the repository:
//!
//! - `POCKET_IC_BIN`  — path to a `pocket-ic` server binary (>= 16.0.0)
//!   (<https://github.com/dfinity/pocketic/releases>)
//! - `ICRC1_LEDGER_WASM` — path to a `ic-icrc1-ledger` canister wasm
//!   (e.g. `https://download.dfinity.systems/ic/<release-sha>/canisters/ic-icrc1-ledger.wasm.gz`)
//! - `TREASURY_WASM` — path to the compiled `treasury` example canister
//!   (defaults to `../../target/wasm32-unknown-unknown/release/treasury.wasm`,
//!   build with `cargo build --release -p treasury --target wasm32-unknown-unknown`)
//!
//! If the artifacts are absent the test exits early with instructions, so
//! `cargo test` stays green in CI. Run it for real with:
//!
//! ```sh
//! cargo build --release -p treasury --target wasm32-unknown-unknown
//! POCKET_IC_BIN=/path/to/pocket-ic ICRC1_LEDGER_WASM=/path/to/ic-icrc1-ledger.wasm \
//!   cargo test -p ic-rmcp --test treasury_ledger -- --nocapture
//! ```

use candid::{utils::ArgumentEncoder, CandidType, Nat, Principal};
use ic_rmcp::treasury::{Account, TransferError, TreasuryError};
use pocket_ic::PocketIc;
use std::path::PathBuf;

// `candid::encode_one`/`encode_args` return `Result`; test args are statically
// valid, so unwrap them through these helpers.
fn encode_one<T: CandidType>(arg: T) -> Vec<u8> {
    candid::encode_one(arg).expect("failed to candid-encode test arg")
}

fn encode_args<Tuple: ArgumentEncoder>(args: Tuple) -> Vec<u8> {
    candid::encode_args(args).expect("failed to candid-encode test args")
}

// ---- Ledger init types (subset of ic-icrc1-ledger.did) ---------------------
// A single-variant `LedgerArg` carrying only `Init` is a valid candid subtype
// of the ledger's `variant { Init : InitArgs; Upgrade : opt UpgradeArgs }`.

// Some variants are never constructed in this test; they exist so the candid
// type descriptor matches the ledger's `MetadataValue` definition.
#[allow(dead_code)]
#[derive(CandidType)]
enum MetadataValue {
    Nat(Nat),
    Int(candid::Int),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(CandidType)]
struct FeatureFlags {
    icrc2: bool,
    icrc152: bool,
}

#[derive(CandidType)]
struct ArchiveOptions {
    num_blocks_to_archive: u64,
    max_transactions_per_response: Option<u64>,
    trigger_threshold: u64,
    max_message_size_bytes: Option<u64>,
    cycles_for_archive_creation: Option<u64>,
    node_max_memory_size_bytes: Option<u64>,
    controller_id: Principal,
    more_controller_ids: Option<Vec<Principal>>,
}

#[derive(CandidType)]
struct InitArgs {
    minting_account: Account,
    fee_collector_account: Option<Account>,
    transfer_fee: Nat,
    decimals: Option<u8>,
    max_memo_length: Option<u16>,
    token_symbol: String,
    token_name: String,
    metadata: Vec<(String, MetadataValue)>,
    initial_balances: Vec<(Account, Nat)>,
    feature_flags: Option<FeatureFlags>,
    archive_options: ArchiveOptions,
    index_principal: Option<Principal>,
}

#[derive(CandidType)]
enum LedgerArg {
    Init(InitArgs),
}

// ---- helpers ---------------------------------------------------------------

fn artifact(name: &str, env: &str, default: Option<PathBuf>) -> Option<Vec<u8>> {
    let path = std::env::var(env)
        .ok()
        .map(PathBuf::from)
        .or(default)
        .or_else(|| {
            // Also try the shared test-assets directory used when developing.
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let candidate = manifest.join("../test-assets").join(name);
            candidate.exists().then_some(candidate)
        })?;
    let bytes = std::fs::read(&path).ok()?;
    // Transparently decompress gzip artifacts (dfinity ships .wasm.gz).
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(decompress_gzip(&bytes));
    }
    Some(bytes)
}

fn decompress_gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .expect("failed to decompress gzip artifact");
    out
}

fn default_treasury_wasm() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest.join("../target/wasm32-unknown-unknown/release/treasury.wasm");
    candidate.exists().then_some(candidate)
}

fn non_owner() -> Principal {
    Principal::self_authenticating(b"treasury-test-non-owner")
}

fn withdraw_arg() -> (Nat, Account) {
    (
        Nat::from(100_000u32),
        Account {
            owner: non_owner(),
            subaccount: None,
        },
    )
}

#[test]
fn treasury_module_interacts_with_live_icrc1_ledger() {
    if std::env::var("POCKET_IC_BIN").is_err() {
        eprintln!(
            "skipping: POCKET_IC_BIN is not set (see this test's doc comment \
             for the required artifacts)"
        );
        return;
    }
    let Some(ledger_wasm) = artifact("ic-icrc1-ledger.wasm", "ICRC1_LEDGER_WASM", None) else {
        eprintln!("skipping: no ICRC-1 ledger wasm (set ICRC1_LEDGER_WASM)");
        return;
    };
    let Some(treasury_wasm) = artifact("treasury.wasm", "TREASURY_WASM", default_treasury_wasm())
    else {
        eprintln!(
            "skipping: treasury example canister not built \
             (cargo build --release -p treasury --target wasm32-unknown-unknown)"
        );
        return;
    };

    let pic = PocketIc::new();
    let owner = Principal::anonymous();

    // 1. Deploy a real ICRC-1 ledger, minting tokens to the treasury
    //    canister's default account.
    let ledger = pic.create_canister();
    pic.add_cycles(ledger, 2_000_000_000_000);
    let treasury_canister = pic.create_canister();
    pic.add_cycles(treasury_canister, 2_000_000_000_000);

    let init = LedgerArg::Init(InitArgs {
        minting_account: Account {
            owner,
            subaccount: None,
        },
        fee_collector_account: None,
        transfer_fee: Nat::from(10_000u32),
        decimals: Some(8),
        max_memo_length: None,
        token_symbol: "TST".to_string(),
        token_name: "Treasury Test Token".to_string(),
        metadata: vec![],
        initial_balances: vec![
            (
                Account {
                    owner: treasury_canister,
                    subaccount: None,
                },
                Nat::from(1_000_000u32),
            ),
            (
                Account {
                    owner,
                    subaccount: None,
                },
                Nat::from(10_000u32),
            ),
        ],
        feature_flags: Some(FeatureFlags {
            icrc2: true,
            icrc152: false,
        }),
        archive_options: ArchiveOptions {
            num_blocks_to_archive: 1_000,
            max_transactions_per_response: None,
            trigger_threshold: 2_000,
            max_message_size_bytes: None,
            cycles_for_archive_creation: None,
            node_max_memory_size_bytes: None,
            controller_id: owner,
            more_controller_ids: None,
        },
        index_principal: None,
    });
    pic.install_canister(ledger, ledger_wasm, encode_one(&init), None);

    // 2. Deploy the treasury example canister; the deployer becomes owner.
    pic.install_canister(treasury_canister, treasury_wasm, encode_args(()), None);

    // 3. get_owner reports the deployer.
    let bytes = pic
        .query_call(treasury_canister, owner, "get_owner", encode_one(()))
        .expect("get_owner call failed");
    let reported: Principal = candid::decode_one(&bytes).unwrap();
    assert_eq!(reported, owner);

    // 4. set_owner is owner-gated: a stranger is rejected, the owner succeeds.
    let bytes = pic
        .update_call(
            treasury_canister,
            non_owner(),
            "set_owner",
            encode_one(non_owner()),
        )
        .expect("set_owner call failed");
    let result: Result<(), TreasuryError> = candid::decode_one(&bytes).unwrap();
    assert_eq!(result, Err(TreasuryError::NotOwner));

    // 5. get_treasury_balance reports the real ledger balance.
    let bytes = pic
        .update_call(
            treasury_canister,
            non_owner(), // public endpoint: any caller may use it
            "get_treasury_balance",
            encode_one(ledger),
        )
        .expect("get_treasury_balance call failed");
    let balance: Nat = candid::decode_one(&bytes).unwrap();
    assert_eq!(balance, Nat::from(1_000_000u32));

    // 6. withdraw is owner-gated.
    let (amount, destination) = withdraw_arg();
    let bytes = pic
        .update_call(
            treasury_canister,
            non_owner(),
            "withdraw",
            encode_args((ledger, amount.clone(), destination.clone())),
        )
        .expect("withdraw call failed");
    let result: Result<Nat, TreasuryError> = candid::decode_one(&bytes).unwrap();
    assert_eq!(result, Err(TreasuryError::NotOwner));

    // 7. The owner can withdraw; the ledger returns a real block index and
    //    the funds land in the destination account.
    let bytes = pic
        .update_call(
            treasury_canister,
            owner,
            "withdraw",
            encode_args((ledger, amount, destination.clone())),
        )
        .expect("withdraw call failed");
    let result: Result<Nat, TreasuryError> = candid::decode_one(&bytes).unwrap();
    let block_index = result.expect("withdraw failed");
    assert!(block_index > 0u32);

    let bytes = pic
        .query_call(ledger, owner, "icrc1_balance_of", encode_one(&destination))
        .expect("ledger balance call failed");
    let dest_balance: Nat = candid::decode_one(&bytes).unwrap();
    // The destination receives the full `amount`; the ledger charges the
    // 10_000 transfer fee on top of it from the treasury's account.
    assert_eq!(dest_balance, Nat::from(100_000u32));

    let treasury_account = Account {
        owner: treasury_canister,
        subaccount: None,
    };
    let bytes = pic
        .query_call(
            ledger,
            owner,
            "icrc1_balance_of",
            encode_one(&treasury_account),
        )
        .expect("ledger balance call failed");
    let remaining: Nat = candid::decode_one(&bytes).unwrap();
    assert_eq!(remaining, Nat::from(1_000_000u32 - 100_000 - 10_000));

    // 8. Withdrawing more than the remaining balance fails with
    //    InsufficientFunds from the real ledger.
    let bytes = pic
        .update_call(
            treasury_canister,
            owner,
            "withdraw",
            encode_args((ledger, Nat::from(100_000_000u32), destination.clone())),
        )
        .expect("withdraw call failed");
    let result: Result<Nat, TreasuryError> = candid::decode_one(&bytes).unwrap();
    assert!(matches!(
        result,
        Err(TreasuryError::TransferFailed(
            TransferError::InsufficientFunds { .. }
        ))
    ));

    // 9. Ownership transfer: old owner loses access, new owner gains it.
    let bytes = pic
        .update_call(
            treasury_canister,
            owner,
            "set_owner",
            encode_one(non_owner()),
        )
        .expect("set_owner call failed");
    let result: Result<(), TreasuryError> = candid::decode_one(&bytes).unwrap();
    assert_eq!(result, Ok(()));

    let bytes = pic
        .update_call(
            treasury_canister,
            owner, // previous owner is no longer authorized
            "withdraw",
            encode_args((ledger, Nat::from(1u32), destination)),
        )
        .expect("withdraw call failed");
    let result: Result<Nat, TreasuryError> = candid::decode_one(&bytes).unwrap();
    assert_eq!(result, Err(TreasuryError::NotOwner));
}
