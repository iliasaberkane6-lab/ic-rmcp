//! Owner management and ICRC-1 treasury functions for MCP canisters.
//!
//! This module mirrors `Payments.mo` and the main server actor of the Motoko
//! SDK: a canister stores its `owner` principal, lets the owner transfer
//! ownership, reports the canister's ICRC-1 token balance, and lets the owner
//! withdraw funds to an external account.
//!
//! All functions take `caller` explicitly. It must come from a verified
//! canister call context (normally `ic_cdk::api::msg_caller()`), never from
//! client-supplied request data.

use candid::{CandidType, Nat, Principal};
use ic_cdk::call::Call;
use serde::Deserialize;
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

/// An ICRC-1 ledger account.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Account {
    /// Account owner principal.
    pub owner: Principal,
    /// Optional 32-byte subaccount.
    pub subaccount: Option<[u8; 32]>,
}

/// Errors returned by an ICRC-1 `icrc1_transfer` call.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum TransferError {
    /// The supplied fee does not match the ledger's current fee.
    BadFee { expected_fee: Nat },
    /// The burn amount is below the ledger minimum.
    BadBurn { min_burn_amount: Nat },
    /// The canister's account does not hold enough tokens.
    InsufficientFunds { balance: Nat },
    /// The transfer's `created_at_time` is too far in the past.
    TooOld,
    /// The transfer's `created_at_time` is in the future.
    CreatedInFuture { ledger_time: u64 },
    /// An identical transfer was already recorded.
    Duplicate { duplicate_of: Nat },
    /// The ledger is temporarily unavailable.
    TemporarilyUnavailable,
    /// Any other ledger error.
    GenericError { error_code: Nat, message: String },
}

/// Errors returned by treasury operations.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum TreasuryError {
    /// The caller is not the current canister owner.
    NotOwner,
    /// The ledger rejected the transfer.
    TransferFailed(TransferError),
    /// The ledger canister itself trapped (missing, out of cycles, ...).
    LedgerTrap(String),
}

impl fmt::Display for TreasuryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOwner => formatter.write_str("caller is not the canister owner"),
            Self::TransferFailed(error) => write!(formatter, "ledger rejected transfer: {error:?}"),
            Self::LedgerTrap(message) => write!(formatter, "ledger canister trapped: {message}"),
        }
    }
}

/// Canister state holding the `owner` principal.
pub struct CanisterState {
    /// Principal allowed to manage ownership and withdraw funds.
    pub owner: Principal,
}

/// Handle used by the free functions in this module.
#[derive(Clone)]
pub struct TreasuryContext {
    state: Rc<RefCell<CanisterState>>,
}

/// Creates the treasury state with `owner` as the initial owner.
///
/// The deployer (`ic_cdk::api::msg_caller()` inside `#[init]`) is the natural
/// choice, matching the Motoko reference actor.
pub fn init(owner: Principal) -> TreasuryContext {
    TreasuryContext {
        state: Rc::new(RefCell::new(CanisterState { owner })),
    }
}

/// Returns the current canister owner.
pub fn get_owner(context: &TreasuryContext) -> Principal {
    context.state.borrow().owner
}

/// Transfers ownership to `new_owner`.
///
/// Only the current owner may call this; any other caller receives
/// [`TreasuryError::NotOwner`] and the owner is left unchanged.
pub fn set_owner(
    context: &TreasuryContext,
    caller: Principal,
    new_owner: Principal,
) -> Result<(), TreasuryError> {
    if caller != context.state.borrow().owner {
        return Err(TreasuryError::NotOwner);
    }
    context.state.borrow_mut().owner = new_owner;
    Ok(())
}

/// Returns this canister's balance on an ICRC-1 ledger.
///
/// Public read; any caller may use it. If the ledger canister traps or does
/// not exist, `0` is returned — identical to the Motoko reference, which
/// treats a missing ledger as an empty treasury.
pub async fn get_treasury_balance(self_id: Principal, ledger_id: Principal) -> Nat {
    let account = Account {
        owner: self_id,
        subaccount: None,
    };
    let response = Call::unbounded_wait(ledger_id, "icrc1_balance_of")
        .with_arg(account)
        .await;
    match response {
        Ok(response) => match response.candid::<Nat>() {
            Ok(balance) => balance,
            Err(error) => {
                ic_cdk::println!("Failed to decode treasury balance: {error}");
                Nat::from(0u32)
            }
        },
        Err(error) => {
            ic_cdk::println!("Failed to get treasury balance: {error}");
            Nat::from(0u32)
        }
    }
}

/// Withdraws `amount` tokens from the canister's default account on an
/// ICRC-1 ledger to `destination`. Returns the ledger block index.
///
/// SECURITY: the owner check runs before any inter-canister call and no
/// `RefCell` borrow is held across the `await`. Only the current owner may
/// withdraw; other callers get [`TreasuryError::NotOwner`].
pub async fn withdraw(
    context: &TreasuryContext,
    caller: Principal,
    ledger_id: Principal,
    amount: Nat,
    destination: Account,
) -> Result<Nat, TreasuryError> {
    if caller != context.state.borrow().owner {
        return Err(TreasuryError::NotOwner);
    }

    let args = TransferArg {
        from_subaccount: None,
        to: destination,
        amount,
        fee: None,
        memo: None,
        created_at_time: None,
    };

    let response = Call::unbounded_wait(ledger_id, "icrc1_transfer")
        .with_arg(args)
        .await
        .map_err(|error| {
            let message = error.to_string();
            ic_cdk::println!("FATAL: withdrawal failed, ledger trapped: {message}");
            TreasuryError::LedgerTrap(message)
        })?;

    response
        .candid::<Result<Nat, TransferError>>()
        .map_err(|error| TreasuryError::LedgerTrap(error.to_string()))?
        .map_err(TreasuryError::TransferFailed)
}

/// Arguments for the ledger's `icrc1_transfer` method (ICRC-1 spec).
#[derive(Clone, Debug, CandidType, Deserialize)]
struct TransferArg {
    from_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    fn principal(text: &str) -> Principal {
        Principal::from_text(text).unwrap()
    }

    #[test]
    fn set_owner_is_owner_gated() {
        let owner = principal("2vxsx-fae");
        let other = principal("rrkah-fqaaa-aaaaa-aaaaq-cai");
        let context = init(owner);

        assert_eq!(get_owner(&context), owner);
        assert_eq!(
            set_owner(&context, other, other),
            Err(TreasuryError::NotOwner)
        );
        assert_eq!(get_owner(&context), owner);
        assert_eq!(set_owner(&context, owner, other), Ok(()));
        assert_eq!(get_owner(&context), other);
    }

    #[test]
    fn withdraw_rejects_non_owner_before_any_ledger_call() {
        let owner = principal("2vxsx-fae");
        let other = principal("rrkah-fqaaa-aaaaa-aaaaq-cai");
        let ledger = principal("ryjl3-tyaaa-aaaaa-aaaba-cai");
        let context = init(owner);
        let destination = Account {
            owner: other,
            subaccount: None,
        };

        // The NotOwner path returns before any inter-canister call, so it is
        // safe to drive synchronously in a unit test.
        let result = block_on(withdraw(
            &context,
            other,
            ledger,
            Nat::from(100u32),
            destination,
        ));
        assert_eq!(result, Err(TreasuryError::NotOwner));
    }
}
