//! Minimal canister exposing the `treasury` module's owner and ICRC-1
//! treasury functions. Used by the `treasury_ledger` integration test and as
//! a reference for wiring the module into a real canister.

use candid::{Nat, Principal};
use ic_cdk::{init, query, update};
use ic_rmcp::treasury::{self, Account, TreasuryContext, TreasuryError};
use std::cell::RefCell;

thread_local! {
    static TREASURY: RefCell<Option<TreasuryContext>> = const { RefCell::new(None) };
}

#[init]
fn init() {
    // The deployer becomes the canister owner, matching the Motoko reference
    // actor (`var owner : Principal = deployer`).
    TREASURY.with_borrow_mut(|slot| *slot = Some(treasury::init(ic_cdk::api::msg_caller())));
}

/// Returns the principal of the current owner of this canister.
#[query]
fn get_owner() -> Principal {
    TREASURY.with_borrow(|slot| treasury::get_owner(slot.as_ref().unwrap()))
}

/// Transfers ownership of the canister to a new principal.
/// Only the current owner can call this function.
#[update]
fn set_owner(new_owner: Principal) -> Result<(), TreasuryError> {
    let context = TREASURY.with_borrow(|slot| slot.clone().unwrap());
    treasury::set_owner(&context, ic_cdk::api::msg_caller(), new_owner)
}

/// Returns this canister's balance on the given ICRC-1 ledger.
#[update]
async fn get_treasury_balance(ledger_id: Principal) -> Nat {
    treasury::get_treasury_balance(ic_cdk::api::canister_self(), ledger_id).await
}

/// Withdraws `amount` tokens from the canister's default account on the given
/// ICRC-1 ledger to `destination`. Only the current owner can call this.
#[update]
async fn withdraw(
    ledger_id: Principal,
    amount: Nat,
    destination: Account,
) -> Result<Nat, TreasuryError> {
    let context = TREASURY.with_borrow(|slot| slot.clone().unwrap());
    treasury::withdraw(
        &context,
        ic_cdk::api::msg_caller(),
        ledger_id,
        amount,
        destination,
    )
    .await
}
