// Copyright 2024 VoteChain Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Storage accessors for the governance contract.
//!
//! # Namespacing strategy
//!
//! All storage entries are keyed by variants of [`DataKey`].  Soroban
//! serialises the enum variant discriminant into the XDR key before any
//! payload, so every variant occupies a completely isolated key space.
//! Adding a new data type requires only a new enum variant — there is no
//! risk of collision with existing keys.
//!
//! Storage tiers in use:
//! - **Instance** – singleton config values (`Admin`, `VotingToken`,
//!   `ProposalCount`, `MinProposalBalance`, `ProposalCooldown`, `MinDuration`, `MaxDuration`, `Version`).
//!   Shares the contract instance TTL; cheap to access.
//! - **Persistent** – proposal data and per-voter records (`Proposal`,
//!   `HasVoted`, `VoteRecord`, `VoterSnapshot`, `LastProposal`).
//!   Survives ledger expiry; must be bumped explicitly for long-lived entries.
//!
//! ## Key-space isolation between related variants
//!
//! Several variants share the same payload shape `(u64, Address)` but are
//! distinct enum variants (`HasVoted`, `VoteRecord`, `VoterSnapshot`).
//! Because the discriminant is part of the serialised key, these can never
//! collide even when called with identical arguments.

use crate::types::{ContractError, ContractState, DataKey, PendingMultisigAction, Proposal, VoteRecord};
use soroban_sdk::{Address, Env, Vec};

// =============================================================================
// Storage Strategy
// =============================================================================
//
// Soroban provides three storage tiers. Each key in this contract is assigned
// to the tier that best matches its access pattern and lifetime:
//
// INSTANCE storage  – contract-wide singleton values that share the contract's
//                     TTL. Reads are cheap because the entire instance bucket is
//                     loaded in one host-function call. Used for configuration
//                     that is set once and read on almost every invocation.
//
//   DataKey::Admin              – admin address (set at init, read on admin ops)
//   DataKey::VotingToken        – governance token address (read on every vote)
//   DataKey::ProposalCount      – monotonic proposal ID counter (SEC-007)
//   DataKey::MinProposalBalance – minimum token balance to create a proposal
//   DataKey::ProposalCooldown   – seconds between proposals per address
//   DataKey::ContractState      – lifecycle state (Uninitialized / Ready)
//   DataKey::RestrictAdminVote  – whether admin may vote on own proposals
//   DataKey::Paused             – contract pause flag
//   DataKey::Version            – semver tuple (major, minor, patch)
//
// PERSISTENT storage – per-key TTL, survives ledger expiry independently.
//                      Used for data that must outlive any single ledger and
//                      is keyed by a variable (proposal ID, voter address, etc.).
//
//   DataKey::Proposal(id)                  – full proposal struct
//   DataKey::HasVoted(proposal_id, voter)  – deduplication flag per voter
//   DataKey::VoteRecord(proposal_id, voter)– immutable vote audit record
//   DataKey::VoterSnapshot(proposal_id, voter) – balance snapshot at vote time
//   DataKey::LastProposal(proposer)        – timestamp of proposer's last proposal
//
// TEMPORARY storage  – not used in this contract. Allowances in the token
//                      contract use temporary storage; see token/src/storage.rs.
// =============================================================================

/// Persists a proposal to contract storage, keyed by its ID.
pub fn save_proposal(env: &Env, p: &Proposal) {
    env.storage().persistent().set(&DataKey::Proposal(p.id), p);
}

/// Loads a proposal from storage by ID.
///
/// # Errors
/// - [`ContractError::ProposalNotFound`] if no proposal exists for `id`.
pub fn load_proposal(env: &Env, id: u64) -> Result<Proposal, ContractError> {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(id))
        .ok_or(ContractError::ProposalNotFound)
}

/// Increments the proposal counter and returns the new ID.
///
/// SEC-007: The counter is the sole source of proposal IDs; no caller-supplied
/// ID is accepted.  The read-increment-write executes atomically within a
/// single Soroban transaction, so concurrent creation attempts (different
/// transactions in the same ledger) each observe a unique counter value.
///
/// # Errors
/// - [`ContractError::ProposalCountOverflow`] if the counter would exceed `u64::MAX`.
pub fn next_id(env: &Env) -> Result<u64, ContractError> {
    let current: u64 = env
        .storage()
        .instance()
        .get(&DataKey::ProposalCount)
        .unwrap_or(0);
    let n = current
        .checked_add(1)
        .ok_or(ContractError::ProposalCountOverflow)?;
    env.storage().instance().set(&DataKey::ProposalCount, &n);
    Ok(n)
}

/// Stores the admin address in instance storage.
pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

/// Returns `true` if the contract has been initialised (admin key exists).
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Admin)
}

/// Stores the contract lifecycle state in instance storage.
pub fn set_contract_state(env: &Env, state: &ContractState) {
    env.storage().instance().set(&DataKey::ContractState, state);
}

/// Returns the contract lifecycle state.
///
/// Defaults to [`ContractState::Uninitialized`] if the key has never been written
/// (i.e. before the very first `initialize` call).
pub fn get_contract_state(env: &Env) -> ContractState {
    env.storage()
        .instance()
        .get(&DataKey::ContractState)
        .unwrap_or(ContractState::Uninitialized)
}

/// Returns the stored admin address.
///
/// # Errors
/// - [`ContractError::AdminNotSet`] if the contract has not been initialised.
pub fn get_admin(env: &Env) -> Result<Address, ContractError> {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(ContractError::AdminNotSet)
}

/// Stores the governance token address in instance storage.
pub fn set_voting_token(env: &Env, token: &Address) {
    env.storage().instance().set(&DataKey::VotingToken, token);
}

/// Returns the stored governance token address.
///
/// # Errors
/// - [`ContractError::VotingTokenNotSet`] if the contract has not been initialised.
pub fn get_voting_token(env: &Env) -> Result<Address, ContractError> {
    env.storage()
        .instance()
        .get(&DataKey::VotingToken)
        .ok_or(ContractError::VotingTokenNotSet)
}

/// Records that `voter` has voted on `proposal_id`.
pub fn mark_voted(env: &Env, proposal_id: u64, voter: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::HasVoted(proposal_id, voter.clone()), &true);
}

/// Returns `true` if `voter` has already voted on `proposal_id`.
pub fn has_voted(env: &Env, proposal_id: u64, voter: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::HasVoted(proposal_id, voter.clone()))
        .unwrap_or(false)
}

/// Stores the vote record for `voter` on `proposal_id`.
pub fn save_vote_record(env: &Env, proposal_id: u64, voter: &Address, record: &VoteRecord) {
    env.storage()
        .persistent()
        .set(&DataKey::VoteRecord(proposal_id, voter.clone()), record);
}

/// Returns the vote record for `voter` on `proposal_id`, or `None` if not voted.
pub fn get_vote_record(env: &Env, proposal_id: u64, voter: &Address) -> Option<VoteRecord> {
    env.storage()
        .persistent()
        .get(&DataKey::VoteRecord(proposal_id, voter.clone()))
}

pub fn set_min_proposal_balance(env: &Env, v: i128) {
    env.storage()
        .instance()
        .set(&DataKey::MinProposalBalance, &v);
}

pub fn get_min_proposal_balance(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::MinProposalBalance)
        .unwrap_or(0)
}

pub fn set_proposal_cooldown(env: &Env, v: u64) {
    env.storage().instance().set(&DataKey::ProposalCooldown, &v);
}

pub fn get_proposal_cooldown(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::ProposalCooldown)
        .unwrap_or(0)
}

pub fn set_last_proposal(env: &Env, proposer: &Address, ts: u64) {
    env.storage()
        .persistent()
        .set(&DataKey::LastProposal(proposer.clone()), &ts);
}

pub fn get_last_proposal(env: &Env, proposer: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::LastProposal(proposer.clone()))
        .unwrap_or(0)
}

/// Records the voter's token balance snapshot for a given proposal.
/// Called once per voter per proposal at the time of casting their vote.
pub fn save_voter_snapshot(env: &Env, proposal_id: u64, voter: &Address, weight: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::VoterSnapshot(proposal_id, voter.clone()), &weight);
}

/// Returns the stored vote-weight snapshot for a voter on a proposal.
/// Returns `None` if no snapshot has been recorded yet.
pub fn get_voter_snapshot(env: &Env, proposal_id: u64, voter: &Address) -> Option<i128> {
    env.storage()
        .persistent()
        .get(&DataKey::VoterSnapshot(proposal_id, voter.clone()))
}
/// Stores the contract version as a `(major, minor, patch)` tuple.
pub fn set_version(env: &Env, version: (u32, u32, u32)) {
    env.storage().instance().set(&DataKey::Version, &version);
}

/// Returns the stored contract version as a `(major, minor, patch)` tuple.
pub fn get_version(env: &Env) -> (u32, u32, u32) {
    env.storage()
        .instance()
        .get(&DataKey::Version)
        .unwrap_or((0, 0, 0))
}

/// Stores whether admin is restricted from voting on their own proposals.
pub fn set_restrict_admin_vote(env: &Env, v: bool) {
    env.storage()
        .instance()
        .set(&DataKey::RestrictAdminVote, &v);
}

/// Returns whether admin vote restriction is enabled. Defaults to `false`.
pub fn get_restrict_admin_vote(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::RestrictAdminVote)
        .unwrap_or(false)
}

/// Stores the mandatory delay (seconds) a passed proposal must wait before it can be executed.
pub fn set_timelock_duration(env: &Env, v: u64) {
    env.storage().instance().set(&DataKey::TimelockDuration, &v);
}

/// Returns the configured timelock duration in seconds. Defaults to 0 (no delay).
pub fn get_timelock_duration(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::TimelockDuration)
        .unwrap_or(0)
}

/// Sets the contract paused state.
pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&DataKey::Paused, &paused);
}

/// Returns `true` if the contract is currently paused.
pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

pub fn set_min_duration(env: &Env, v: u64) {
    env.storage().instance().set(&DataKey::MinDuration, &v);
}

pub fn get_min_duration(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::MinDuration)
        .unwrap_or(60)
}

pub fn set_max_duration(env: &Env, v: u64) {
    env.storage().instance().set(&DataKey::MaxDuration, &v);
}

pub fn get_max_duration(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::MaxDuration)
        .unwrap_or(2_592_000)
}

/// Stores the pending admin address nominated for rotation.
pub fn set_pending_admin(env: &Env, addr: &Address) {
    env.storage().instance().set(&DataKey::PendingAdmin, addr);
}

/// Returns the pending admin address, if any.
pub fn get_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::PendingAdmin)
}

/// Clears the pending admin nomination.
pub fn clear_pending_admin(env: &Env) {
    env.storage().instance().remove(&DataKey::PendingAdmin);
    env.storage()
        .instance()
        .remove(&DataKey::AdminTransferExpiry);
}

/// Stores the expiry timestamp for the pending admin nomination.
pub fn set_admin_transfer_expiry(env: &Env, ts: u64) {
    env.storage()
        .instance()
        .set(&DataKey::AdminTransferExpiry, &ts);
}

/// Returns the expiry timestamp for the pending admin nomination.
pub fn get_admin_transfer_expiry(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::AdminTransferExpiry)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Delegation storage
// ---------------------------------------------------------------------------

/// Records that `delegator` has delegated their voting power to `delegate`.
///
/// Stored in persistent storage so that delegations survive ledger expiry
/// without needing to be re-submitted on every proposal.
pub fn set_delegation(env: &Env, delegator: &Address, delegate: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::Delegation(delegator.clone()), delegate);
}

/// Returns the address to which `delegator` has delegated, or `None` if the
/// delegator has not delegated their voting power.
pub fn get_delegation(env: &Env, delegator: &Address) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::Delegation(delegator.clone()))
}

/// Removes the delegation record for `delegator`.
///
/// After this call `get_delegation(delegator)` returns `None` and the
/// delegator may vote directly again.
pub fn clear_delegation(env: &Env, delegator: &Address) {
    env.storage()
        .persistent()
        .remove(&DataKey::Delegation(delegator.clone()));
}

/// Stores the previous WASM hash for rollback purposes.
pub fn set_previous_wasm_hash(env: &Env, hash: &soroban_sdk::BytesN<32>) {
    env.storage()
        .instance()
        .set(&DataKey::PreviousWasmHash, hash);
}

/// Returns the previous WASM hash, if any.
pub fn get_previous_wasm_hash(env: &Env) -> Option<soroban_sdk::BytesN<32>> {
    env.storage().instance().get(&DataKey::PreviousWasmHash)
}

// ---------------------------------------------------------------------------
// Active-proposal cap storage (issue #59)
// ---------------------------------------------------------------------------

/// Default global cap on simultaneously active proposals when none has been
/// explicitly configured.
const DEFAULT_MAX_ACTIVE_PROPOSALS: u64 = 50;

/// Persists the global cap on simultaneously active proposals.
///
/// Stored in instance storage so the value is loaded cheaply alongside other
/// config on every `create_proposal` call.
pub fn set_max_active_proposals(env: &Env, max: u64) {
    env.storage()
        .instance()
        .set(&DataKey::MaxActiveProposals, &max);
}

/// Returns the configured global cap on simultaneously active proposals.
///
/// Falls back to [`DEFAULT_MAX_ACTIVE_PROPOSALS`] (50) when the key has never
/// been written (i.e. contracts initialised before this config key was added).
pub fn get_max_active_proposals(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::MaxActiveProposals)
        .unwrap_or(DEFAULT_MAX_ACTIVE_PROPOSALS)
}
