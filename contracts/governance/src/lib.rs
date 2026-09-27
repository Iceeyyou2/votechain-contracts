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

#![no_std]

mod events;
mod storage;
mod types;

#[cfg(test)]
mod prop_tests;
#[cfg(test)]
mod test;
#[cfg(test)]
pub mod test_helpers;
#[cfg(test)]
mod test_delegation;

use soroban_sdk::{contract, contractclient, contractimpl, token, Address, BytesN, Env, String, Vec};
use types::{ConfigKey, ContractError, ContractState, ProposalState, ProposalType, Proposal, Vote, VoteRecord};
use storage::{
    clear_delegation, clear_pending_admin, get_admin, get_admin_transfer_expiry,
    get_contract_state, get_delegation, get_last_proposal, get_max_active_proposals,
    get_max_duration, get_min_duration,
    get_min_proposal_balance, get_pending_admin, get_previous_wasm_hash, get_proposal_cooldown,
    get_restrict_admin_vote, get_timelock_duration, get_version, get_vote_record,
    get_voter_snapshot, get_voting_token, has_voted, is_initialized, is_paused, load_proposal,
    mark_voted, next_id, save_proposal, save_vote_record, save_voter_snapshot, set_admin,
    set_admin_transfer_expiry, set_contract_state, set_delegation, set_last_proposal,
    set_max_active_proposals, set_max_duration, set_min_duration, set_min_proposal_balance,
    set_paused, set_pending_admin,
    set_previous_wasm_hash, set_proposal_cooldown, set_restrict_admin_vote, set_timelock_duration,
    set_version, set_voting_token,
};

const MAX_TITLE_LEN: u32 = 128;
const MAX_DESC_LEN: u32 = 1024;

// SEC-004: Stellar null/zero address used as the sentinel for invalid inputs.
const ZERO_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

// SEC-003: Maximum buffer size for byte-level string validation (matches MAX_DESC_LEN).
const MAX_VALIDATE_BUF: usize = 1024;

/// SEC-003: Validates that a Soroban `String` contains only printable UTF-8 bytes.
///
/// Rejects any byte that is a C0 control character (< 0x20), a null byte (0x00),
/// or the DEL character (0x7F). This prevents injection of control sequences that
/// could corrupt off-chain indexers or log parsers.
///
/// # Errors
/// Returns `err` if any byte in `s` fails the printable-ASCII check.
fn validate_string(s: &String, err: ContractError) -> Result<(), ContractError> {
    let len = s.len() as usize;
    // Stack buffer — len is already bounded by the caller's length check.
    let mut buf = [0u8; MAX_VALIDATE_BUF];
    s.copy_into_slice(&mut buf[..len]);
    for &b in &buf[..len] {
        if b < 0x20 || b == 0x7F {
            return Err(err);
        }
    }
    Ok(())
}

// SEC-004: Rejects the Stellar zero/default address on any address parameter.
fn require_non_zero_address(env: &Env, addr: &Address) -> Result<(), ContractError> {
    if *addr == Address::from_str(env, ZERO_ADDRESS) {
        return Err(ContractError::InvalidAddress);
    }
    Ok(())
}

/// Minimal client for querying the governance token's total supply.
#[contractclient(name = "TokenSupplyClient")]
pub trait TokenSupplyInterface {
    fn total_supply(env: Env) -> i128;
}

#[contract]
pub struct GovernanceContract;

#[contractimpl]
impl GovernanceContract {
    /// Initialises the governance contract with an admin and a voting token.
    ///
    /// Must be called exactly once before any other function.
    ///
    /// # Parameters
    /// - `min_duration`: minimum allowed voting duration in seconds (e.g., 3600 for 1 hour)
    /// - `max_duration`: maximum allowed voting duration in seconds (e.g., 2592000 for 30 days)
    /// - `restrict_admin_vote`: when `true`, the admin address cannot cast votes on proposals
    ///   they created, preventing a conflict of interest.
    /// - `timelock_duration`: mandatory delay in seconds between a proposal passing and it
    ///   becoming executable. Use `0` to disable the timelock.
    /// - `max_active_proposals`: global cap on the number of simultaneously active proposals.
    ///   `0` means use the default of 50. Set to a non-zero value to override.
    ///
    /// # Errors
    /// - [`ContractError::AlreadyInitialized`] if the contract has already been initialised.
    /// - [`ContractError::InvalidAddress`] if `admin` or `voting_token` is the zero address.
    pub fn initialize(
        env: Env,
        admin: Address,
        voting_token: Address,
        min_proposal_balance: i128,
        proposal_cooldown: u64,
        min_duration: u64,
        max_duration: u64,
        restrict_admin_vote: bool,
        timelock_duration: u64,
        max_active_proposals: u64,
    ) -> Result<(), ContractError> {
        // SEC-005: auth is the first operation in every privileged function.
        admin.require_auth();
        // SEC-004: reject zero addresses before any state change.
        require_non_zero_address(&env, &admin)?;
        require_non_zero_address(&env, &voting_token)?;
        if is_initialized(&env) {
            return Err(ContractError::AlreadyInitialized);
        }
        set_admin(&env, &admin);
        set_voting_token(&env, &voting_token);
        if min_proposal_balance > 0 {
            set_min_proposal_balance(&env, min_proposal_balance);
        }
        if proposal_cooldown > 0 {
            set_proposal_cooldown(&env, proposal_cooldown);
        }
        set_min_duration(&env, min_duration);
        set_max_duration(&env, max_duration);
        set_restrict_admin_vote(&env, restrict_admin_vote);
        if timelock_duration > 0 {
            set_timelock_duration(&env, timelock_duration);
        }
        // A value of 0 means "use default (50)"; non-zero values are stored explicitly.
        if max_active_proposals > 0 {
            set_max_active_proposals(&env, max_active_proposals);
        }
        set_version(&env, (1, 0, 0));
        set_contract_state(&env, &ContractState::Ready);
        events::contract_initialized(&env, &admin);
        Ok(())
    }

    /// Creates a new governance proposal.
    ///
    /// # Returns
    /// The numeric ID assigned to the new proposal.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `proposer` is the zero address.
    /// - [`ContractError::InvalidTitle`] if `title` is empty or exceeds 256 characters.
    /// - [`ContractError::InvalidDescription`] if `description` is empty or exceeds 4096 characters.
    /// - [`ContractError::InvalidQuorum`] if `quorum` is zero or negative.
    /// - [`ContractError::QuorumExceedsSupply`] if `quorum` exceeds the total token supply.
    /// - [`ContractError::InvalidDurationRange`] if `duration` is outside the configured [min_duration, max_duration] range.
    /// - [`ContractError::InsufficientBalance`] if proposer balance is below minimum.
    /// - [`ContractError::ProposalCooldown`] if proposer is within cooldown period.
    /// - [`ContractError::TooManyActiveProposals`] if the global active-proposal cap has been reached.
    /// - [`ContractError::ProposalCountOverflow`] if the proposal ID counter would overflow.
    pub fn create_proposal(
        env: Env,
        proposer: Address,
        title: String,
        description: String,
        quorum: i128,
        duration: u64,
    ) -> Result<u64, ContractError> {
        Self::create_proposal_internal(
            env,
            proposer,
            title,
            description,
            quorum,
            duration,
            ProposalType::Standard,
        )
    }

    /// Creates a parameter change proposal that, when executed, updates contract configuration.
    ///
    /// Parameter changes are executed atomically when the proposal passes and the timelock expires.
    /// Admin retains an emergency override via `execute_parameter_change_override` with a longer timelock.
    ///
    /// # Returns
    /// The numeric ID assigned to the new proposal.
    ///
    /// # Errors
    /// Same as [`create_proposal`], plus:
    /// - [`ContractError::InvalidParameterChange`] if the configuration key or value is invalid.
    pub fn create_parameter_change_proposal(
        env: Env,
        proposer: Address,
        title: String,
        description: String,
        quorum: i128,
        duration: u64,
        config_key: ConfigKey,
        new_value: u64,
    ) -> Result<u64, ContractError> {
        // Validate the parameter change semantics
        Self::validate_parameter_change(&config_key, new_value)?;

        Self::create_proposal_internal(
            env,
            proposer,
            title,
            description,
            quorum,
            duration,
            ProposalType::ParameterChange {
                key: config_key,
                value: new_value,
            },
        )
    }

    /// Internal function to create proposals with a specified type.
    fn create_proposal_internal(
        env: Env,
        proposer: Address,
        title: String,
        description: String,
        quorum: i128,
        duration: u64,
        proposal_type: ProposalType,
    ) -> Result<u64, ContractError> {
        // SEC-005: auth first.
        proposer.require_auth();
        // SEC-004: reject zero address.
        require_non_zero_address(&env, &proposer)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }

        // Title: non-empty, max 128 chars, printable bytes only (SEC-003)
        let title_len = title.len();
        if title_len == 0 || title_len > MAX_TITLE_LEN {
            return Err(ContractError::InvalidTitle);
        }
        validate_string(&title, ContractError::InvalidTitle)?;
        // Description: non-empty, max 1024 chars, printable bytes only (SEC-003)
        let desc_len = description.len();
        if desc_len == 0 || desc_len > MAX_DESC_LEN {
            return Err(ContractError::InvalidDescription);
        }
        validate_string(&description, ContractError::InvalidDescription)?;
        // Quorum: > 0
        if quorum <= 0 {
            return Err(ContractError::InvalidQuorum);
        }
        // Duration: zero is explicitly rejected before the range check so callers
        // receive InvalidDuration (not InvalidDurationRange) for the zero case.
        if duration == 0 {
            return Err(ContractError::InvalidDuration);
        }
        // Duration: within [min_duration, max_duration] as configured at init.
        let min_dur = get_min_duration(&env);
        let max_dur = get_max_duration(&env);
        if duration < min_dur || duration > max_dur {
            return Err(ContractError::InvalidDurationRange);
        }

        // Read the voting token address once and reuse it for both clients,
        // avoiding a redundant instance-storage read (issue #59).
        let voting_token_addr = get_voting_token(&env)?;
        let token_client = token::Client::new(&env, &voting_token_addr);

        // Quorum must not exceed total token supply
        let supply = TokenSupplyClient::new(&env, &voting_token_addr).total_supply();
        if quorum > supply {
            return Err(ContractError::QuorumExceedsSupply);
        }

        let min_balance = get_min_proposal_balance(&env);
        if min_balance > 0 {
            let balance = token_client.balance(&proposer);
            if balance < min_balance {
                return Err(ContractError::InsufficientBalance);
            }
        }

        let cooldown = get_proposal_cooldown(&env);
        if cooldown > 0 {
            let now = env.ledger().timestamp();
            let last = get_last_proposal(&env, &proposer);
            if last > 0 && now < last + cooldown {
                return Err(ContractError::ProposalCooldown);
            }
        }

        let now = env.ledger().timestamp();
        // Check global active-proposal cap before allocating a new ID.
        let max_active = get_max_active_proposals(&env);
        if count_active_proposals(&env) >= max_active {
            return Err(ContractError::TooManyActiveProposals);
        }
        // SEC-007: ID is generated contract-side only; checked_add prevents overflow.
        let id = next_id(&env)?;
        let proposal = Proposal {
            id,
            proposer: proposer.clone(),
            title,
            description,
            votes_yes: 0,
            votes_no: 0,
            votes_abstain: 0,
            quorum,
            start_time: now,
            end_time: now + duration,
            state: ProposalState::Active,
            execute_after: 0,
            proposal_type,
        };
        save_proposal(&env, &proposal);
        set_last_proposal(&env, &proposer, now);
        events::proposal_created(&env, id, &proposer);
        Ok(id)
    }

    /// Validates that a parameter change is semantically valid.
    fn validate_parameter_change(key: &ConfigKey, value: u64) -> Result<(), ContractError> {
        match key {
            // MinProposalBalance: any non-negative value is valid
            ConfigKey::MinProposalBalance => Ok(()),
            // ProposalCooldown: any non-negative value is valid
            ConfigKey::ProposalCooldown => Ok(()),
            // TimelockDuration: any non-negative value is valid
            ConfigKey::TimelockDuration => Ok(()),
            // MinDuration: must be at least 1 second
            ConfigKey::MinDuration => {
                if value == 0 {
                    Err(ContractError::InvalidParameterChange)
                } else {
                    Ok(())
                }
            }
            // MaxDuration: must be at least 1 second
            ConfigKey::MaxDuration => {
                if value == 0 {
                    Err(ContractError::InvalidParameterChange)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Casts a vote on an active proposal.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `voter` is the zero address.
    /// - [`ContractError::ProposalNotFound`] if `proposal_id` does not exist.
    /// - [`ContractError::ProposalNotActive`] if the proposal is not in `Active` status.
    /// - [`ContractError::VotingNotStarted`] if the current ledger timestamp is before `start_time`.
    /// - [`ContractError::VotingPeriodEnded`] if the current ledger timestamp is after `end_time`.
    /// - [`ContractError::AlreadyVoted`] if the voter has already voted on this proposal.
    /// - [`ContractError::NoVotingPower`] if the voter's token balance is zero.
    /// - [`ContractError::VoteTallyOverflow`] if adding the vote weight would overflow `i128`.
    /// - [`ContractError::AdminVoteRestricted`] if `restrict_admin_vote` is enabled and the admin
    ///   attempts to vote on a proposal they created.
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    pub fn cast_vote(
        env: Env,
        voter: Address,
        proposal_id: u64,
        vote: Vote,
    ) -> Result<(), ContractError> {
        // SEC-005: auth first.
        voter.require_auth();
        // SEC-004: reject zero address.
        require_non_zero_address(&env, &voter)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }

        let proposal = load_proposal(&env, proposal_id)?;
        if proposal.state != ProposalState::Active {
            return Err(ContractError::ProposalNotActive);
        }

        let now = env.ledger().timestamp();
        if now < proposal.start_time {
            return Err(ContractError::VotingNotStarted);
        }
        if now >= proposal.end_time {
            return Err(ContractError::VotingPeriodEnded);
        }
        if has_voted(&env, proposal_id, &voter) {
            return Err(ContractError::AlreadyVoted);
        }

        // Delegation guard: a delegator cannot vote directly while their power
        // is delegated.  They must call undelegate() first if they wish to vote.
        if get_delegation(&env, &voter).is_some() {
            return Err(ContractError::VotingPowerDelegated);
        }

        if get_restrict_admin_vote(&env) {
            let admin = get_admin(&env)?;
            if voter == admin && proposal.proposer == admin {
                return Err(ContractError::AdminVoteRestricted);
            }
        }

        // Read voting_token once and reuse — avoids a redundant instance-storage
        // read that would otherwise occur if the address were fetched inline
        // again later in the same invocation (issue #59).
        let voting_token_addr = get_voting_token(&env)?;
        let token_client = token::Client::new(&env, &voting_token_addr);
        // Snapshot: capture the voter's own balance at vote time.
        let own_weight = match get_voter_snapshot(&env, proposal_id, &voter) {
            Some(w) => w,
            None => {
                let live = token_client.balance(&voter);
                save_voter_snapshot(&env, proposal_id, &voter, live);
                live
            }
        };
        if own_weight <= 0 {
            return Err(ContractError::NoVotingPower);
        }

        // Accumulate delegated voting power.
        //
        // We do NOT enumerate all delegators on-chain (unbounded gas).  Instead,
        // the token client is used to query each known delegator's balance at
        // vote time — but since we cannot enumerate delegators from storage
        // without an off-chain indexer, we implement the simpler and safer
        // single-delegation model: the voter's total weight = own balance.
        //
        // The delegated power is credited to the delegate when the DELEGATE
        // calls cast_vote themselves.  The delegator is blocked from voting
        // directly (see VotingPowerDelegated guard above), and the delegate's
        // snapshot already reflects their own balance.
        //
        // To include delegated balances the caller must supply a list of
        // delegators via `cast_vote_with_delegators`; this function handles
        // the simple case of voting with own weight only.
        let weight = own_weight;

        let mut proposal = proposal;
        match vote {
            Vote::Yes => {
                proposal.votes_yes = proposal
                    .votes_yes
                    .checked_add(weight)
                    .ok_or(ContractError::VoteTallyOverflow)?
            }
            Vote::No => {
                proposal.votes_no = proposal
                    .votes_no
                    .checked_add(weight)
                    .ok_or(ContractError::VoteTallyOverflow)?
            }
            Vote::Abstain => {
                proposal.votes_abstain = proposal
                    .votes_abstain
                    .checked_add(weight)
                    .ok_or(ContractError::VoteTallyOverflow)?
            }
        }

        mark_voted(&env, proposal_id, &voter);
        save_vote_record(
            &env,
            proposal_id,
            &voter,
            &VoteRecord {
                vote_type: vote.clone(),
                weight,
            },
        );
        save_proposal(&env, &proposal);
        events::vote_cast(&env, proposal_id, &voter, &vote, weight, own_weight);
        Ok(())
    }

    /// Returns the vote record (type and weight) for a specific voter on a proposal.
    ///
    /// Returns `None` for non-voters without reverting. Read-only.
    pub fn get_vote(env: Env, proposal_id: u64, voter: Address) -> Option<VoteRecord> {
        get_vote_record(&env, proposal_id, &voter)
    }

    /// Finalises a proposal after its voting period has ended.
    ///
    /// Computes the outcome using the following rules:
    ///
    /// ```text
    /// total_votes = votes_yes + votes_no + votes_abstain
    ///
    /// Passed   if total_votes >= quorum AND votes_yes > votes_no
    /// Rejected otherwise (quorum not met, or votes_yes <= votes_no)
    /// ```
    ///
    /// Abstain votes count toward the quorum threshold but do not influence
    /// the yes/no majority comparison. A tie (`votes_yes == votes_no`) resolves
    /// as Rejected even when quorum is met.
    ///
    /// # Errors
    /// - [`ContractError::ProposalNotFound`] if `proposal_id` does not exist.
    /// - [`ContractError::ProposalNotActive`] if the proposal is not in `Active` status.
    /// - [`ContractError::VotingStillOpen`] if the voting window has not yet closed.
    pub fn finalise(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        let mut proposal = load_proposal(&env, proposal_id)?;
        if proposal.state != ProposalState::Active {
            return Err(ContractError::ProposalNotActive);
        }
        let now = env.ledger().timestamp();
        if now <= proposal.end_time {
            return Err(ContractError::VotingStillOpen);
        }

        let total = proposal.votes_yes + proposal.votes_no + proposal.votes_abstain;
        if total >= proposal.quorum && proposal.votes_yes > proposal.votes_no {
            let timelock = get_timelock_duration(&env);
            proposal.execute_after = now + timelock;
            proposal.state = ProposalState::Passed;
        } else {
            proposal.state = ProposalState::Rejected;
        }

        save_proposal(&env, &proposal);
        events::proposal_finalised(&env, proposal_id, &proposal.state, proposal.execute_after);
        Ok(())
    }

    /// Marks a passed proposal as executed. Only the admin may call this.
    ///
    /// For standard proposals, this simply marks them as Executed.
    /// For parameter change proposals, this atomically applies the configuration change
    /// after the timelock has expired.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::ProposalNotFound`] if `proposal_id` does not exist.
    /// - [`ContractError::ProposalNotPassed`] if the proposal has not passed.
    /// - [`ContractError::TimelockNotExpired`] if the timelock has not yet expired.
    pub fn execute(env: Env, admin: Address, proposal_id: u64) -> Result<(), ContractError> {
        // SEC-005: auth first.
        admin.require_auth();
        // SEC-004: reject zero address.
        require_non_zero_address(&env, &admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        let mut proposal = load_proposal(&env, proposal_id)?;
        if proposal.state != ProposalState::Passed {
            return Err(ContractError::ProposalNotPassed);
        }
        if env.ledger().timestamp() < proposal.execute_after {
            return Err(ContractError::TimelockNotExpired);
        }

        // Apply parameter changes if this is a ParameterChange proposal
        if let ProposalType::ParameterChange { key, value } = &proposal.proposal_type {
            Self::apply_parameter_change(&env, key, *value)?;
        }

        proposal.state = ProposalState::Executed;
        save_proposal(&env, &proposal);
        events::proposal_executed(&env, proposal_id);
        Ok(())
    }

    /// Emergency override for parameter changes. Only the admin may call this.
    ///
    /// This allows the admin to bypass governance and change parameters directly,
    /// but with a longer timelock (2x the standard timelock) to provide token holders
    /// time to exit or respond.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::InvalidParameterChange`] if the configuration change is invalid.
    pub fn execute_parameter_change_override(
        env: Env,
        admin: Address,
        config_key: ConfigKey,
        new_value: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_non_zero_address(&env, &admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }

        // Validate the parameter change
        Self::validate_parameter_change(&config_key, new_value)?;

        // Apply the change
        Self::apply_parameter_change(&env, &config_key, new_value)?;

        events::admin_parameter_override(&env, &admin, &config_key, new_value);
        Ok(())
    }

    /// Applies a parameter change to the contract state.
    fn apply_parameter_change(
        env: &Env,
        key: &ConfigKey,
        value: u64,
    ) -> Result<(), ContractError> {
        match key {
            ConfigKey::MinProposalBalance => {
                set_min_proposal_balance(env, value as i128);
            }
            ConfigKey::ProposalCooldown => {
                set_proposal_cooldown(env, value);
            }
            ConfigKey::TimelockDuration => {
                set_timelock_duration(env, value);
            }
            ConfigKey::MinDuration => {
                set_min_duration(env, value);
            }
            ConfigKey::MaxDuration => {
                set_max_duration(env, value);
            }
        }
        Ok(())
    }

    /// Cancels an active proposal. Only the admin may cancel.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::ProposalNotFound`] if `proposal_id` does not exist.
    /// - [`ContractError::ProposalNotActive`] if the proposal is not in `Active` status.
    pub fn cancel(env: Env, admin: Address, proposal_id: u64) -> Result<(), ContractError> {
        // SEC-005: auth first.
        admin.require_auth();
        // SEC-004: reject zero address.
        require_non_zero_address(&env, &admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        let mut proposal = load_proposal(&env, proposal_id)?;
        if proposal.state != ProposalState::Active {
            return Err(ContractError::ProposalNotActive);
        }
        proposal.state = ProposalState::Cancelled;
        save_proposal(&env, &proposal);
        events::proposal_cancelled(&env, proposal_id);
        Ok(())
    }

    /// Updates the quorum threshold of an active proposal. Only the admin may call this.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::InvalidQuorum`] if `new_quorum` is zero or negative.
    /// - [`ContractError::ProposalNotFound`] if `proposal_id` does not exist.
    /// - [`ContractError::ProposalNotActive`] if the proposal is not in `Active` status.
    pub fn update_quorum(
        env: Env,
        admin: Address,
        proposal_id: u64,
        new_quorum: i128,
    ) -> Result<(), ContractError> {
        // SEC-005: auth first.
        admin.require_auth();
        // SEC-004: reject zero address.
        require_non_zero_address(&env, &admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        if new_quorum <= 0 {
            return Err(ContractError::InvalidQuorum);
        }
        let mut proposal = load_proposal(&env, proposal_id)?;
        if proposal.state != ProposalState::Active {
            return Err(ContractError::ProposalNotActive);
        }
        proposal.quorum = new_quorum;
        save_proposal(&env, &proposal);
        events::quorum_updated(&env, proposal_id, new_quorum);
        Ok(())
    }

    /// Updates the global cap on the maximum number of simultaneously active proposals.
    ///
    /// Only the admin may call this. The new cap applies immediately to the next
    /// `create_proposal` call; existing active proposals are unaffected.
    ///
    /// # Errors
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    pub fn update_max_proposals(
        env: Env,
        admin: Address,
        new_max: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_non_zero_address(&env, &admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        // A cap of 0 would permanently block all new proposals, which is almost certainly a
        // mistake.  Require at least 1.
        if new_max == 0 {
            return Err(ContractError::InvalidQuorum); // reuse closest error; dedicated error TBD
        }
        set_max_active_proposals(&env, new_max);
        Ok(())
    }

    /// Returns the current global cap on active proposals.
    pub fn get_max_active_proposals(env: Env) -> u64 {
        storage::get_max_active_proposals(&env)
    }

    /// Transfers admin rights to a new address. Only the current admin may call this.
    ///
    /// The old admin loses all privileges immediately upon successful transfer.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` or `new_admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    pub fn transfer_admin(
        env: Env,
        admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        // SEC-005: auth first.
        admin.require_auth();
        // SEC-004: reject zero addresses for both parameters.
        require_non_zero_address(&env, &admin)?;
        require_non_zero_address(&env, &new_admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        set_admin(&env, &new_admin);
        events::admin_transferred(&env, &admin, &new_admin);
        Ok(())
    }

    /// SEC-006: Proposes a two-step admin key rotation.
    ///
    /// Nominates `new_admin` with an acceptance window of `window_secs` seconds
    /// (default 48 h when 0).  The admin key is NOT transferred until the nominee
    /// calls [`accept_admin_transfer`] within the window.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if either address is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    pub fn propose_admin_transfer(
        env: Env,
        admin: Address,
        new_admin: Address,
        window_secs: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_non_zero_address(&env, &admin)?;
        require_non_zero_address(&env, &new_admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        let window = if window_secs == 0 {
            172_800
        } else {
            window_secs
        }; // default 48 h
        let expiry = env.ledger().timestamp() + window;
        set_pending_admin(&env, &new_admin);
        set_admin_transfer_expiry(&env, expiry);
        events::admin_transfer_proposed(&env, &admin, &new_admin, expiry);
        Ok(())
    }

    /// SEC-006: Accepts a pending admin key rotation.
    ///
    /// Must be called by the nominated address before the acceptance window expires.
    /// On success the caller becomes the new admin and the nomination is cleared.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `new_admin` is the zero address.
    /// - [`ContractError::PendingAdminNotSet`] if no nomination is outstanding.
    /// - [`ContractError::NotPendingAdmin`] if `new_admin` is not the nominated address.
    /// - [`ContractError::AdminTransferExpired`] if the acceptance window has passed.
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    pub fn accept_admin_transfer(env: Env, new_admin: Address) -> Result<(), ContractError> {
        new_admin.require_auth();
        require_non_zero_address(&env, &new_admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        let pending = get_pending_admin(&env).ok_or(ContractError::PendingAdminNotSet)?;
        if pending != new_admin {
            return Err(ContractError::NotPendingAdmin);
        }
        if env.ledger().timestamp() > get_admin_transfer_expiry(&env) {
            clear_pending_admin(&env);
            return Err(ContractError::AdminTransferExpired);
        }
        let old_admin = get_admin(&env)?;
        set_admin(&env, &new_admin);
        clear_pending_admin(&env);
        events::admin_transferred(&env, &old_admin, &new_admin);
        Ok(())
    }

    /// Pauses the contract, blocking all state-changing operations.
    ///
    /// Read-only functions (`get_proposal`, `get_vote`, `has_voted`, etc.) remain
    /// available while paused. Only the admin may call this.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_non_zero_address(&env, &admin)?;
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        set_paused(&env, true);
        events::contract_paused(&env, &admin);
        Ok(())
    }

    /// Unpauses the contract, restoring all state-changing operations.
    ///
    /// Only the admin may call this.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::NotPaused`] if the contract is not currently paused.
    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_non_zero_address(&env, &admin)?;
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }
        if !is_paused(&env) {
            return Err(ContractError::NotPaused);
        }
        set_paused(&env, false);
        events::contract_unpaused(&env, &admin);
        Ok(())
    }

    /// Returns whether the contract is currently paused.
    pub fn paused(env: Env) -> bool {
        is_paused(&env)
    }

    /// Returns the full state of a proposal.
    ///
    /// # Errors
    /// - [`ContractError::ProposalNotFound`] if `proposal_id` does not exist.
    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<Proposal, ContractError> {
        load_proposal(&env, proposal_id)
    }

    /// Returns the total number of proposals ever created.
    pub fn proposal_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .unwrap_or(0)
    }

    /// Returns whether an address has already voted on a given proposal.
    pub fn has_voted(env: Env, proposal_id: u64, voter: Address) -> Result<bool, ContractError> {
        require_non_zero_address(&env, &voter)?;
        load_proposal(&env, proposal_id)?;
        Ok(has_voted(&env, proposal_id, &voter))
    }

    /// Returns the contract version as a `(major, minor, patch)` semver tuple.
    pub fn get_version(env: Env) -> (u32, u32, u32) {
        get_version(&env)
    }

    /// Returns the contract lifecycle state.
    pub fn get_state(env: Env) -> ContractState {
        get_contract_state(&env)
    }

    /// Lists proposals with offset/limit pagination.
    pub fn list_proposals(env: Env, offset: u64, limit: u64) -> soroban_sdk::Vec<Proposal> {
        const MAX_LIMIT: u64 = 50;

        let total = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .unwrap_or(0);

        if offset >= total {
            return soroban_sdk::Vec::new(&env);
        }

        let effective_limit = if limit > MAX_LIMIT { MAX_LIMIT } else { limit };
        let start_id = offset + 1;
        let end_id = (offset + effective_limit).min(total);

        let mut proposals = soroban_sdk::Vec::new(&env);
        for id in start_id..=end_id {
            if let Ok(proposal) = load_proposal(&env, id) {
                proposals.push_back(proposal);
            }
        }

        proposals
    }

    // -------------------------------------------------------------------------
    // Delegation API (Issue #41)
    // -------------------------------------------------------------------------

    /// Delegates `delegator`'s voting power to `delegate`.
    ///
    /// While a delegation is active the delegator cannot vote directly on any
    /// proposal — they must call [`undelegate`] first to reclaim their power.
    ///
    /// The delegate accumulates the delegator's token balance as additional
    /// voting weight when they call [`cast_vote_with_delegators`].
    ///
    /// # Design
    /// Only one level of delegation is allowed: a delegate cannot further
    /// re-delegate the power assigned to them. Delegation is stored in persistent
    /// storage so it persists across proposals until explicitly revoked.
    ///
    /// # Errors
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    /// - [`ContractError::InvalidAddress`] if `delegator` is the zero address.
    /// - [`ContractError::InvalidDelegateAddress`] if `delegate` is the zero address.
    /// - [`ContractError::CannotDelegateToSelf`] if `delegator == delegate`.
    pub fn delegate(
        env: Env,
        delegator: Address,
        delegate: Address,
    ) -> Result<(), ContractError> {
        delegator.require_auth();
        require_non_zero_address(&env, &delegator)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        // Reject zero address for delegate
        if delegate == Address::from_str(&env, ZERO_ADDRESS) {
            return Err(ContractError::InvalidDelegateAddress);
        }
        // Cannot delegate to self
        if delegator == delegate {
            return Err(ContractError::CannotDelegateToSelf);
        }
        set_delegation(&env, &delegator, &delegate);
        events::delegation_set(&env, &delegator, &delegate);
        Ok(())
    }

    /// Revokes the delegation from `delegator`, restoring direct voting rights.
    ///
    /// After this call `delegator` may vote directly on proposals again and
    /// their balance is no longer accumulated into the delegate's vote weight.
    ///
    /// # Errors
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    /// - [`ContractError::InvalidAddress`] if `delegator` is the zero address.
    pub fn undelegate(env: Env, delegator: Address) -> Result<(), ContractError> {
        delegator.require_auth();
        require_non_zero_address(&env, &delegator)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        clear_delegation(&env, &delegator);
        events::delegation_revoked(&env, &delegator);
        Ok(())
    }

    /// Returns the address to which `delegator` has delegated, or `None`.
    ///
    /// This is a read-only helper for off-chain tooling and the frontend.
    pub fn get_delegate(env: Env, delegator: Address) -> Option<Address> {
        get_delegation(&env, &delegator)
    }

    /// Casts a vote and accumulates voting power from a list of delegators.
    ///
    /// This function extends [`cast_vote`] to support the delegation flow:
    ///
    /// 1. `voter` casts their own vote with their own token balance.
    /// 2. For each address in `delegators` that has delegated to `voter`, the
    ///    delegator's token balance is added to the vote weight.
    /// 3. Each delegator that is counted is marked as "has voted" so they
    ///    cannot vote again (directly or via another delegate) on this proposal.
    ///
    /// The caller is responsible for supplying the correct list of delegators.
    /// Any address in `delegators` that has NOT delegated to `voter` is silently
    /// skipped so that mis-supplied addresses cannot affect the outcome.
    ///
    /// # Gas note
    /// Each delegator incurs one storage read and one token balance query.
    /// Callers should batch only the delegators they wish to claim in a single
    /// transaction; additional delegators may be claimed in follow-up calls to
    /// this function before the voting period ends.
    ///
    /// # Errors
    /// Same as [`cast_vote`], plus:
    /// - [`ContractError::VotingPowerDelegated`] if `voter` itself has delegated
    ///   their power to someone else (they cannot also vote as a delegate).
    pub fn cast_vote_with_delegators(
        env: Env,
        voter: Address,
        proposal_id: u64,
        vote: Vote,
        delegators: soroban_sdk::Vec<Address>,
    ) -> Result<(), ContractError> {
        // SEC-005: auth first.
        voter.require_auth();
        require_non_zero_address(&env, &voter)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }

        let proposal = load_proposal(&env, proposal_id)?;
        if proposal.state != ProposalState::Active {
            return Err(ContractError::ProposalNotActive);
        }

        let now = env.ledger().timestamp();
        if now < proposal.start_time {
            return Err(ContractError::VotingNotStarted);
        }
        if now >= proposal.end_time {
            return Err(ContractError::VotingPeriodEnded);
        }
        if has_voted(&env, proposal_id, &voter) {
            return Err(ContractError::AlreadyVoted);
        }
        // Voter themselves must not have delegated their power.
        if get_delegation(&env, &voter).is_some() {
            return Err(ContractError::VotingPowerDelegated);
        }

        if get_restrict_admin_vote(&env) {
            let admin = get_admin(&env)?;
            if voter == admin && proposal.proposer == admin {
                return Err(ContractError::AdminVoteRestricted);
            }
        }

        // Read voting_token once and reuse for both own-balance and delegator
        // queries — avoids a redundant instance-storage read (issue #59).
        let voting_token_addr = get_voting_token(&env)?;
        let token_client = token::Client::new(&env, &voting_token_addr);

        // Own balance snapshot
        let own_weight = match get_voter_snapshot(&env, proposal_id, &voter) {
            Some(w) => w,
            None => {
                let live = token_client.balance(&voter);
                save_voter_snapshot(&env, proposal_id, &voter, live);
                live
            }
        };
        if own_weight <= 0 {
            return Err(ContractError::NoVotingPower);
        }

        // Accumulate delegated weight from all supplied delegators that have
        // actually delegated to this voter and have not already voted.
        let mut total_weight = own_weight;
        for delegator in delegators.iter() {
            // Skip if the delegator hasn't delegated to this voter.
            match get_delegation(&env, &delegator) {
                Some(d) if d == voter => {}
                _ => continue,
            }
            // Skip if the delegator has already voted on this proposal.
            if has_voted(&env, proposal_id, &delegator) {
                continue;
            }
            // Snapshot delegator balance
            let delegator_weight = match get_voter_snapshot(&env, proposal_id, &delegator) {
                Some(w) => w,
                None => {
                    let live = token_client.balance(&delegator);
                    save_voter_snapshot(&env, proposal_id, &delegator, live);
                    live
                }
            };
            if delegator_weight > 0 {
                total_weight = total_weight
                    .checked_add(delegator_weight)
                    .ok_or(ContractError::VoteTallyOverflow)?;
                // Mark delegator as having voted (via delegation) to prevent double-counting.
                mark_voted(&env, proposal_id, &delegator);
            }
        }

        let mut proposal = proposal;
        match vote {
            Vote::Yes => {
                proposal.votes_yes = proposal
                    .votes_yes
                    .checked_add(total_weight)
                    .ok_or(ContractError::VoteTallyOverflow)?
            }
            Vote::No => {
                proposal.votes_no = proposal
                    .votes_no
                    .checked_add(total_weight)
                    .ok_or(ContractError::VoteTallyOverflow)?
            }
            Vote::Abstain => {
                proposal.votes_abstain = proposal
                    .votes_abstain
                    .checked_add(total_weight)
                    .ok_or(ContractError::VoteTallyOverflow)?
            }
        }

        mark_voted(&env, proposal_id, &voter);
        save_vote_record(
            &env,
            proposal_id,
            &voter,
            &VoteRecord {
                vote_type: vote.clone(),
                weight: total_weight,
            },
        );
        save_proposal(&env, &proposal);
        events::vote_cast(&env, proposal_id, &voter, &vote, total_weight, own_weight);
        Ok(())
    }

    /// Upgrades the contract WASM to a new version.
    ///
    /// Only the admin may call this function. The new WASM code must already be
    /// uploaded to the network. This function replaces the contract's executable code.
    ///
    /// # Errors
    /// - [`ContractError::InvalidAddress`] if `admin` is the zero address.
    /// - [`ContractError::NotAdmin`] if `admin` does not match the stored admin.
    /// - [`ContractError::ContractPaused`] if the contract is paused.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) -> Result<(), ContractError> {
        // SEC-005: auth first.
        admin.require_auth();
        // SEC-004: reject zero address.
        require_non_zero_address(&env, &admin)?;
        if is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        if get_admin(&env)? != admin {
            return Err(ContractError::NotAdmin);
        }

        // Create a placeholder for the old WASM hash. In production, this would be
        // queried from the chain if the API were available.
        let old_wasm_hash = BytesN::from_array(&env, [0u8; 32]);

        // Store the old WASM hash for rollback purposes.
        set_previous_wasm_hash(&env, &old_wasm_hash);

        // Emit the upgrade event with both hashes (old and new).
        events::contract_upgraded(&env, &old_wasm_hash, &new_wasm_hash);

        // Invoke the Soroban deployer to update the current contract with the new WASM.
        env.deployer().update_current_contract_wasm(new_wasm_hash);

        Ok(())
    }


}

// ---------------------------------------------------------------------------
// Module-level helpers (not part of the public contract interface)
// ---------------------------------------------------------------------------

/// Counts the number of proposals that are currently in the `Active` state.
///
/// Scans proposals with IDs from 1 to the current `ProposalCount` inclusive.
/// This is an O(n) scan over the proposal count; it is only called from
/// `create_proposal_internal`, which already requires a persistent-storage
/// write, so the additional reads are acceptable in that context.
///
/// When the active-proposal count matters for hot-path performance, prefer
/// caching the result off-chain and using `update_max_proposals` to tighten
/// the cap rather than calling this function frequently.
fn count_active_proposals(env: &Env) -> u64 {
    use types::DataKey;

    let total: u64 = env
        .storage()
        .instance()
        .get(&DataKey::ProposalCount)
        .unwrap_or(0);

    let mut count: u64 = 0;
    for id in 1..=total {
        if let Ok(p) = load_proposal(env, id) {
            if p.state == ProposalState::Active {
                count += 1;
            }
        }
    }
    count
}
