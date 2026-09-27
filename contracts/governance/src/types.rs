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

use soroban_sdk::{contracterror, contracttype, Address, String};

/// All revert conditions for the governance contract.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    /// 1 – Admin address is not set
    AdminNotSet = 1,
    /// 2 – Caller is not the admin
    NotAdmin = 2,
    /// 3 – Voting token address is not set
    VotingTokenNotSet = 3,
    /// 4 – Quorum must be greater than zero
    InvalidQuorum = 4,
    /// 5 – Duration must be greater than zero
    InvalidDuration = 5,
    /// 6 – Proposal with the given ID does not exist
    ProposalNotFound = 6,
    /// 7 – Proposal is not in Active status
    ProposalNotActive = 7,
    /// 8 – Voting period has already ended
    VotingPeriodEnded = 8,
    /// 9 – Voting period has not ended yet
    VotingStillOpen = 9,
    /// 10 – Voter has already cast a vote on this proposal
    AlreadyVoted = 10,
    /// 11 – Voter has no token balance (no voting power)
    NoVotingPower = 11,
    /// 12 – Proposal has not passed
    ProposalNotPassed = 12,
    /// 13 – Contract has already been initialized
    AlreadyInitialized = 13,
    /// 14 – Vote tally arithmetic overflow
    VoteTallyOverflow = 14,
    /// 15 – Proposer has insufficient token balance to create a proposal
    InsufficientBalance = 15,
    /// 16 – Proposer must wait for the cooldown period to expire
    ProposalCooldown = 16,
    /// 17 – Proposal title exceeds maximum byte length
    TitleTooLong = 17,
    /// 18 – Proposal description exceeds maximum byte length
    DescriptionTooLong = 18,
    /// 19 – Proposal title is empty or exceeds maximum byte length
    InvalidTitle = 19,
    /// 20 – Proposal description is empty or exceeds maximum byte length
    InvalidDescription = 20,
    /// 21 – Duration is outside the allowed [MIN_DURATION, MAX_DURATION] range
    InvalidDurationRange = 21,
    /// 22 – Quorum exceeds the total token supply
    QuorumExceedsSupply = 22,
    /// 23 – Voting period has not yet started
    VotingNotStarted = 23,
    /// 24 – New admin address is invalid (e.g. zero address)
    InvalidNewAdmin = 24,
    /// 25 – Admin is not permitted to vote on their own proposals
    AdminVoteRestricted = 25,
    /// 26 – Contract is paused; state-changing operations are blocked
    ContractPaused = 26,
    /// 27 – Contract is not paused
    NotPaused = 27,
    /// 28 – Address parameter is the zero/default address
    InvalidAddress = 28,
    /// 29 – Proposal ID counter overflowed (u64::MAX reached)
    ProposalCountOverflow = 29,
    /// 30 – Timelock period has not yet expired
    TimelockNotExpired = 30,
    /// 31 – No pending admin transfer has been proposed
    PendingAdminNotSet = 31,
    /// 32 – The admin transfer window has expired; propose again
    AdminTransferExpired = 32,
    /// 33 – Caller is not the pending admin
    NotPendingAdmin = 33,
    /// 34 – Delegator cannot vote directly while their power is delegated
    VotingPowerDelegated = 34,
    /// 35 – Cannot delegate to self
    CannotDelegateToSelf = 35,
    /// 36 – Cannot delegate to the zero address
    InvalidDelegateAddress = 36,
    /// 37 – Invalid parameter change proposal (e.g., invalid ConfigKey or semantic error)
    InvalidParameterChange = 37,
    /// 38 – Parameter change is not supported for the given proposal type
    ParameterChangeNotSupported = 38,
    /// 39 – Token is already registered in multi-token voting
    TokenAlreadyRegistered = 39,
    /// 40 – Token is not registered in multi-token voting
    TokenNotRegistered = 40,
    /// 41 – Cannot remove the last voting token (DAO must have at least one)
    CannotRemoveLastToken = 41,
    /// 42 – Weight multiplier must be greater than zero
    InvalidWeightMultiplier = 42,
    /// 43 – Global cap on simultaneously active proposals has been reached
    TooManyActiveProposals = 43,
}

/// Different types of proposals the governance contract supports.
/// Standard proposals affect specific proposals; parameter change proposals update contract configuration.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalType {
    /// Standard governance proposal (default)
    Standard,
    /// Parameter change proposal that updates contract configuration when executed
    ParameterChange {
        key: ConfigKey,
        /// New value as a 64-bit unsigned integer (suitable for durations, balances, etc.)
        /// The contract enforces semantic validation based on the ConfigKey.
        value: u64,
    },
}
///
/// - `Uninitialized`: the contract has been deployed but `initialize` has not
///   yet been called. No governance operations are possible.
/// - `Ready`: `initialize` completed successfully. The contract is fully
///   operational.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ContractState {
    Uninitialized,
    Ready,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalState {
    Active,
    Passed,
    Rejected,
    Executed,
    Cancelled,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Vote {
    Yes,
    No,
    Abstain,
}

/// Configuration keys that can be changed via governance proposals.
/// These are used in ParameterChange proposals to identify which parameter is being updated.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ConfigKey {
    /// Minimum token balance required to create a proposal
    MinProposalBalance = 1,
    /// Minimum seconds between consecutive proposals per address
    ProposalCooldown = 2,
    /// Mandatory delay (seconds) between proposal passing and execution
    TimelockDuration = 3,
    /// Minimum allowed voting duration in seconds
    MinDuration = 4,
    /// Maximum allowed voting duration in seconds
    MaxDuration = 5,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Address,
    pub title: String,
    pub description: String,
    pub votes_yes: i128,
    pub votes_no: i128,
    pub votes_abstain: i128,
    pub quorum: i128, // minimum total votes required to pass
    pub start_time: u64,
    pub end_time: u64,
    pub state: ProposalState,
    /// Earliest Unix timestamp at which the proposal may be executed.
    /// Set to `end_time + timelock_duration` when the proposal passes; 0 otherwise.
    pub execute_after: u64,
    /// Type of proposal (Standard or ParameterChange)
    pub proposal_type: ProposalType,
}

/// Pending multi-sig action types.
///
/// Each variant represents a privileged admin operation that requires
/// M-of-N co-signer approval before it is executed on-chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum MultisigAction {
    /// Mark a passed proposal as executed.
    AdminExecute(u64),
    /// Cancel an active proposal.
    AdminCancel(u64),
    /// Pause the contract.
    AdminPause,
    /// Unpause the contract.
    AdminUnpause,
    /// Update the quorum threshold on an active proposal.
    AdminUpdateQuorum(u64, i128),
    /// Transfer the admin set to a new set of addresses.
    AdminTransfer(soroban_sdk::Vec<Address>),
}

/// Stored record of a pending multi-sig action and its current approvals.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingMultisigAction {
    /// The action to be executed once the threshold is reached.
    pub action: MultisigAction,
    /// Addresses that have already approved this action.
    pub approvals: soroban_sdk::Vec<Address>,
    /// Unix timestamp after which this action expires.
    pub expires_at: u64,
}

/// Configuration for a voting token in multi-asset voting.
/// Stores a token contract address and its relative weight multiplier.
#[contracttype]
#[derive(Clone, Debug)]
pub struct VotingTokenConfig {
    /// Address of the token contract (e.g., USDC, governance NFT)
    pub token_address: Address,
    /// Weight multiplier for votes from this token (e.g., 100 = 1x, 200 = 2x)
    /// Allows different tokens to have different voting influence
    pub weight_multiplier: u64,
}
///
/// Every storage entry is keyed by a variant of this enum.  Because Soroban
/// serialises the variant discriminant as part of the XDR key, each variant
/// occupies a completely separate key space — two variants with the same
/// payload can never collide.
///
/// ## Key-space map (SEC-006 collision analysis)
///
/// | Variant                          | Storage tier | Description                                         |
/// |----------------------------------|--------------|-----------------------------------------------------|
/// | `Proposal(u64)`                  | Persistent   | Full proposal struct, keyed by proposal ID          |
/// | `ProposalCount`                  | Instance     | Monotonic counter used to assign proposal IDs       |
/// | `HasVoted(u64, Address)`         | Persistent   | Boolean flag: has this voter voted on this proposal |
/// | `VoteRecord(u64, Address)`       | Persistent   | Detailed vote record (type + weight) per voter      |
/// | `VoterSnapshot(u64, Address)`    | Persistent   | Token-balance snapshot captured at vote time        |
/// | `LastProposal(Address)`          | Persistent   | Timestamp of a proposer's most recent proposal      |
/// | `Admin`                          | Instance     | Contract administrator address                      |
/// | `VotingToken`                    | Instance     | Governance token contract address                   |
/// | `MinProposalBalance`             | Instance     | Minimum token balance required to create a proposal |
/// | `ProposalCooldown`               | Instance     | Seconds a proposer must wait between proposals      |
/// | `ContractState`                  | Instance     | Lifecycle state (Uninitialized / Ready)             |
/// | `RestrictAdminVote`              | Instance     | Whether admin vote on own proposals is blocked      |
/// | `Paused`                         | Instance     | Whether the contract is currently paused            |
/// | `Version`                        | Instance     | Semver tuple `(major, minor, patch)`                |
///
/// ## Collision safety
///
/// Soroban serialises each `DataKey` variant by encoding the enum discriminant
/// **before** any payload into the XDR key.  This means:
///
/// - `HasVoted(id, addr)`, `VoteRecord(id, addr)`, and `VoterSnapshot(id, addr)`
///   share the same payload shape `(u64, Address)` but have distinct discriminants,
///   so they can never alias each other regardless of the argument values.
/// - Singleton variants (`Admin`, `VotingToken`, `ProposalCount`, …) have no
///   payload, so their keys are fixed and globally unique within this contract.
/// - No two distinct variants can produce the same serialised key because the
///   discriminant is always the first element of the encoding.
#[contracttype]
pub enum DataKey {
    /// Full [`Proposal`] struct, keyed by proposal ID (persistent storage).
    /// Key space: one entry per unique `u64` proposal ID.
    Proposal(u64),

    /// Monotonic counter used to derive the next proposal ID (instance storage).
    /// Key space: singleton — only one `ProposalCount` entry exists.
    ProposalCount,

    /// Boolean flag recording whether `voter` has voted on `proposal_id` (persistent storage).
    /// Key space: one entry per `(proposal_id, voter)` pair.
    /// Kept separate from `VoteRecord` so existence checks are cheap.
    HasVoted(u64, Address),

    /// Detailed vote record (vote type + weight) for `voter` on `proposal_id` (persistent storage).
    /// Key space: one entry per `(proposal_id, voter)` pair.
    VoteRecord(u64, Address),

    /// Contract administrator address (instance storage).
    /// Key space: singleton — only one `Admin` entry exists.
    Admin,

    /// Address of the governance token contract (instance storage).
    /// Key space: singleton — only one `VotingToken` entry exists.
    VotingToken,

    /// Minimum token balance a proposer must hold to create a proposal (instance storage).
    /// Key space: singleton — only one `MinProposalBalance` entry exists.
    MinProposalBalance,

    /// Minimum seconds a proposer must wait between consecutive proposals (instance storage).
    /// Key space: singleton — only one `ProposalCooldown` entry exists.
    ProposalCooldown,

    /// Lifecycle state of the governance contract (instance storage).
    /// Key space: singleton — only one `ContractState` entry exists.
    ContractState,

    /// Whether admin is restricted from voting on their own proposals (instance storage).
    /// Key space: singleton — only one `RestrictAdminVote` entry exists.
    RestrictAdminVote,

    /// Whether the contract is currently paused (instance storage).
    /// Key space: singleton — only one `Paused` entry exists.
    Paused,

    /// Timestamp (Unix seconds) of `proposer`'s most recent proposal (persistent storage).
    /// Key space: one entry per unique proposer address.
    LastProposal(Address),

    /// Contract version stored as a `(major, minor, patch)` semver tuple (instance storage).
    /// Key space: singleton — only one `Version` entry exists.
    Version,

    /// Token-balance snapshot for `voter` on `proposal_id`, captured at vote time (persistent storage).
    /// Key space: one entry per `(proposal_id, voter)` pair.
    /// Kept separate from `VoteRecord` to allow independent querying of vote weight.
    VoterSnapshot(u64, Address),

    /// Mandatory delay (seconds) between a proposal passing and it becoming executable (instance storage).
    /// Key space: singleton — only one `TimelockDuration` entry exists.
    TimelockDuration,

    /// Minimum allowed voting duration in seconds (instance storage).
    /// Key space: singleton — only one `MinDuration` entry exists.
    MinDuration,

    /// Maximum allowed voting duration in seconds (instance storage).
    /// Key space: singleton — only one `MaxDuration` entry exists.
    MaxDuration,

    /// Address nominated to become the next admin (instance storage).
    /// Set by `propose_admin_transfer`; cleared on acceptance or expiry.
    PendingAdmin,

    /// Unix timestamp after which the pending admin nomination expires (instance storage).
    AdminTransferExpiry,

    /// The address to which `delegator` has delegated their voting power (persistent storage).
    /// Key space: one entry per unique delegator address.
    /// Cleared when the delegator calls `undelegate`.
    ///
    /// Design note: only one delegation per delegator is allowed (no chaining).
    /// If a delegator wants to change their delegate they must first undelegate.
    Delegation(Address),

    /// List of registered voting tokens with per-token weight multipliers (instance storage).
    /// Stored as Vec<VotingTokenConfig>. Used for multi-asset voting support (v0.2.0+).
    /// Key space: singleton — only one `VotingTokens` entry exists.
    /// For backward compatibility, single-token DAOs store a token in `VotingToken`
    /// and may also have a corresponding entry in `VotingTokens`.
    VotingTokens,

    /// Global cap on the maximum number of simultaneously active proposals (instance storage).
    /// Defaults to 50 when not set. Set via `initialize` or `update_max_proposals`.
    /// Key space: singleton — only one `MaxActiveProposals` entry exists.
    MaxActiveProposals,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct VoteRecord {
    pub vote_type: Vote,
    pub weight: i128,
}
