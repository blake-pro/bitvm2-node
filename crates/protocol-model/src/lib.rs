use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use strum::{Display, EnumString};
use thiserror::Error;

#[derive(
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Display,
    EnumString,
)]
pub enum GraphStatus {
    #[default]
    OperatorPresigned,
    CommitteePresigned,
    OperatorDataPushed,
    PreKickoff,
    OperatorKickOff,
    Challenge,
    Disprove,
    Obsoleted,
    Skipped,
    OperatorTake1,
    OperatorTake2,
}

impl GraphStatus {
    pub fn get_closed_status() -> Vec<Self> {
        vec![Self::OperatorTake1, Self::OperatorTake2, Self::Skipped, Self::Disprove]
    }

    pub fn get_pegin_finalized_status() -> Self {
        Self::OperatorDataPushed
    }

    pub fn get_pegout_started_status() -> Vec<Self> {
        vec![Self::OperatorKickOff, Self::Challenge]
    }

    pub fn is_pegin_finalized(&self) -> bool {
        *self == Self::get_pegin_finalized_status()
    }

    pub fn is_pegout_started(&self) -> bool {
        Self::get_pegout_started_status().contains(self)
    }

    pub fn is_closed(&self) -> bool {
        Self::get_closed_status().contains(self)
    }

    pub fn is_obsoleted(&self) -> bool {
        *self == Self::Obsoleted
    }

    pub fn get_previous_status(&self) -> Option<Self> {
        match self {
            Self::OperatorPresigned => None,
            Self::CommitteePresigned => Some(Self::OperatorPresigned),
            Self::OperatorDataPushed => Some(Self::CommitteePresigned),
            Self::PreKickoff | Self::Skipped | Self::Obsoleted => Some(Self::OperatorDataPushed),
            Self::OperatorKickOff => Some(Self::PreKickoff),
            Self::OperatorTake1 | Self::Challenge => Some(Self::OperatorKickOff),
            Self::Disprove | Self::OperatorTake2 => Some(Self::Challenge),
        }
    }

    pub fn is_before(&self, other: &Self) -> bool {
        let mut current = *other;
        while let Some(previous) = current.get_previous_status() {
            if previous == *self {
                return true;
            }
            current = previous;
        }
        false
    }

    pub fn is_after(&self, other: &Self) -> bool {
        other.is_before(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct GraphKey {
    pub instance_id: String,
    pub graph_id: String,
    pub graph_nonce: u64,
}

impl GraphKey {
    pub fn new(
        instance_id: impl Into<String>,
        graph_id: impl Into<String>,
        graph_nonce: u64,
    ) -> Self {
        Self { instance_id: instance_id.into(), graph_id: graph_id.into(), graph_nonce }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct OutPointRef {
    pub txid: String,
    pub vout: u32,
}

impl OutPointRef {
    pub fn new(txid: impl Into<String>, vout: u32) -> Self {
        Self { txid: txid.into(), vout }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpendKind {
    Unspent,
    Expected,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct GraphState {
    pub status: GraphStatus,
    pub operator_proof_valid: bool,
    committee_signatures: BTreeMap<String, String>,
    finalized_hash: Option<String>,
}

impl GraphState {
    fn at(status: GraphStatus) -> Self {
        Self {
            status,
            operator_proof_valid: false,
            committee_signatures: BTreeMap::new(),
            finalized_hash: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PeginOutcome {
    Confirmed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProtocolState {
    pub committee_required: usize,
    #[serde(with = "graph_map_serde")]
    pub graphs: BTreeMap<GraphKey, GraphState>,
    #[serde(with = "spend_map_serde")]
    pub confirmed_spends: BTreeMap<OutPointRef, String>,
    pub pegin_outcomes: BTreeMap<String, PeginOutcome>,
    pub minted_instances: BTreeSet<String>,
}

mod graph_map_serde {
    use super::{GraphKey, GraphState};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S>(
        value: &BTreeMap<GraphKey, GraphState>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.iter().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<GraphKey, GraphState>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<(GraphKey, GraphState)>::deserialize(deserializer)?;
        Ok(entries.into_iter().collect())
    }
}

mod spend_map_serde {
    use super::OutPointRef;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S>(
        value: &BTreeMap<OutPointRef, String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.iter().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<OutPointRef, String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<(OutPointRef, String)>::deserialize(deserializer)?;
        Ok(entries.into_iter().collect())
    }
}

impl ProtocolState {
    pub fn new(committee_required: usize) -> Self {
        Self {
            committee_required,
            graphs: BTreeMap::new(),
            confirmed_spends: BTreeMap::new(),
            pegin_outcomes: BTreeMap::new(),
            minted_instances: BTreeSet::new(),
        }
    }

    pub fn graph(&self, key: &GraphKey) -> Option<&GraphState> {
        self.graphs.get(key)
    }

    pub fn with_graph(mut self, key: GraphKey, status: GraphStatus) -> Self {
        self.graphs.entry(key).or_insert_with(|| GraphState::at(status));
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct GraphObservation {
    pub key: GraphKey,
    pub committee_pre_signed: bool,
    pub goat_graph_recorded: bool,
    pub goat_graph_obsoleted: bool,
    pub prekickoff_confirmed: bool,
    pub prekickoff_spend: SpendKind,
    pub guardian_disprove: bool,
    pub connector_a_spend: SpendKind,
    pub take1_timelock_satisfied: bool,
    pub challenge_confirmed: bool,
    pub operator_proof_valid: bool,
    pub connector_d_spend: SpendKind,
    pub verifier_disprove: bool,
    pub take2_confirmed: bool,
    pub take2_timelock_satisfied: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProtocolEvent {
    CreateGraph { key: GraphKey },
    CommitteeSigned { key: GraphKey, signer: String, graph_hash: String, valid: bool },
    FinalizeGraph { key: GraphKey, graph_hash: String },
    GoatGraphRecorded { key: GraphKey },
    PreKickoffConfirmed { key: GraphKey },
    KickoffConfirmed { key: GraphKey, input: OutPointRef },
    ChallengeConfirmed { key: GraphKey, input: OutPointRef },
    OperatorProofAccepted { key: GraphKey, valid: bool },
    Take1Confirmed { key: GraphKey, input: OutPointRef, timelock_satisfied: bool },
    Take2Confirmed { key: GraphKey, input: OutPointRef, timelock_satisfied: bool },
    DisproveConfirmed { key: GraphKey, input: OutPointRef },
    SkipConfirmed { key: GraphKey, input: OutPointRef },
    PeginConfirmed { instance_id: String, input: OutPointRef },
    PeginCancelled { instance_id: String, input: OutPointRef },
    Minted { instance_id: String },
    Rescan { observation: GraphObservation },
}

#[derive(Clone, Debug, Error, Serialize, Deserialize, Eq, PartialEq)]
pub enum TransitionError {
    #[error("invalid committee signature")]
    InvalidSignature,
    #[error("invalid operator proof")]
    InvalidProof,
    #[error("not all configured committee signatures are present")]
    InsufficientCommitteeSignatures,
    #[error("honest committee signer already signed another graph hash")]
    ConflictingCommitteeSignature,
    #[error("message belongs to another graph or instance")]
    CrossGraphReplay,
    #[error("required preceding protocol stage is absent")]
    MissingPrerequisite,
    #[error("transaction timelock is not satisfied")]
    TimelockNotSatisfied,
    #[error("confirmed outpoint is already spent by a competing branch")]
    OutPointAlreadySpent,
    #[error("conflicting terminal state")]
    ConflictingTerminal,
    #[error("graph is unknown")]
    UnknownGraph,
}

fn graph_mut<'a>(
    state: &'a mut ProtocolState,
    key: &GraphKey,
) -> Result<&'a mut GraphState, TransitionError> {
    state.graphs.get_mut(key).ok_or(TransitionError::UnknownGraph)
}

fn claim(
    state: &mut ProtocolState,
    input: OutPointRef,
    owner: String,
) -> Result<(), TransitionError> {
    match state.confirmed_spends.get(&input) {
        Some(existing) if existing != &owner => Err(TransitionError::OutPointAlreadySpent),
        Some(_) => Ok(()),
        None => {
            state.confirmed_spends.insert(input, owner);
            Ok(())
        }
    }
}

fn branch_owner(key: &GraphKey, branch: &str) -> String {
    format!("{}:{}:{}:{branch}", key.instance_id, key.graph_id, key.graph_nonce)
}

/// Applies `event` to a clone of the current `state` without performing I/O.
pub fn apply_event(
    state: &ProtocolState,
    event: ProtocolEvent,
) -> Result<ProtocolState, TransitionError> {
    let mut next = state.clone();
    match event {
        ProtocolEvent::CreateGraph { key } => {
            next.graphs
                .entry(key)
                .or_insert_with(|| GraphState::at(GraphStatus::OperatorPresigned));
        }
        ProtocolEvent::CommitteeSigned { key, signer, graph_hash, valid } => {
            if !valid {
                return Err(TransitionError::InvalidSignature);
            }
            if !next.graphs.contains_key(&key) && !next.graphs.is_empty() {
                return Err(TransitionError::CrossGraphReplay);
            }
            let graph = next
                .graphs
                .entry(key)
                .or_insert_with(|| GraphState::at(GraphStatus::OperatorPresigned));
            match graph.committee_signatures.get(&signer) {
                Some(existing) if existing != &graph_hash => {
                    return Err(TransitionError::ConflictingCommitteeSignature);
                }
                Some(_) => {}
                None => {
                    graph.committee_signatures.insert(signer, graph_hash);
                }
            }
        }
        ProtocolEvent::FinalizeGraph { key, graph_hash } => {
            let required = next.committee_required;
            let graph = graph_mut(&mut next, &key)?;
            if graph.status == GraphStatus::CommitteePresigned
                && graph.finalized_hash.as_ref() == Some(&graph_hash)
            {
                return Ok(next);
            }
            if graph.status != GraphStatus::OperatorPresigned {
                return Err(TransitionError::MissingPrerequisite);
            }
            let matching = graph
                .committee_signatures
                .values()
                .filter(|signed_hash| *signed_hash == &graph_hash)
                .count();
            if matching < required {
                return Err(TransitionError::InsufficientCommitteeSignatures);
            }
            graph.finalized_hash = Some(graph_hash);
            graph.status = GraphStatus::CommitteePresigned;
        }
        ProtocolEvent::GoatGraphRecorded { key } => {
            let graph = graph_mut(&mut next, &key)?;
            if graph.status == GraphStatus::OperatorDataPushed {
                return Ok(next);
            }
            if graph.status != GraphStatus::CommitteePresigned {
                return Err(TransitionError::MissingPrerequisite);
            }
            graph.status = GraphStatus::OperatorDataPushed;
        }
        ProtocolEvent::PreKickoffConfirmed { key } => {
            let graph = graph_mut(&mut next, &key)?;
            if graph.status == GraphStatus::PreKickoff {
                return Ok(next);
            }
            if !matches!(graph.status, GraphStatus::OperatorDataPushed | GraphStatus::Obsoleted) {
                return Err(TransitionError::MissingPrerequisite);
            }
            if graph.status == GraphStatus::OperatorDataPushed {
                graph.status = GraphStatus::PreKickoff;
            }
        }
        ProtocolEvent::KickoffConfirmed { key, input } => {
            let current = graph_mut(&mut next, &key)?.status;
            if current == GraphStatus::OperatorKickOff {
                claim(&mut next, input, branch_owner(&key, "kickoff"))?;
                return Ok(next);
            }
            if !matches!(current, GraphStatus::PreKickoff | GraphStatus::Obsoleted) {
                return Err(TransitionError::MissingPrerequisite);
            }
            claim(&mut next, input, branch_owner(&key, "kickoff"))?;
            graph_mut(&mut next, &key)?.status = GraphStatus::OperatorKickOff;
        }
        ProtocolEvent::ChallengeConfirmed { key, input } => {
            let current = graph_mut(&mut next, &key)?.status;
            if current == GraphStatus::Challenge {
                claim(&mut next, input, branch_owner(&key, "challenge"))?;
                return Ok(next);
            }
            if current != GraphStatus::OperatorKickOff {
                return Err(TransitionError::MissingPrerequisite);
            }
            claim(&mut next, input, branch_owner(&key, "challenge"))?;
            graph_mut(&mut next, &key)?.status = GraphStatus::Challenge;
        }
        ProtocolEvent::OperatorProofAccepted { key, valid } => {
            if !valid {
                return Err(TransitionError::InvalidProof);
            }
            let graph = graph_mut(&mut next, &key)?;
            if graph.status != GraphStatus::Challenge {
                return Err(TransitionError::MissingPrerequisite);
            }
            graph.operator_proof_valid = true;
        }
        ProtocolEvent::Take1Confirmed { key, input, timelock_satisfied } => {
            let current = graph_mut(&mut next, &key)?.status;
            if current == GraphStatus::OperatorTake1 {
                claim(&mut next, input, branch_owner(&key, "take1"))?;
                return Ok(next);
            }
            if current != GraphStatus::OperatorKickOff {
                if next.confirmed_spends.contains_key(&input) {
                    return Err(TransitionError::OutPointAlreadySpent);
                }
                return Err(TransitionError::MissingPrerequisite);
            }
            if !timelock_satisfied {
                return Err(TransitionError::TimelockNotSatisfied);
            }
            claim(&mut next, input, branch_owner(&key, "take1"))?;
            graph_mut(&mut next, &key)?.status = GraphStatus::OperatorTake1;
        }
        ProtocolEvent::Take2Confirmed { key, input, timelock_satisfied } => {
            let graph = graph_mut(&mut next, &key)?;
            if graph.status == GraphStatus::OperatorTake2 {
                claim(&mut next, input, branch_owner(&key, "take2"))?;
                return Ok(next);
            }
            if graph.status != GraphStatus::Challenge || !graph.operator_proof_valid {
                if next.confirmed_spends.contains_key(&input) {
                    return Err(TransitionError::OutPointAlreadySpent);
                }
                return Err(TransitionError::MissingPrerequisite);
            }
            if !timelock_satisfied {
                return Err(TransitionError::TimelockNotSatisfied);
            }
            claim(&mut next, input, branch_owner(&key, "take2"))?;
            graph_mut(&mut next, &key)?.status = GraphStatus::OperatorTake2;
        }
        ProtocolEvent::DisproveConfirmed { key, input } => {
            let current = graph_mut(&mut next, &key)?.status;
            if current == GraphStatus::Disprove {
                claim(&mut next, input, branch_owner(&key, "disprove"))?;
                return Ok(next);
            }
            if !matches!(current, GraphStatus::OperatorKickOff | GraphStatus::Challenge) {
                return Err(TransitionError::MissingPrerequisite);
            }
            claim(&mut next, input, branch_owner(&key, "disprove"))?;
            graph_mut(&mut next, &key)?.status = GraphStatus::Disprove;
        }
        ProtocolEvent::SkipConfirmed { key, input } => {
            let current = graph_mut(&mut next, &key)?.status;
            if current == GraphStatus::Skipped {
                claim(&mut next, input, branch_owner(&key, "skip"))?;
                return Ok(next);
            }
            if !matches!(current, GraphStatus::PreKickoff | GraphStatus::Obsoleted) {
                return Err(TransitionError::MissingPrerequisite);
            }
            claim(&mut next, input, branch_owner(&key, "skip"))?;
            graph_mut(&mut next, &key)?.status = GraphStatus::Skipped;
        }
        ProtocolEvent::PeginConfirmed { instance_id, input } => {
            if next.pegin_outcomes.get(&instance_id) == Some(&PeginOutcome::Cancelled) {
                return Err(TransitionError::ConflictingTerminal);
            }
            if next.pegin_outcomes.get(&instance_id) == Some(&PeginOutcome::Confirmed) {
                claim(&mut next, input, format!("{instance_id}:pegin_confirm"))?;
                return Ok(next);
            }
            claim(&mut next, input, format!("{instance_id}:pegin_confirm"))?;
            next.pegin_outcomes.insert(instance_id, PeginOutcome::Confirmed);
        }
        ProtocolEvent::PeginCancelled { instance_id, input } => {
            if next.pegin_outcomes.get(&instance_id) == Some(&PeginOutcome::Confirmed) {
                return Err(TransitionError::ConflictingTerminal);
            }
            if next.pegin_outcomes.get(&instance_id) == Some(&PeginOutcome::Cancelled) {
                claim(&mut next, input, format!("{instance_id}:pegin_cancel"))?;
                return Ok(next);
            }
            claim(&mut next, input, format!("{instance_id}:pegin_cancel"))?;
            next.pegin_outcomes.insert(instance_id, PeginOutcome::Cancelled);
        }
        ProtocolEvent::Minted { instance_id } => {
            if next.minted_instances.contains(&instance_id) {
                return Ok(next);
            }
            if next.pegin_outcomes.get(&instance_id) != Some(&PeginOutcome::Confirmed) {
                return Err(TransitionError::MissingPrerequisite);
            }
            next.minted_instances.insert(instance_id);
        }
        ProtocolEvent::Rescan { observation } => {
            let status = derive_graph_status(&next, &observation)?;
            let graph = graph_mut(&mut next, &observation.key)?;
            if graph.status.is_closed() && graph.status != status {
                return Err(TransitionError::ConflictingTerminal);
            }
            graph.status = status;
        }
    }
    Ok(next)
}

/// Derives status using durable `state` and a stable confirmed-chain `observation`.
pub fn derive_graph_status(
    state: &ProtocolState,
    observation: &GraphObservation,
) -> Result<GraphStatus, TransitionError> {
    let initial = state
        .graph(&observation.key)
        .map(|graph| graph.status)
        .unwrap_or(GraphStatus::OperatorPresigned);
    if initial.is_closed() {
        return Ok(initial);
    }
    if !observation.committee_pre_signed {
        return Ok(GraphStatus::OperatorPresigned);
    }
    if !observation.goat_graph_recorded {
        return Ok(GraphStatus::CommitteePresigned);
    }
    if !observation.prekickoff_confirmed {
        return Ok(if observation.goat_graph_obsoleted {
            GraphStatus::Obsoleted
        } else {
            GraphStatus::OperatorDataPushed
        });
    }
    match observation.prekickoff_spend {
        SpendKind::Unspent => {
            return Ok(if observation.goat_graph_obsoleted {
                GraphStatus::Obsoleted
            } else {
                GraphStatus::PreKickoff
            });
        }
        SpendKind::Other => return Ok(GraphStatus::Skipped),
        SpendKind::Expected => {}
    }
    if observation.guardian_disprove {
        return Ok(GraphStatus::Disprove);
    }
    if observation.challenge_confirmed {
        if observation.verifier_disprove || observation.connector_d_spend == SpendKind::Other {
            return Ok(GraphStatus::Disprove);
        }
        if observation.take2_confirmed || observation.connector_d_spend == SpendKind::Expected {
            if !observation.operator_proof_valid {
                return Err(TransitionError::InvalidProof);
            }
            if !observation.take2_timelock_satisfied {
                return Err(TransitionError::TimelockNotSatisfied);
            }
            return Ok(GraphStatus::OperatorTake2);
        }
        return Ok(GraphStatus::Challenge);
    }
    match observation.connector_a_spend {
        SpendKind::Unspent => Ok(GraphStatus::OperatorKickOff),
        SpendKind::Other => Ok(GraphStatus::Challenge),
        SpendKind::Expected => {
            if !observation.take1_timelock_satisfied {
                Err(TransitionError::TimelockNotSatisfied)
            } else {
                Ok(GraphStatus::OperatorTake1)
            }
        }
    }
}
