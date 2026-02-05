use crate::goat_chain::chain_adaptor::*;
use crate::utils::generate_random_bytes;
use alloy::primitives::{Address, TxHash, U256};
use alloy::rpc::types::{
    TransactionReceipt,
    trace::geth::{GethDebugTracingOptions, GethTrace, NoopFrame},
};
use anyhow::bail;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tracing::info;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct GatewayContractConfig {
    pub min_challenge_amount_sats: u64,
    pub min_pegin_fee_sats: u64,
    pub pegin_fee_rate: u64,
    pub min_operator_reward_sats: u64,
    pub operator_reward_rate: u64,
    pub min_stake_amount: u64,
    pub min_challenger_reward: u64,
    pub min_disprover_reward: u64,
    pub min_slash_amount: u64,
}

#[derive(Clone, Debug)]
pub struct MockAdaptor {
    finalized_block_number: Arc<Mutex<i64>>,
    latest_block_number: Arc<Mutex<i64>>,
    tx_receipts: Arc<Mutex<HashMap<String, TransactionReceipt>>>,
    gateway_contract_config: Arc<Mutex<GatewayContractConfig>>,
    pegin_data_store: Arc<Mutex<HashMap<[u8; 16], PeginData>>>,
    graph_data_store: Arc<Mutex<HashMap<[u8; 16], GraphData>>>,
    withdraw_data_store: Arc<Mutex<HashMap<[u8; 16], WithdrawData>>>,
    traces: Arc<Mutex<HashMap<String, GethTrace>>>,
    quorum_size: Arc<Mutex<u64>>,
    gateway_answer_pegin_request_calls: Arc<AtomicUsize>,
    committee_pubkeys: Arc<Mutex<Vec<Vec<u8>>>>,
    committee_members: Arc<Mutex<HashSet<[u8; 20]>>>,
    response_window_blocks: Arc<Mutex<u64>>,
}

impl MockAdaptor {
    pub fn set_finalized_block_number(&self, block_number: i64) {
        if let Ok(mut h) = self.finalized_block_number.lock() {
            *h = block_number
        }
    }

    pub fn set_latest_block_number(&self, block_number: i64) {
        if let Ok(mut h) = self.latest_block_number.lock() {
            *h = block_number
        }
    }

    pub fn set_tx_receipt(&self, tx_hash: String, receipt: TransactionReceipt) {
        if let Ok(mut h) = self.tx_receipts.lock() {
            h.insert(tx_hash, receipt);
        }
    }

    pub fn set_trace(&self, tx_hash: String, trace: GethTrace) {
        if let Ok(mut t) = self.traces.lock() {
            t.insert(tx_hash, trace);
        }
    }

    pub fn set_gateway_contract_config(&self, config: GatewayContractConfig) {
        if let Ok(mut h) = self.gateway_contract_config.lock() {
            *h = config;
        }
    }

    pub fn set_pegin_data(&self, instance_id: [u8; 16], data: PeginData) {
        if let Ok(mut h) = self.pegin_data_store.lock() {
            h.insert(instance_id, data);
        }
    }

    pub fn set_graph_data(&self, graph_id: [u8; 16], data: GraphData) {
        if let Ok(mut h) = self.graph_data_store.lock() {
            h.insert(graph_id, data);
        }
    }

    pub fn set_withdraw_data(&self, graph_id: [u8; 16], data: WithdrawData) {
        if let Ok(mut h) = self.withdraw_data_store.lock() {
            h.insert(graph_id, data);
        }
    }

    pub fn set_quorum_size(&self, size: u64) {
        if let Ok(mut h) = self.quorum_size.lock() {
            *h = size;
        }
    }

    pub fn set_committee_pubkeys(&self, pubkeys: Vec<Vec<u8>>) {
        if let Ok(mut h) = self.committee_pubkeys.lock() {
            *h = pubkeys;
        }
    }

    pub fn get_gateway_answer_pegin_request_calls(&self) -> usize {
        self.gateway_answer_pegin_request_calls.load(Ordering::SeqCst)
    }

    pub fn reset_gateway_answer_pegin_request_calls(&self) {
        self.gateway_answer_pegin_request_calls.store(0, Ordering::SeqCst);
    }

    pub fn set_committee_member(&self, member: [u8; 20], is_member: bool) {
        if let Ok(mut h) = self.committee_members.lock() {
            if is_member {
                h.insert(member);
            } else {
                h.remove(&member);
            }
        }
    }

    pub fn set_response_window_blocks(&self, blocks: u64) {
        if let Ok(mut h) = self.response_window_blocks.lock() {
            *h = blocks;
        }
    }
}

#[async_trait]
impl ChainAdaptor for MockAdaptor {
    fn get_default_signer_address(&self) -> Address {
        Address::ZERO
    }

    async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        match self.finalized_block_number.lock() {
            Ok(h) => Ok(*h),
            Err(_) => bail!("MockAdaptor::get_finalized_block_number() failed"),
        }
    }
    async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        match self.latest_block_number.lock() {
            Ok(h) => Ok(*h),
            Err(_) => bail!("MockAdaptor::get_latest_block_number() failed"),
        }
    }

    async fn get_tx_receipt(&self, tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>> {
        info!("call get_tx_receipt");
        Ok(if let Ok(tx_receipt) = self.tx_receipts.lock() {
            tx_receipt.get(tx_hash).cloned()
        } else {
            None
        })
    }

    async fn debug_trace_tx(
        &self,
        tx_hash: &str,
        _trace_options: Option<GethDebugTracingOptions>,
    ) -> anyhow::Result<GethTrace> {
        #[allow(clippy::collapsible_if)]
        if let Ok(traces) = self.traces.lock() {
            if let Some(trace) = traces.get(tx_hash) {
                return Ok(trace.clone());
            }
        }
        // Mock adaptor returns empty trace structure.
        Ok(GethTrace::NoopTracer(NoopFrame::default()))
    }

    async fn gateway_get_min_challenge_amount_sats(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() {
            h.min_challenge_amount_sats
        } else {
            0
        })
    }

    async fn gateway_get_min_pegin_fee_sats(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() { h.min_pegin_fee_sats } else { 0 })
    }

    async fn gateway_get_pegin_fee_rate(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() { h.pegin_fee_rate } else { 0 })
    }

    async fn gateway_get_min_operator_reward_sats(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() {
            h.min_operator_reward_sats
        } else {
            0
        })
    }

    async fn gateway_get_operator_reward_rate(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() { h.operator_reward_rate } else { 0 })
    }

    async fn gateway_get_min_stake_amount(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() { h.min_stake_amount } else { 0 })
    }

    async fn gateway_get_min_challenger_reward(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() {
            h.min_challenger_reward
        } else {
            0
        })
    }

    async fn gateway_get_min_disprover_reward(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() { h.min_disprover_reward } else { 0 })
    }

    async fn gateway_get_min_slash_amount(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.gateway_contract_config.lock() { h.min_slash_amount } else { 0 })
    }

    async fn gateway_get_committee_management(&self) -> anyhow::Result<[u8; 20]> {
        Ok([0_u8; 20])
    }

    async fn gateway_get_stake_management(&self) -> anyhow::Result<[u8; 20]> {
        Ok([0_u8; 20])
    }

    async fn gateway_get_pegin_data(&self, instance_id: &[u8; 16]) -> anyhow::Result<PeginData> {
        info!("call get_pegin_data");
        #[allow(clippy::collapsible_if)]
        if let Ok(store) = self.pegin_data_store.lock() {
            if let Some(data) = store.get(instance_id) {
                return Ok(data.clone());
            }
        }
        bail!("not find pegin data")
    }

    async fn gateway_get_withdraw_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<WithdrawData> {
        info!("call get_withdraw_data");
        if let Ok(store) = self.withdraw_data_store.lock()
            && let Some(data) = store.get(graph_id)
        {
            return Ok(data.clone());
        }

        bail!("not find withdraw data")
    }

    async fn gateway_get_graph_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<GraphData> {
        info!("call get_operator_data");
        if let Ok(store) = self.graph_data_store.lock()
            && let Some(data) = store.get(graph_id)
        {
            return Ok(data.clone());
        }

        bail!("not find operator data")
    }

    async fn gateway_get_response_window_blocks(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.response_window_blocks.lock() { *h } else { 1000 })
    }

    #[allow(clippy::too_many_arguments)]
    async fn gateway_post_pegin_request(
        &self,
        _instance_id: &[u8; 16],
        _pegin_amount_sats: u64,
        _tx_fees: &[u64; 3],
        _receiver_addr: &[u8; 20],
        _user_inputs: &[Utxo],
        _user_xonly_pubkey: &[u8; 32],
        _user_change_addr: &str,
        _user_refund_addr: &str,
    ) -> anyhow::Result<String> {
        Ok(TxHash::default().to_string())
    }

    async fn gateway_answer_pegin_request(
        &self,
        _instance_id: &[u8; 16],
        _committee_pubkey: &[u8],
    ) -> anyhow::Result<String> {
        self.gateway_answer_pegin_request_calls.fetch_add(1, Ordering::SeqCst);
        Ok(TxHash::default().to_string())
    }

    async fn gateway_post_pegin_data(
        &self,
        _instance_id: &[u8; 16],
        _raw_pgin_tx: &BitcoinTx,
        _pegin_proof: &BitcoinTxProof,
        _committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        info!("call post_pegin_data");
        Ok(TxHash::default().to_string())
    }

    async fn gateway_post_graph_data(
        &self,
        _instance_id: &[u8; 16],
        _graph_id: &[u8; 16],
        _operator_data: &GraphData,
        _committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        info!("call post_operator_data");
        Ok(TxHash::default().to_string())
    }

    async fn gateway_get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        info!("call get_initialized_ids");
        Ok(vec![])
    }

    async fn gateway_get_instanceids_by_pubkey(
        &self,
        _operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        info!("call get_instanceids_by_pubkey");
        Ok(vec![])
    }

    async fn gateway_init_withdraw(
        &self,
        _instance_id: &[u8; 16],
        _graph_id: &[u8; 16],
    ) -> anyhow::Result<String> {
        info!("call init_withdraw");
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn gateway_cancel_withdraw(&self, _graph_id: &[u8; 16]) -> anyhow::Result<String> {
        info!("call cancel_withdraw");
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn gateway_process_withdraw(
        &self,
        _graph_id: &[u8; 16],
        _raw_kickoff_tx: &BitcoinTx,
        _kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        info!("call process_withdraw");
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn gateway_finish_withdraw_happy_path(
        &self,
        _graph_id: &[u8; 16],
        _raw_take1_tx: &BitcoinTx,
        _take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        info!("call finish_withdraw_happy_path");
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn gateway_finish_withdraw_unhappy_path(
        &self,
        _graph_id: &[u8; 16],
        _raw_take2_tx: &BitcoinTx,
        _take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        info!("call finish_withdraw_unhappy_path");
        Ok(hex::encode(generate_random_bytes(32)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn gateway_finish_withdraw_disproved(
        &self,
        _graph_id: &[u8; 16],
        _disprove_type: DisproveTxType,
        _tx_index: u64,
        _raw_challenge_start_tx: &BitcoinTx,
        _challenge_start_proof: &BitcoinTxProof,
        _raw_challenge_finshish_tx: &BitcoinTx,
        _challenge_finish_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        info!("call gateway_finish_withdraw_disproved");
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn gateway_get_committee_pubkeys(
        &self,
        _instance_id: &[u8; 16],
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self.committee_pubkeys.lock().map(|v| v.clone()).unwrap_or_default())
    }

    async fn gateway_get_post_graph_digest(
        &self,
        _instance_id: &[u8; 16],
        _graph_id: &[u8; 16],
        _graph_data: GraphData,
    ) -> anyhow::Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn gateway_get_post_pegin_digest(
        &self,
        _instance_id: &[u8; 16],
        _pegin_txid: &[u8; 32],
    ) -> anyhow::Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn gateway_get_graph_ids_by_instance_id(
        &self,
        _instance_id: &[u8; 16],
    ) -> anyhow::Result<Vec<[u8; 16]>> {
        Ok(vec![])
    }

    async fn btc_spv_blockhash(&self, _height: u64) -> anyhow::Result<[u8; 32]> {
        info!("call get_btc_block_hash");
        Ok([0; 32])
    }

    async fn btc_spv_latest_height(&self) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn btc_spv_post_block_hash(
        &self,
        _height: u64,
        _header_hash: &[u8; 32],
    ) -> anyhow::Result<String> {
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn btc_spv_post_block_hash_batch(
        &self,
        _heights: &[u64],
        _header_hashes: &[[u8; 32]],
    ) -> anyhow::Result<String> {
        Ok(hex::encode(generate_random_bytes(32)))
    }

    async fn ss_update_sequencer_set(
        &self,
        _goat_height: U256,
        _witness: SequencerSetUpdateWitness,
    ) -> anyhow::Result<String> {
        Ok(String::new())
    }

    async fn ss_get_sequencer_set_update_witness(
        &self,
        _goat_height: U256,
    ) -> anyhow::Result<Vec<SequencerSetUpdateWitness>> {
        todo!()
    }

    async fn stake_mana_stake_token_address(&self) -> anyhow::Result<[u8; 20]> {
        Ok([0_u8; 20])
    }

    async fn stake_mana_pubkey_to_address(&self, _pubkey: &[u8; 32]) -> anyhow::Result<[u8; 20]> {
        Ok([0_u8; 20])
    }
    async fn stake_mana_stake_of(&self, _operator: &[u8; 20]) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn stake_mana_lock_stake_of(&self, _operator: &[u8; 20]) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn stake_mana_slash_stake(
        &self,
        _operator: &[u8; 20],
        _amount: u64,
    ) -> anyhow::Result<String> {
        Ok("".to_string())
    }

    async fn stake_mana_lock_stake(
        &self,
        _operator: &[u8; 20],
        _amount: u64,
    ) -> anyhow::Result<String> {
        Ok("".to_string())
    }

    async fn stake_mana_unlock_stake(
        &self,
        _operator: &[u8; 20],
        _amount: u64,
    ) -> anyhow::Result<String> {
        Ok("".to_string())
    }

    async fn committee_mana_is_committee_member(&self, member: &[u8; 20]) -> anyhow::Result<bool> {
        Ok(if let Ok(h) = self.committee_members.lock() { h.contains(member) } else { false })
    }

    async fn committee_mana_committee_size(&self) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn committee_mana_quorum_size(&self) -> anyhow::Result<u64> {
        Ok(if let Ok(h) = self.quorum_size.lock() { *h } else { 0 })
    }

    async fn committee_mana_verify_signatures(
        &self,
        _msg_hash: &[u8; 32],
        _signs: &[Vec<u8>],
    ) -> anyhow::Result<bool> {
        Ok(false)
    }

    async fn committee_mana_get_committee_peer_id(
        &self,
        _member: &[u8; 20],
    ) -> anyhow::Result<Vec<u8>> {
        Ok(vec![])
    }

    async fn committee_mana_is_validate_peer_id(&self, _peer_id: &[u8]) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn committee_mana_get_watchtowers(&self) -> anyhow::Result<Vec<[u8; 32]>> {
        Ok(vec![])
    }

    async fn committee_mana_add_watchtower(
        &self,
        _watchtower: &[u8; 32],
        _nonce: U256,
        _auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        Ok("".to_string())
    }

    async fn committee_mana_remove_watchtower(
        &self,
        _watchtower: &[u8; 32],
        _nonce: U256,
        _auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        Ok("".to_string())
    }

    async fn peg_btc_balance(&self, _address: &[u8; 20]) -> anyhow::Result<U256> {
        Ok(U256::default())
    }
}

impl Default for MockAdaptor {
    fn default() -> Self {
        Self::new()
    }
}

impl MockAdaptor {
    pub fn new() -> Self {
        Self {
            finalized_block_number: Arc::new(Mutex::new(0)),
            latest_block_number: Arc::new(Mutex::new(0)),
            tx_receipts: Arc::new(Mutex::new(HashMap::new())),
            gateway_contract_config: Arc::new(Mutex::new(Default::default())),
            pegin_data_store: Arc::new(Mutex::new(HashMap::new())),
            graph_data_store: Arc::new(Mutex::new(HashMap::new())),
            withdraw_data_store: Arc::new(Mutex::new(HashMap::new())),
            traces: Arc::new(Mutex::new(HashMap::new())),
            quorum_size: Arc::new(Mutex::new(0)),
            gateway_answer_pegin_request_calls: Arc::new(AtomicUsize::new(0)),
            committee_pubkeys: Arc::new(Mutex::new(Vec::new())),
            committee_members: Arc::new(Mutex::new(HashSet::new())),
            response_window_blocks: Arc::new(Mutex::new(1000)),
        }
    }
}
