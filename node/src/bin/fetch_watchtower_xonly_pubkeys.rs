use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result, anyhow};
use bitvm2_noded::env::{
    ENV_GOAT_CHAIN_URL, ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_GOAT_NETWORK,
    get_goat_gateway_contract_from_env, get_goat_network, goat_config_from_env,
};
use client::goat_chain::GOATClient;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize)]
struct WatchtowerSnapshot {
    goat_chain_url: String,
    goat_gateway_contract_address: String,
    goat_network: String,
    committee_management_address: String,
    watchtower_xonly_public_keys: Vec<String>,
    watchtower_count: usize,
    watchtower_list_hash: String,
    watchtower_order_note: String,
    generated_at_unix: u64,
}

fn require_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("{name} must be set"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("node crate is under the workspace root")
        .to_path_buf()
}

fn snapshot_path(gateway: &EvmAddress) -> PathBuf {
    workspace_root()
        .join("target")
        .join("watchtower-snapshots")
        .join(format!("{}.json", gateway.to_string().to_lowercase()))
}

fn watchtower_list_hash(watchtower_pubkeys: &[String]) -> String {
    let mut hasher = Sha256::new();
    // The hash is intentionally order-sensitive because watchtower index maps to node_index.
    for key in watchtower_pubkeys {
        hasher.update(key.as_bytes());
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    let goat_chain_url = require_env(ENV_GOAT_CHAIN_URL)?;
    let goat_gateway_contract_address = require_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)?;
    let goat_network = env::var(ENV_GOAT_NETWORK).unwrap_or_else(|_| "test".to_string());

    let gateway = get_goat_gateway_contract_from_env();
    let goat_client = GOATClient::new(goat_config_from_env().await, get_goat_network());
    let committee_management_address =
        EvmAddress::from_slice(&goat_client.gateway_get_committee_management().await?);
    // Preserve on-chain order. The operator circuit compares this list by index with graph
    // watchtower_pubkeys, watchtower_challenge vouts, and included_watchtowers bitmap bits.
    let watchtower_pubkeys = goat_client
        .committee_mana_get_watchtowers()
        .await?
        .into_iter()
        .map(|key| format!("0x{}", hex::encode(key.serialize())))
        .collect::<Vec<_>>();

    if watchtower_pubkeys.is_empty() {
        return Err(anyhow!("committee management returned an empty watchtower list"));
    }

    let watchtower_list_hash = watchtower_list_hash(&watchtower_pubkeys);
    let snapshot = WatchtowerSnapshot {
        goat_chain_url,
        goat_gateway_contract_address,
        goat_network,
        committee_management_address: committee_management_address.to_string(),
        watchtower_count: watchtower_pubkeys.len(),
        watchtower_xonly_public_keys: watchtower_pubkeys.clone(),
        watchtower_list_hash: watchtower_list_hash.clone(),
        watchtower_order_note:
            "order-sensitive: index must match graph watchtower_pubkeys/node_index".to_string(),
        generated_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };

    let path = snapshot_path(&gateway);
    let parent = path.parent().context("snapshot path has parent")?;
    fs::create_dir_all(parent)?;
    fs::write(&path, serde_json::to_string_pretty(&snapshot)?)?;

    eprintln!("watchtower snapshot: {}", path.display());
    eprintln!("watchtower list hash: {watchtower_list_hash}");
    eprintln!(
        "before build, export FIXED_WATCHTOWER_XONLY_PUBLIC_KEYS or eval this command output"
    );
    println!("export FIXED_WATCHTOWER_XONLY_PUBLIC_KEYS={}", watchtower_pubkeys.join(","));

    Ok(())
}
