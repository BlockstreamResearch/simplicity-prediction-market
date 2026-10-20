use super::*;
use simplex::simplicityhl::elements::bitcoin::hashes::Hash as _;
use simplex::simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction as Pset};
use simplex::simplicityhl::elements::secp256k1_zkp::{
    Message as ZkpMessage, PublicKey as ZkpPublicKey, SecretKey as ZkpSecretKey,
};
use simplex::simplicityhl::elements::{Address, AddressParams, PubkeyHash, sighash::SighashCache};
use tokio::sync::Mutex;

#[derive(Clone)]
pub(super) struct LocalWallet {
    secret_key: ZkpSecretKey,
    public_key: BitcoinPublicKey,
    address: Address,
    policy_asset: AssetId,
}

impl LocalWallet {
    pub(super) fn script_pubkey(&self) -> Script {
        self.address.script_pubkey()
    }

    pub(super) async fn load(path: &Path, network: SimplicityNetwork) -> Result<Self, AppError> {
        use tokio::io::AsyncWriteExt;

        let contents = match tokio::fs::read_to_string(path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let secret_key = ZkpSecretKey::new(&mut thread_rng());
                let contents = hex::encode(secret_key.secret_bytes());
                let mut options = tokio::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                let mut file = options.open(path).await?;
                file.write_all(contents.as_bytes()).await?;
                file.sync_all().await?;
                contents
            }
            Err(error) => return Err(error.into()),
        };
        let bytes = hex::decode(contents.trim()).map_err(|_| AppError::InvalidEscrowKey)?;
        let secret_key =
            ZkpSecretKey::from_slice(&bytes).map_err(|_| AppError::InvalidEscrowKey)?;
        Ok(Self::new(secret_key, network))
    }

    fn new(secret_key: ZkpSecretKey, network: SimplicityNetwork) -> Self {
        let public_key = BitcoinPublicKey::new(ZkpPublicKey::from_secret_key(
            &ZkpSecp256k1::new(),
            &secret_key,
        ));
        let params = if network.genesis_block_hash()
            == SimplicityNetwork::LiquidTestnet.genesis_block_hash()
        {
            &AddressParams::LIQUID_TESTNET
        } else {
            &AddressParams::ELEMENTS
        };
        Self {
            secret_key,
            public_key,
            address: Address::p2wpkh(&public_key, None, params),
            policy_asset: network.policy_asset(),
        }
    }

    fn sign(&self, pset: &mut Pset) -> Result<(), ApiError> {
        let index = pset
            .inputs()
            .len()
            .checked_sub(1)
            .ok_or_else(|| ApiError::bad_request("host funding input is missing"))?;
        let source = pset.inputs()[index]
            .witness_utxo
            .as_ref()
            .ok_or_else(|| ApiError::bad_request("host funding prevout is missing"))?;
        if source.script_pubkey != self.address.script_pubkey()
            || source.asset.explicit() != Some(self.policy_asset)
            || source.value.explicit().is_none()
            || pset.inputs()[index].sighash_type != Some(EcdsaSighashType::All.into())
        {
            return Err(ApiError::bad_request(
                "host funding input does not belong to the reserve wallet",
            ));
        }
        let transaction = pset
            .extract_tx()
            .map_err(|_| ApiError::bad_request("invalid escrow transaction"))?;
        let script_code = Script::new_p2pkh(&PubkeyHash::hash(&self.public_key.to_bytes()));
        let hash = SighashCache::new(&transaction).segwitv0_sighash(
            index,
            &script_code,
            source.value,
            EcdsaSighashType::All,
        );
        let message = ZkpMessage::from_digest(hash.to_byte_array());
        let mut signature = ZkpSecp256k1::new()
            .sign_ecdsa(&message, &self.secret_key)
            .serialize_der()
            .to_vec();
        signature.push(1);
        pset.inputs_mut()[index].final_script_witness =
            Some(vec![signature, self.public_key.to_bytes()].into());
        Ok(())
    }

    fn finalize(&self, pset: &mut Pset) -> Result<Transaction, ApiError> {
        let transaction = pset
            .extract_tx()
            .map_err(|_| ApiError::bad_request("invalid signed escrow transaction"))?;
        let host_index = pset
            .inputs()
            .len()
            .checked_sub(1)
            .ok_or_else(|| ApiError::bad_request("host funding input is missing"))?;
        for index in 0..host_index {
            let input = &pset.inputs()[index];
            let source = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| ApiError::bad_request("holder funding prevout is missing"))?;
            if !source.script_pubkey.is_v0_p2wpkh()
                || source.script_pubkey == self.address.script_pubkey()
                || input
                    .final_script_sig
                    .as_ref()
                    .is_some_and(|script| !script.is_empty())
            {
                return Err(ApiError::bad_request(
                    "holder funding must use its own native SegWit wallet",
                ));
            }
            let witness = if let Some(witness) = &input.final_script_witness {
                witness.clone()
            } else {
                let (key, signature) = input.partial_sigs.iter().find(|(key, _)| {
                    Address::p2wpkh(key, None, self.address.params).script_pubkey() == source.script_pubkey
                }).ok_or_else(|| ApiError::bad_request("Humid must sign all holder funding inputs before the host can open escrow"))?;
                vec![signature.clone(), key.to_bytes()].into()
            };
            if witness.len() != 2 || witness[0].last() != Some(&1) || witness[1].len() != 33 {
                return Err(ApiError::bad_request(
                    "holder funding requires a SIGHASH_ALL signature",
                ));
            }
            let public_key = ZkpPublicKey::from_slice(&witness[1])
                .map_err(|_| ApiError::bad_request("invalid holder public key"))?;
            if Address::p2wpkh(
                &BitcoinPublicKey::new(public_key),
                None,
                self.address.params,
            )
            .script_pubkey()
                != source.script_pubkey
            {
                return Err(ApiError::bad_request(
                    "holder signature does not match the funding script",
                ));
            }
            let signature =
                simplex::simplicityhl::elements::secp256k1_zkp::ecdsa::Signature::from_der(
                    &witness[0][..witness[0].len() - 1],
                )
                .map_err(|_| ApiError::bad_request("invalid holder signature"))?;
            let script_code = Script::new_p2pkh(&PubkeyHash::hash(&witness[1]));
            let hash = SighashCache::new(&transaction).segwitv0_sighash(
                index,
                &script_code,
                source.value,
                EcdsaSighashType::All,
            );
            ZkpSecp256k1::new()
                .verify_ecdsa(
                    &ZkpMessage::from_digest(hash.to_byte_array()),
                    &signature,
                    &public_key,
                )
                .map_err(|_| ApiError::bad_request("holder funding signature is invalid"))?;
            pset.inputs_mut()[index].final_script_witness = Some(witness);
        }
        self.sign(pset)?;
        pset.extract_tx()
            .map_err(|_| ApiError::bad_request("invalid finalized escrow transaction"))
    }

    async fn verify_holder_inputs(
        &self,
        state: &AppState,
        inputs: &[Input],
    ) -> Result<(), ApiError> {
        let base = state.config.chain_backend.esplora_url.trim_end_matches('/');
        let mut transactions = HashMap::<Txid, Transaction>::new();
        for input in inputs {
            let txid = input.previous_txid;
            if !transactions.contains_key(&txid) {
                let raw = state
                    .chain_client
                    .get(format!("{base}/tx/{txid}/hex"))
                    .send()
                    .await
                    .map_err(|_| ApiError::internal("holder funding transaction unavailable"))?
                    .error_for_status()
                    .map_err(|_| ApiError::bad_request("holder funding transaction not found"))?
                    .text()
                    .await
                    .map_err(|_| ApiError::internal("invalid holder funding response"))?;
                let transaction: Transaction =
                    simplex::simplicityhl::elements::encode::deserialize(
                        &hex::decode(raw.trim())
                            .map_err(|_| ApiError::internal("invalid holder funding hex"))?,
                    )
                    .map_err(|_| ApiError::internal("invalid holder funding transaction"))?;
                if transaction.txid() != txid {
                    return Err(ApiError::internal(
                        "holder funding transaction ID does not match",
                    ));
                }
                transactions.insert(txid, transaction);
            }
            let source = transactions[&txid]
                .output
                .get(input.previous_output_index as usize)
                .ok_or_else(|| ApiError::bad_request("holder funding output does not exist"))?;
            let claimed = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| ApiError::bad_request("holder funding prevout is missing"))?;
            if source.asset != claimed.asset
                || source.value != claimed.value
                || source.nonce != claimed.nonce
                || source.script_pubkey != claimed.script_pubkey
                || source.script_pubkey == self.address.script_pubkey()
                || !source.script_pubkey.is_v0_p2wpkh()
            {
                return Err(ApiError::bad_request(
                    "holder funding must match its own on-chain native SegWit prevout",
                ));
            }
            let spent: serde_json::Value = state
                .chain_client
                .get(format!(
                    "{base}/tx/{txid}/outspend/{}",
                    input.previous_output_index
                ))
                .send()
                .await
                .map_err(|_| ApiError::internal("holder funding status unavailable"))?
                .error_for_status()
                .map_err(|_| ApiError::bad_request("holder funding status not found"))?
                .json()
                .await
                .map_err(|_| ApiError::internal("invalid holder funding status"))?;
            if spent["spent"] != false {
                return Err(ApiError::conflict("holder funding output is already spent"));
            }
        }
        Ok(())
    }

    async fn reserves(&self, state: &AppState) -> Result<Vec<(OutPoint, TxOut)>, ApiError> {
        let base = state.config.chain_backend.esplora_url.trim_end_matches('/');
        let genesis = state
            .chain_client
            .get(format!("{base}/block-height/0"))
            .send()
            .await
            .map_err(|_| ApiError::internal("reserve chain index unavailable"))?
            .error_for_status()
            .map_err(|_| ApiError::internal("reserve chain identity unavailable"))?
            .text()
            .await
            .map_err(|_| ApiError::internal("invalid reserve chain identity"))?;
        if genesis.trim() != state.config.genesis_block_hash {
            return Err(ApiError::conflict(
                "reserve chain index does not match the configured network",
            ));
        }
        let candidates: serde_json::Value = state
            .chain_client
            .get(format!("{base}/address/{}/utxo", self.address))
            .send()
            .await
            .map_err(|_| ApiError::internal("reserve chain index unavailable"))?
            .error_for_status()
            .map_err(|_| ApiError::internal("reserve address lookup failed"))?
            .json()
            .await
            .map_err(|_| ApiError::internal("invalid reserve address response"))?;
        let candidates = candidates
            .as_array()
            .ok_or_else(|| ApiError::internal("invalid reserve UTXOs"))?;
        let mut reserves = Vec::new();
        let mut transactions = HashMap::<Txid, Transaction>::new();
        for candidate in candidates
            .iter()
            .filter(|candidate| candidate["status"]["confirmed"] == true)
        {
            let txid: Txid = candidate["txid"]
                .as_str()
                .unwrap_or("")
                .parse()
                .map_err(|_| ApiError::internal("invalid reserve transaction ID"))?;
            let vout = candidate["vout"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| ApiError::internal("invalid reserve output index"))?;
            if !transactions.contains_key(&txid) {
                let raw = state
                    .chain_client
                    .get(format!("{base}/tx/{txid}/hex"))
                    .send()
                    .await
                    .map_err(|_| ApiError::internal("reserve transaction unavailable"))?
                    .error_for_status()
                    .map_err(|_| ApiError::internal("reserve transaction not found"))?
                    .text()
                    .await
                    .map_err(|_| ApiError::internal("invalid reserve transaction response"))?;
                let transaction: Transaction =
                    simplex::simplicityhl::elements::encode::deserialize(
                        &hex::decode(raw.trim())
                            .map_err(|_| ApiError::internal("invalid reserve transaction hex"))?,
                    )
                    .map_err(|_| ApiError::internal("invalid reserve transaction"))?;
                if transaction.txid() != txid {
                    return Err(ApiError::internal("reserve transaction ID does not match"));
                }
                transactions.insert(txid, transaction);
            }
            let transaction = &transactions[&txid];
            let output = transaction
                .output
                .get(vout as usize)
                .ok_or_else(|| ApiError::internal("reserve output not found"))?;
            if transaction.is_coinbase()
                || output.script_pubkey != self.address.script_pubkey()
                || output.asset.explicit() != Some(self.policy_asset)
                || output.value.explicit().is_none()
            {
                continue;
            }
            let spent: serde_json::Value = state
                .chain_client
                .get(format!("{base}/tx/{txid}/outspend/{vout}"))
                .send()
                .await
                .map_err(|_| ApiError::internal("reserve output status unavailable"))?
                .error_for_status()
                .map_err(|_| ApiError::internal("reserve output status not found"))?
                .json()
                .await
                .map_err(|_| ApiError::internal("invalid reserve output status"))?;
            if spent["spent"] == false {
                let outpoint = OutPoint::new(txid, vout);
                if !reserves.iter().any(|(existing, _)| *existing == outpoint) {
                    reserves.push((outpoint, output.clone()));
                }
            }
        }
        Ok(reserves)
    }
}

#[derive(Clone, Deserialize)]
pub struct EscrowConfig {
    #[serde(default)]
    pub wallet: String,
    #[serde(default)]
    pub private_key_file: Option<PathBuf>,
    pub max_stake_sats: u64,
}

#[derive(Serialize)]
pub(super) struct ReserveStatus {
    configured: bool,
    funding_address: Option<String>,
    balance_sats: u64,
    available_sats: u64,
    reserved_sats: u64,
    utxo_count: usize,
    max_stake_sats: u64,
}

pub(super) async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReserveStatus>, ApiError> {
    authenticate(&state, &headers).await?;
    let Some(wallet) = &state.reserve_wallet else {
        return Ok(Json(ReserveStatus {
            configured: false,
            funding_address: None,
            balance_sats: 0,
            available_sats: 0,
            reserved_sats: 0,
            utxo_count: 0,
            max_stake_sats: 0,
        }));
    };
    let reserves = wallet.reserves(&state).await?;
    let mut proposals = state.escrows.lock().await;
    proposals.retain(|_, proposal| proposal.expires_at > unix_time().unwrap_or(u64::MAX));
    let mut balance_sats = 0u64;
    let mut reserved_sats = 0u64;
    for (outpoint, output) in &reserves {
        let amount = output.value.explicit().expect("checked reserve amount");
        balance_sats = balance_sats
            .checked_add(amount)
            .ok_or_else(|| ApiError::internal("reserve balance overflows"))?;
        if proposals.values().any(|proposal| {
            proposal.pset.inputs().iter().any(|input| {
                input.previous_txid == outpoint.txid && input.previous_output_index == outpoint.vout
            })
        }) {
            reserved_sats += amount;
        }
    }
    Ok(Json(ReserveStatus {
        configured: true,
        funding_address: Some(wallet.address.to_string()),
        balance_sats,
        available_sats: balance_sats - reserved_sats,
        reserved_sats,
        utxo_count: reserves.len(),
        max_stake_sats: state
            .config
            .escrow
            .as_ref()
            .expect("configured local wallet")
            .max_stake_sats,
    }))
}

pub(super) struct Proposal {
    prediction_id: String,
    expires_at: u64,
    pset: Pset,
}

pub(super) type Proposals = Arc<Mutex<HashMap<String, Proposal>>>;

#[derive(Deserialize)]
pub(super) struct PrepareRequest {
    pset: String,
    stake_sats: u64,
    contract: DeriveContractRequest,
}

#[derive(Serialize)]
pub(super) struct FundingResponse {
    funding_id: String,
    pset: String,
    escrow_sats: u64,
}

#[derive(Deserialize)]
pub(super) struct CommitRequest {
    funding_id: String,
    pset: String,
}

#[derive(Serialize)]
pub(super) struct BroadcastResponse {
    txid: String,
}

async fn rpc(
    state: &AppState,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let config = state
        .config
        .escrow
        .as_ref()
        .ok_or_else(|| ApiError::conflict("host escrow reserves are not configured"))?;
    let backend = &state.config.chain_backend;
    let mut url = reqwest::Url::parse(&backend.rpc_url)
        .map_err(|_| ApiError::internal("invalid host wallet RPC URL"))?;
    url.path_segments_mut()
        .map_err(|_| ApiError::internal("invalid host wallet RPC URL"))?
        .pop_if_empty()
        .push("wallet")
        .push(&config.wallet);
    let response: serde_json::Value = state.chain_client.post(url)
        .basic_auth(&backend.rpc_username, Some(&backend.rpc_password))
        .json(&serde_json::json!({ "jsonrpc": "1.0", "id": "prediction-escrow", "method": method, "params": params }))
        .send().await.map_err(|_| ApiError::internal("host reserve wallet unavailable"))?
        .json().await.map_err(|_| ApiError::internal("invalid host wallet response"))?;
    if !response["error"].is_null() {
        return Err(ApiError::conflict(
            "host reserve wallet could not complete the escrow operation",
        ));
    }
    Ok(response["result"].clone())
}

fn parse_pset(value: &str) -> Result<Pset, ApiError> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid escrow PSET"))
}

fn validate_funding(
    pset: &Pset,
    stake: u64,
    policy: AssetId,
    contract: &Script,
    payout: &Script,
) -> Result<(), ApiError> {
    if pset.inputs().is_empty()
        || pset.inputs().len() > 64
        || !(4..=5).contains(&pset.outputs().len())
    {
        return Err(ApiError::bad_request("invalid escrow funding layout"));
    }
    let outputs = pset.outputs();
    if outputs[0].script_pubkey != *contract
        || outputs[0].amount != Some(stake)
        || outputs[0].asset != Some(policy)
        || outputs[0].blinding_key.is_some()
        || outputs[0].amount_comm.is_some()
        || outputs[0].asset_comm.is_some()
        || outputs[1].amount != Some(10_000)
        || outputs[1].script_pubkey.is_empty()
        || outputs[2].amount.unwrap_or(0) <= 1_000
        || outputs[2].script_pubkey != *payout
    {
        return Err(ApiError::bad_request(
            "escrow must contain the stake, oracle fee and wallet fee reserve",
        ));
    }
    for (index, output) in outputs.iter().enumerate() {
        if output.asset != Some(policy)
            || output.amount_comm.is_some()
            || output.asset_comm.is_some()
            || (index != 3 && output.blinding_key.is_some())
        {
            return Err(ApiError::bad_request(
                "invalid escrow funding asset or commitment",
            ));
        }
    }
    let fee = outputs.last().expect("checked funding outputs");
    if !fee.script_pubkey.is_empty()
        || fee.amount != Some(1_000)
        || fee.blinding_key.is_some()
        || (outputs.len() == 5 && outputs[3].script_pubkey != *payout)
    {
        return Err(ApiError::bad_request(
            "escrow change must return to the holder and fee must be 1000 sats",
        ));
    }
    let transaction = pset
        .extract_tx()
        .map_err(|_| ApiError::bad_request("invalid escrow transaction"))?;
    for (index, input) in transaction.input.iter().enumerate() {
        if input.is_coinbase()
            || input.is_pegin
            || input.has_issuance()
            || transaction.input[..index]
                .iter()
                .any(|other| other.previous_output == input.previous_output)
            || pset.inputs()[index].sighash_type != Some(EcdsaSighashType::All.into())
        {
            return Err(ApiError::bad_request(
                "escrow requires distinct regular inputs with SIGHASH_ALL",
            ));
        }
    }
    Ok(())
}

fn validate_signed(expected: &Pset, signed: &Pset) -> Result<(), ApiError> {
    let transaction = signed
        .extract_tx()
        .map_err(|_| ApiError::bad_request("invalid signed escrow transaction"))?;
    if transaction
        .input
        .iter()
        .any(|input| input.is_pegin || input.has_issuance())
    {
        return Err(ApiError::bad_request(
            "escrow inputs cannot issue or peg in assets",
        ));
    }
    if expected.inputs().len() != signed.inputs().len()
        || expected.outputs().len() != signed.outputs().len()
        || expected.global.tx_data.version != signed.global.tx_data.version
        || expected.locktime().ok() != signed.locktime().ok()
    {
        return Err(ApiError::bad_request(
            "escrow transaction layout changed after preparation",
        ));
    }
    for (original, input) in expected.inputs().iter().zip(signed.inputs()) {
        if original.previous_txid != input.previous_txid
            || original.previous_output_index != input.previous_output_index
            || original.sequence != input.sequence
            || input.sighash_type != Some(EcdsaSighashType::All.into())
            || input.issuance_value_amount.is_some()
            || input.issuance_value_comm.is_some()
            || input.issuance_inflation_keys.is_some()
            || input.issuance_inflation_keys_comm.is_some()
            || input.pegin_tx.is_some()
            || input.pegin_value.is_some()
            || (original.witness_utxo.is_some() && original.witness_utxo != input.witness_utxo)
        {
            return Err(ApiError::bad_request(
                "escrow inputs changed after preparation",
            ));
        }
    }
    for (original, output) in expected.outputs().iter().zip(signed.outputs()) {
        if original.script_pubkey != output.script_pubkey {
            return Err(ApiError::bad_request("escrow output destination changed"));
        }
        if original.blinding_key.is_none()
            && (original.amount != output.amount
                || original.asset != output.asset
                || output.amount_comm.is_some()
                || output.asset_comm.is_some()
                || output.ecdh_pubkey.is_some()
                || output.blinding_key.is_some())
        {
            return Err(ApiError::bad_request(
                "escrow, fees or host change changed after preparation",
            ));
        }
    }
    Ok(())
}

fn reject_host_inputs(pset: &Pset, candidates: &[serde_json::Value]) -> Result<(), ApiError> {
    if pset.inputs().iter().any(|input| {
        candidates.iter().any(|candidate| {
            candidate["txid"].as_str() == Some(&input.previous_txid.to_string())
                && candidate["vout"].as_u64() == Some(u64::from(input.previous_output_index))
        })
    }) {
        return Err(ApiError::bad_request(
            "holder funding inputs must not belong to the host reserve wallet",
        ));
    }
    Ok(())
}

pub(super) async fn prepare(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<PrepareRequest>,
) -> Result<Json<FundingResponse>, ApiError> {
    let config = state
        .config
        .escrow
        .as_ref()
        .ok_or_else(|| ApiError::conflict("host escrow reserves are not configured"))?;
    if request.stake_sats == 0 || request.stake_sats > config.max_stake_sats {
        return Err(ApiError::bad_request(
            "stake exceeds the configured host matching limit",
        ));
    }
    let escrow_sats = request
        .stake_sats
        .checked_mul(2)
        .ok_or_else(|| ApiError::bad_request("escrow amount overflows"))?;
    let now = unix_time()?;
    let market = find_prediction(&state, &id).await?;
    if market.deadline <= now {
        return Err(ApiError::conflict(
            "prediction is no longer open for escrow funding",
        ));
    }
    let payout = parse_script(&request.contract.payout_script_pubkey, "payout script")?;
    let derived = derive_contract(
        State(state.clone()),
        AxumPath(id.clone()),
        Json(request.contract),
    )
    .await?
    .0;
    let contract = parse_script(&derived.script_pubkey, "escrow script")?;
    let mut pset = parse_pset(&request.pset)?;
    validate_funding(
        &pset,
        request.stake_sats,
        state.network.policy_asset(),
        &contract,
        &payout,
    )?;
    if state.reserve_wallet.is_none()
        && (rpc(&state, "getblockchaininfo", serde_json::json!([])).await?["chain"]
            != "elementsregtest"
            || rpc(&state, "getblockhash", serde_json::json!([0]))
                .await?
                .as_str()
                != Some(&state.config.genesis_block_hash))
    {
        return Err(ApiError::conflict(
            "automatic host matching is only supported on the configured Elements regtest chain",
        ));
    }

    let mut proposals = state.escrows.lock().await;
    proposals.retain(|_, proposal| proposal.expires_at > now);
    if proposals.len() >= 64 {
        return Err(ApiError::conflict(
            "host funding queue is full; try again later",
        ));
    }
    let local_reserves = if let Some(wallet) = &state.reserve_wallet {
        let reserves = wallet.reserves(&state).await?;
        wallet.verify_holder_inputs(&state, pset.inputs()).await?;
        Some(reserves)
    } else {
        None
    };
    let candidates = if let Some(reserves) = &local_reserves {
        serde_json::Value::Array(reserves.iter().map(|(outpoint, output)| serde_json::json!({
            "txid": outpoint.txid.to_string(), "vout": outpoint.vout,
            "spendable": true, "confirmations": 1, "asset": output.asset.explicit().expect("checked reserve asset").to_string(),
        })).collect())
    } else {
        rpc(&state, "listunspent", serde_json::json!([0, 9999999])).await?
    };
    let candidates = candidates
        .as_array()
        .ok_or_else(|| ApiError::internal("invalid host reserve balance"))?;
    reject_host_inputs(&pset, candidates)?;
    let mut reserve = None;
    let mut pending_reserve = false;
    for candidate in candidates.iter().filter(|candidate| {
        candidate["spendable"] == true
            && candidate["confirmations"].as_u64().unwrap_or(0) >= 1
            && candidate["asset"].as_str() == Some(&state.config.policy_asset_id)
    }) {
        let txid: Txid = candidate["txid"]
            .as_str()
            .unwrap_or("")
            .parse()
            .map_err(|_| ApiError::internal("invalid host reserve outpoint"))?;
        let vout: u32 = candidate["vout"]
            .as_u64()
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ApiError::internal("invalid host reserve outpoint"))?;
        if pset
            .inputs()
            .iter()
            .any(|input| input.previous_txid == txid && input.previous_output_index == vout)
            || proposals.values().any(|proposal| {
                proposal
                    .pset
                    .inputs()
                    .iter()
                    .any(|input| input.previous_txid == txid && input.previous_output_index == vout)
            })
        {
            pending_reserve = true;
            continue;
        }
        let output = if let Some(reserves) = &local_reserves {
            reserves
                .iter()
                .find(|(outpoint, _)| outpoint.txid == txid && outpoint.vout == vout)
                .map(|(_, output)| output.clone())
                .ok_or_else(|| ApiError::internal("host reserve output disappeared"))?
        } else {
            let raw = rpc(
                &state,
                "getrawtransaction",
                serde_json::json!([txid.to_string()]),
            )
            .await?;
            let bytes = hex::decode(raw.as_str().unwrap_or(""))
                .map_err(|_| ApiError::internal("invalid host reserve transaction"))?;
            let transaction: Transaction =
                simplex::simplicityhl::elements::encode::deserialize(&bytes)
                    .map_err(|_| ApiError::internal("invalid host reserve transaction"))?;
            transaction
                .output
                .get(vout as usize)
                .cloned()
                .ok_or_else(|| ApiError::internal("invalid host reserve output"))?
        };
        if output.asset.explicit() == Some(state.network.policy_asset())
            && output
                .value
                .explicit()
                .is_some_and(|amount| amount >= request.stake_sats)
        {
            reserve = Some((txid, vout, output.clone()));
            break;
        }
    }
    let (txid, vout, output) = reserve.ok_or_else(|| {
        ApiError::conflict(if pending_reserve {
            "host reserves are temporarily reserved by a pending opening; retry after it completes, is cancelled, or expires (up to 10 minutes)"
        } else {
            "host reserves need a confirmed explicit LBTC output large enough to match this stake"
        })
    })?;
    let change = if let Some(wallet) = &state.reserve_wallet {
        wallet.address.script_pubkey()
    } else {
        let change_address =
            rpc(&state, "getrawchangeaddress", serde_json::json!(["bech32"])).await?;
        let address_info = rpc(
            &state,
            "getaddressinfo",
            serde_json::json!([change_address]),
        )
        .await?;
        parse_script(
            address_info["scriptPubKey"].as_str().unwrap_or(""),
            "host change script",
        )?
    };
    pset.outputs_mut()[0].amount = Some(escrow_sats);
    pset.add_input(Input {
        previous_txid: txid,
        previous_output_index: vout,
        witness_utxo: Some(output.clone()),
        sighash_type: Some(EcdsaSighashType::All.into()),
        ..Input::default()
    });
    let change_sats =
        output.value.explicit().expect("checked explicit reserve") - request.stake_sats;
    if change_sats > 0 {
        pset.add_output(Output::new_explicit(
            change,
            change_sats,
            state.network.policy_asset(),
            None,
        ));
    }
    let funding_id = Uuid::new_v4().to_string();
    proposals.insert(
        funding_id.clone(),
        Proposal {
            prediction_id: id,
            expires_at: now + 600,
            pset: pset.clone(),
        },
    );
    Ok(Json(FundingResponse {
        funding_id,
        pset: pset.to_string(),
        escrow_sats,
    }))
}

pub(super) async fn cancel(
    State(state): State<AppState>,
    AxumPath((id, funding_id)): AxumPath<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let mut proposals = state.escrows.lock().await;
    if proposals
        .get(&funding_id)
        .is_some_and(|proposal| proposal.prediction_id != id)
    {
        return Err(ApiError::not_found(
            "escrow proposal does not match this prediction",
        ));
    }
    proposals.remove(&funding_id);
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn commit(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<CommitRequest>,
) -> Result<Json<BroadcastResponse>, ApiError> {
    let mut proposals = state.escrows.lock().await;
    let proposal = proposals.get(&request.funding_id).ok_or_else(|| {
        ApiError::conflict("escrow funding proposal expired; prepare a new opening")
    })?;
    if proposal.prediction_id != id || proposal.expires_at <= unix_time()? {
        return Err(ApiError::conflict(
            "escrow funding proposal does not match this prediction or has expired",
        ));
    }
    let open = state
        .db
        .find(&id)
        .await?
        .is_some_and(|market| market.deadline > unix_time().unwrap_or(u64::MAX));
    if !open {
        return Err(ApiError::conflict(
            "prediction closed before escrow funding was signed",
        ));
    }
    let mut signed = parse_pset(&request.pset)?;
    validate_signed(&proposal.pset, &signed)?;
    let transaction_hex = if let Some(wallet) = &state.reserve_wallet {
        let input = signed.inputs().last().expect("prepared host input");
        let outpoint = OutPoint::new(input.previous_txid, input.previous_output_index);
        if !wallet
            .reserves(&state)
            .await?
            .iter()
            .any(|(candidate, output)| {
                *candidate == outpoint && input.witness_utxo.as_ref() == Some(output)
            })
        {
            return Err(ApiError::conflict(
                "host reserve output is no longer confirmed and unspent",
            ));
        }
        wallet
            .verify_holder_inputs(&state, &signed.inputs()[..signed.inputs().len() - 1])
            .await?;
        let transaction = wallet.finalize(&mut signed)?;
        validate_signed(&proposal.pset, &signed)?;
        hex::encode(simplex::simplicityhl::elements::encode::serialize(
            &transaction,
        ))
    } else {
        let processed = rpc(
            &state,
            "walletprocesspsbt",
            serde_json::json!([signed.to_string(), true, "ALL", true, false]),
        )
        .await?;
        let processed_pset = parse_pset(processed["psbt"].as_str().unwrap_or(""))?;
        validate_signed(&proposal.pset, &processed_pset)?;
        let finalized = rpc(
            &state,
            "finalizepsbt",
            serde_json::json!([processed_pset.to_string()]),
        )
        .await?;
        if finalized["complete"] != true {
            return Err(ApiError::bad_request(
                "Humid must sign all holder funding inputs before the host can open escrow",
            ));
        }
        finalized["hex"].as_str().unwrap_or("").to_owned()
    };
    let txid = broadcast_transaction(State(state.clone()), transaction_hex).await?;
    proposals.remove(&request.funding_id);
    Ok(Json(BroadcastResponse { txid }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn local_wallet_signs_only_its_explicit_host_input() {
        let wallet = LocalWallet::new(
            ZkpSecretKey::from_slice(&[1; 32]).unwrap(),
            SimplicityNetwork::LiquidTestnet,
        );
        assert!(wallet.address.to_string().starts_with("tex1"));
        assert!(wallet.address.blinding_pubkey.is_none());
        let (mut pset, _, _, _) = funding();
        let source = TxOut {
            asset: Asset::Explicit(wallet.policy_asset),
            value: Value::Explicit(1_000_000),
            nonce: Nonce::Null,
            script_pubkey: wallet.address.script_pubkey(),
            witness: TxOutWitness::default(),
        };
        pset.add_input(Input {
            previous_txid: "22".repeat(32).parse().unwrap(),
            previous_output_index: 0,
            witness_utxo: Some(source.clone()),
            sighash_type: Some(EcdsaSighashType::All.into()),
            ..Input::default()
        });
        wallet.sign(&mut pset).unwrap();
        assert!(pset.inputs()[0].final_script_witness.is_none());
        let witness = pset.inputs()[1].final_script_witness.as_ref().unwrap();
        let signature = simplex::simplicityhl::elements::secp256k1_zkp::ecdsa::Signature::from_der(
            &witness[0][..witness[0].len() - 1],
        )
        .unwrap();
        let transaction = pset.extract_tx().unwrap();
        let hash = SighashCache::new(&transaction).segwitv0_sighash(
            1,
            &Script::new_p2pkh(&PubkeyHash::hash(&wallet.public_key.to_bytes())),
            source.value,
            EcdsaSighashType::All,
        );
        ZkpSecp256k1::new()
            .verify_ecdsa(
                &ZkpMessage::from_digest(hash.to_byte_array()),
                &signature,
                &wallet.public_key.inner,
            )
            .unwrap();
        pset.inputs_mut()[1]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = Script::new();
        assert!(wallet.sign(&mut pset).is_err());
    }

    #[tokio::test]
    async fn local_key_file_is_persistent_and_rejects_invalid_keys() {
        let directory = std::env::temp_dir().join(format!("escrow-key-{}", Uuid::new_v4()));
        let path = directory.join("reserve.key");
        let first = LocalWallet::load(&path, SimplicityNetwork::LiquidTestnet)
            .await
            .unwrap();
        let second = LocalWallet::load(&path, SimplicityNetwork::LiquidTestnet)
            .await
            .unwrap();
        assert_eq!(first.address, second.address);
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                tokio::fs::metadata(&path)
                    .await
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        tokio::fs::write(&path, "invalid").await.unwrap();
        assert!(
            LocalWallet::load(&path, SimplicityNetwork::LiquidTestnet)
                .await
                .is_err()
        );
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[tokio::test]
    async fn local_wallet_matches_and_broadcasts_without_wallet_rpc() {
        for reserve_sats in [99_999, 100_000, 1_000_000] {
            local_wallet_matching_flow(reserve_sats).await;
        }
    }

    async fn local_wallet_matching_flow(reserve_sats: u64) {
        use std::sync::atomic::{AtomicBool, Ordering};

        let directory = std::env::temp_dir().join(format!("local-escrow-{}", Uuid::new_v4()));
        let key_path = directory.join("reserve.key");
        let network = SimplicityNetwork::LiquidTestnet;
        let wallet = LocalWallet::load(&key_path, network).await.unwrap();
        let holder = LocalWallet::new(ZkpSecretKey::from_slice(&[2; 32]).unwrap(), network);
        let policy = network.policy_asset();
        let source = TxOut {
            asset: Asset::Explicit(policy),
            value: Value::Explicit(reserve_sats),
            nonce: Nonce::Null,
            script_pubkey: wallet.address.script_pubkey(),
            witness: TxOutWitness::default(),
        };
        let reserve_tx = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![simplex::simplicityhl::elements::TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0; 32]), 0),
                ..Default::default()
            }],
            output: vec![
                source.clone(),
                TxOut {
                    asset: Asset::Explicit(parse_asset(&"99".repeat(32), "other").unwrap()),
                    ..source.clone()
                },
                TxOut {
                    script_pubkey: holder.address.script_pubkey(),
                    ..source.clone()
                },
                source.clone(),
            ],
        };
        let reserve_txid = reserve_tx.txid();
        let reserve_hex = hex::encode(simplex::simplicityhl::elements::encode::serialize(
            &reserve_tx,
        ));
        let holder_source = TxOut {
            asset: Asset::Explicit(policy),
            value: Value::Explicit(113_000),
            nonce: Nonce::Null,
            script_pubkey: holder.address.script_pubkey(),
            witness: TxOutWitness::default(),
        };
        let holder_tx = Transaction {
            output: vec![holder_source.clone()],
            ..reserve_tx.clone()
        };
        let holder_txid = holder_tx.txid();
        let holder_hex = hex::encode(simplex::simplicityhl::elements::encode::serialize(
            &holder_tx,
        ));
        let candidates = serde_json::json!([
            { "txid": reserve_txid.to_string(), "vout": 0, "status": { "confirmed": true } },
            { "txid": reserve_txid.to_string(), "vout": 1, "status": { "confirmed": true } },
            { "txid": reserve_txid.to_string(), "vout": 2, "status": { "confirmed": true } },
            { "txid": reserve_txid.to_string(), "vout": 3, "status": { "confirmed": false } },
        ]);
        let spent = Arc::new(AtomicBool::new(false));
        let spending = spent.clone();
        let received = Arc::new(Mutex::new(None::<Transaction>));
        let received_tx = received.clone();
        let broadcast_spent = spent.clone();
        let backend =
            Router::new()
                .merge(super::super::tests::oracle_routes("liquidtestnet"))
                .route(
                    "/block-height/0",
                    get(move || async move { network.genesis_block_hash().to_string() }),
                )
                .route(
                    "/address/{address}/utxo",
                    get(move || {
                        let candidates = candidates.clone();
                        async move { Json(candidates) }
                    }),
                )
                .route(
                    "/tx/{txid}/hex",
                    get(move |AxumPath(txid): AxumPath<String>| {
                        let raw = if txid == holder_txid.to_string() {
                            holder_hex.clone()
                        } else {
                            reserve_hex.clone()
                        };
                        async move { raw }
                    }),
                )
                .route(
                    "/tx/{txid}/outspend/{vout}",
                    get(move || {
                        let spent = spending.clone();
                        async move {
                            Json(serde_json::json!({ "spent": spent.load(Ordering::Relaxed) }))
                        }
                    }),
                )
                .route(
                    "/tx",
                    post(move |body: String| {
                        let received = received_tx.clone();
                        let spent = broadcast_spent.clone();
                        async move {
                            let transaction: Transaction =
                                simplex::simplicityhl::elements::encode::deserialize(
                                    &hex::decode(body).unwrap(),
                                )
                                .unwrap();
                            let txid = transaction.txid().to_string();
                            *received.lock().await = Some(transaction);
                            spent.store(true, Ordering::Relaxed);
                            txid
                        }
                    }),
                );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = super::super::tests::config();
        config.policy_asset_id = policy.to_string();
        config.genesis_block_hash = network.genesis_block_hash().to_string();
        config.chain_backend.esplora_url = format!("http://{}", listener.local_addr().unwrap());
        config.oracle_url = config.chain_backend.esplora_url.clone();
        config.chain_backend.rpc_url.clear();
        config.escrow = Some(EscrowConfig {
            wallet: String::new(),
            private_key_file: Some(key_path),
            max_stake_sats: 1_000_000,
        });
        let task = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let app = App::new(config).await.unwrap();
        app.state
            .sessions
            .write()
            .await
            .insert("admin-session".into(), unix_time().unwrap() + 3600);
        let admin_request = || {
            Request::builder()
                .uri("/api/admin/escrow")
                .header(header::AUTHORIZATION, "Bearer admin-session")
                .body(Body::empty())
                .unwrap()
        };
        let router = app.router();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/escrow")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = router.clone().oneshot(admin_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let info: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(info["funding_address"], wallet.address.to_string());
        assert_eq!(info["available_sats"], reserve_sats);
        assert_eq!(info["utxo_count"], 1);
        assert!(info.get("private_key").is_none());
        assert!(app.state.reserve_wallet.is_some());
        let response = public_config(State(app.state.clone())).await;
        assert!(response.0.matched_escrow_enabled);

        let id = "77".repeat(32);
        app.state
            .db
            .insert(&Prediction {
                id: id.clone(),
                title: "Local signer".into(),
                deadline: unix_time().unwrap() + 3600,
                created_at: unix_time().unwrap(),
                price: super::super::tests::price_terms(),
            })
            .await
            .unwrap();
        let parameters = serde_json::json!({ "payout_script_pubkey": hex::encode(holder.address.script_pubkey().as_bytes()), "tick_script_pubkey": "51", "owner_public_key": crate::tests::HOLDER_PUBLIC_KEY });
        let derived = derive_contract(
            State(app.state.clone()),
            AxumPath(id.clone()),
            Json(serde_json::from_value(parameters.clone()).unwrap()),
        )
        .await
        .unwrap()
        .0;
        let (mut pset, _, _, _) = funding();
        pset.outputs_mut()[0].script_pubkey =
            parse_script(&derived.script_pubkey, "position").unwrap();
        for output in pset.outputs_mut() {
            output.asset = Some(policy);
            if output.script_pubkey.is_v0_p2wpkh() {
                output.script_pubkey = holder.address.script_pubkey();
            }
        }
        pset.inputs_mut()[0].previous_txid = holder_txid;
        pset.inputs_mut()[0].witness_utxo = Some(holder_source.clone());
        let request = |path: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let body = serde_json::json!({ "stake_sats": 100_000, "pset": pset.to_string(), "contract": parameters });
        let response = router
            .clone()
            .oneshot(request(
                &format!("/api/predictions/{id}/escrow"),
                body.clone(),
            ))
            .await
            .unwrap();
        if reserve_sats < 100_000 {
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert!(app.state.escrows.lock().await.is_empty());
            task.abort();
            tokio::fs::remove_dir_all(directory).await.unwrap();
            return;
        }
        assert_eq!(response.status(), StatusCode::OK);
        let funding: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let mut matched = parse_pset(funding["pset"].as_str().unwrap()).unwrap();
        assert_eq!(matched.outputs()[0].amount, Some(200_000));
        assert_eq!(
            matched.outputs().len(),
            pset.outputs().len() + usize::from(reserve_sats > 100_000)
        );
        if reserve_sats > 100_000 {
            assert_eq!(
                matched.outputs().last().unwrap().amount,
                Some(reserve_sats - 100_000)
            );
            assert_eq!(
                matched.outputs().last().unwrap().script_pubkey,
                wallet.address.script_pubkey()
            );
        }
        let response = router.clone().oneshot(admin_request()).await.unwrap();
        let info: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(info["reserved_sats"], reserve_sats);
        assert_eq!(info["available_sats"], 0);
        let response = router
            .clone()
            .oneshot(request(
                &format!("/api/predictions/{id}/escrow"),
                body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let conflict: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(
            conflict["error"]
                .as_str()
                .unwrap()
                .contains("temporarily reserved")
        );
        let cancel_request = |market_id: &str| {
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/predictions/{market_id}/escrow/{}",
                    funding["funding_id"].as_str().unwrap()
                ))
                .body(Body::empty())
                .unwrap()
        };
        let response = router
            .clone()
            .oneshot(cancel_request("wrong-market"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(app.state.escrows.lock().await.len(), 1);
        for _ in 0..2 {
            let response = router.clone().oneshot(cancel_request(&id)).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        let response = router.clone().oneshot(admin_request()).await.unwrap();
        let info: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(info["available_sats"], reserve_sats);
        assert_eq!(info["reserved_sats"], 0);
        assert!(received.lock().await.is_none());
        let response = router
            .clone()
            .oneshot(request(&format!("/api/predictions/{id}/escrow"), body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let funding: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let commit_body = |pset: &Pset| serde_json::json!({ "funding_id": funding["funding_id"], "pset": pset.to_string() });
        let commit_path = format!("/api/predictions/{id}/escrow/commit");
        let response = router
            .clone()
            .oneshot(request(&commit_path, commit_body(&matched)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(received.lock().await.is_none());

        let transaction = matched.extract_tx().unwrap();
        let hash = SighashCache::new(&transaction).segwitv0_sighash(
            0,
            &Script::new_p2pkh(&PubkeyHash::hash(&holder.public_key.to_bytes())),
            holder_source.value,
            EcdsaSighashType::All,
        );
        let mut signature = ZkpSecp256k1::new()
            .sign_ecdsa(
                &ZkpMessage::from_digest(hash.to_byte_array()),
                &holder.secret_key,
            )
            .serialize_der()
            .to_vec();
        signature.push(1);
        matched.inputs_mut()[0]
            .partial_sigs
            .insert(holder.public_key, signature);
        let mut invalid = matched.clone();
        invalid.inputs_mut()[0]
            .partial_sigs
            .values_mut()
            .next()
            .unwrap()[5] ^= 1;
        let response = router
            .clone()
            .oneshot(request(&commit_path, commit_body(&invalid)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let mut invalid = matched.clone();
        invalid.inputs_mut()[0].witness_utxo.as_mut().unwrap().value = Value::Explicit(999_999);
        let response = router
            .clone()
            .oneshot(request(&commit_path, commit_body(&invalid)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let mut invalid = matched.clone();
        invalid.outputs_mut()[0].amount = Some(100_000);
        let response = router
            .clone()
            .oneshot(request(&commit_path, commit_body(&invalid)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = router
            .clone()
            .oneshot(request(&commit_path, commit_body(&matched)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let broadcast = received.lock().await.clone().unwrap();
        assert_eq!(broadcast.output[0].value.explicit(), Some(200_000));
        assert!(
            broadcast
                .input
                .iter()
                .all(|input| input.witness.script_witness.len() == 2)
        );
        let host_witness = &broadcast.input[1].witness.script_witness;
        let signature = simplex::simplicityhl::elements::secp256k1_zkp::ecdsa::Signature::from_der(
            &host_witness[0][..host_witness[0].len() - 1],
        )
        .unwrap();
        let hash = SighashCache::new(&broadcast).segwitv0_sighash(
            1,
            &Script::new_p2pkh(&PubkeyHash::hash(&wallet.public_key.to_bytes())),
            source.value,
            EcdsaSighashType::All,
        );
        ZkpSecp256k1::new()
            .verify_ecdsa(
                &ZkpMessage::from_digest(hash.to_byte_array()),
                &signature,
                &wallet.public_key.inner,
            )
            .unwrap();
        let response = router
            .oneshot(request(&commit_path, commit_body(&matched)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        task.abort();
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    fn funding() -> (Pset, Script, Script, AssetId) {
        let policy = parse_asset(&"66".repeat(32), "policy").unwrap();
        let payout = parse_script(&format!("0014{}", "55".repeat(20)), "payout").unwrap();
        let contract = parse_script(&format!("5120{}", "77".repeat(32)), "contract").unwrap();
        let mut pset = Pset::new_v2();
        pset.add_input(Input {
            previous_txid: "11".repeat(32).parse().unwrap(),
            previous_output_index: 0,
            sighash_type: Some(EcdsaSighashType::All.into()),
            ..Input::default()
        });
        for (script, amount) in [
            (contract.clone(), 100_000),
            (payout.clone(), 10_000),
            (payout.clone(), 2000),
            (Script::new(), 1000),
        ] {
            pset.add_output(Output::new_explicit(script, amount, policy, None));
        }
        (pset, contract, payout, policy)
    }

    #[test]
    fn funding_requires_stake_fees_and_holder_change() {
        let (pset, contract, payout, policy) = funding();
        assert!(validate_funding(&pset, 100_000, policy, &contract, &payout).is_ok());
        let owned = serde_json::json!({ "txid": "11".repeat(32), "vout": 0 });
        assert!(reject_host_inputs(&pset, &[owned]).is_err());
        assert!(reject_host_inputs(&pset, &[]).is_ok());
        for index in 0..4 {
            let mut invalid = pset.clone();
            invalid.outputs_mut()[index].asset =
                Some(parse_asset(&"99".repeat(32), "wrong").unwrap());
            assert!(validate_funding(&invalid, 100_000, policy, &contract, &payout).is_err());
        }
        let mut invalid = pset.clone();
        invalid.outputs_mut()[0].amount = Some(200_000);
        assert!(validate_funding(&invalid, 100_000, policy, &contract, &payout).is_err());
        let mut invalid = pset.clone();
        invalid.add_input(invalid.inputs()[0].clone());
        assert!(validate_funding(&invalid, 100_000, policy, &contract, &payout).is_err());
    }

    #[test]
    fn host_signing_rejects_changes_to_escrow_reserves_fees_and_inputs() {
        let (mut pset, _, payout, policy) = funding();
        pset.outputs_mut()[0].amount = Some(200_000);
        pset.add_input(Input {
            previous_txid: "22".repeat(32).parse().unwrap(),
            previous_output_index: 0,
            sighash_type: Some(EcdsaSighashType::All.into()),
            ..Input::default()
        });
        pset.add_output(Output::new_explicit(payout, 900_000, policy, None));
        assert!(validate_signed(&pset, &pset).is_ok());
        for index in 0..pset.outputs().len() {
            let mut invalid = pset.clone();
            invalid.outputs_mut()[index].amount = Some(1);
            assert!(validate_signed(&pset, &invalid).is_err());
            let mut invalid = pset.clone();
            invalid.outputs_mut()[index].script_pubkey = Script::new();
            if index != 3 {
                assert!(validate_signed(&pset, &invalid).is_err());
            }
        }
        let mut invalid = pset.clone();
        invalid.inputs_mut()[0].sighash_type = Some(EcdsaSighashType::None.into());
        assert!(validate_signed(&pset, &invalid).is_err());
        let mut invalid = pset.clone();
        invalid.inputs_mut()[1].previous_output_index = 1;
        assert!(validate_signed(&pset, &invalid).is_err());
        let mut invalid = pset.clone();
        invalid.inputs_mut()[0].issuance_value_amount = Some(100_000);
        assert!(validate_signed(&pset, &invalid).is_err());
    }

    #[tokio::test]
    async fn escrow_routes_match_once_and_reject_tampering_and_unsigned_openings() {
        let policy = parse_asset(&"66".repeat(32), "policy").unwrap();
        let wallet_script = parse_script(&format!("0014{}", "55".repeat(20)), "wallet").unwrap();
        let reserve_tx = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                asset: Asset::Explicit(policy),
                value: Value::Explicit(1_000_000),
                nonce: Nonce::Null,
                script_pubkey: wallet_script.clone(),
                witness: TxOutWitness::default(),
            }],
        };
        let reserve_hex = hex::encode(simplex::simplicityhl::elements::encode::serialize(
            &reserve_tx,
        ));
        let backend = Router::new().merge(super::super::tests::oracle_routes("elementsregtest")).route("/wallet/host", post(move |Json(request): Json<serde_json::Value>| {
            let reserve_hex = reserve_hex.clone();
            async move {
                let result = match request["method"].as_str().unwrap() {
                    "getblockchaininfo" => serde_json::json!({ "chain": "elementsregtest" }),
                    "getblockhash" => serde_json::json!("cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f"),
                    "listunspent" => serde_json::json!([{ "txid": "22".repeat(32), "vout": 0, "spendable": true, "confirmations": 1, "asset": "66".repeat(32) }]),
                    "getrawtransaction" => serde_json::json!(reserve_hex),
                    "getrawchangeaddress" => serde_json::json!("host-address"),
                    "getaddressinfo" => serde_json::json!({ "scriptPubKey": format!("0014{}", "88".repeat(20)) }),
                    "walletprocesspsbt" => {
                        assert_eq!(request["params"][2], "ALL");
                        assert_eq!(request["params"][4], false);
                        serde_json::json!({ "psbt": request["params"][0], "complete": false })
                    },
                    "finalizepsbt" => serde_json::json!({ "complete": false }),
                    method => panic!("unexpected wallet RPC: {method}"),
                };
                Json(serde_json::json!({ "result": result, "error": null }))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = super::super::tests::config();
        config.chain_backend.rpc_url = format!("http://{}", listener.local_addr().unwrap());
        config.oracle_url = config.chain_backend.rpc_url.clone();
        config.escrow = Some(EscrowConfig {
            wallet: "host".into(),
            private_key_file: None,
            max_stake_sats: 1_000_000,
        });
        let task = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let app = App::new(config).await.unwrap();
        let id = "77".repeat(32);
        app.state
            .db
            .insert(&Prediction {
                id: id.clone(),
                title: "Matched price market".into(),
                created_at: unix_time().unwrap(),
                deadline: unix_time().unwrap() + 3600,
                price: super::super::tests::price_terms(),
            })
            .await
            .unwrap();
        let parameters = serde_json::json!({ "payout_script_pubkey": hex::encode(wallet_script.as_bytes()), "tick_script_pubkey": "51", "owner_public_key": crate::tests::HOLDER_PUBLIC_KEY });
        let derived = derive_contract(
            State(app.state.clone()),
            AxumPath(id.clone()),
            Json(serde_json::from_value(parameters.clone()).unwrap()),
        )
        .await
        .unwrap()
        .0;
        let (mut pset, _, _, _) = funding();
        pset.outputs_mut()[0].script_pubkey =
            parse_script(&derived.script_pubkey, "contract").unwrap();
        let prepare_body = serde_json::json!({ "pset": pset.to_string(), "stake_sats": 100_000, "contract": parameters });
        let request = |path: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let response = app
            .router()
            .oneshot(request(
                &format!("/api/predictions/{id}/escrow"),
                prepare_body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let matched = parse_pset(body["pset"].as_str().unwrap()).unwrap();
        assert_eq!(body["escrow_sats"], 200_000);
        assert_eq!(matched.outputs()[0].amount, Some(200_000));
        assert_eq!(matched.outputs().last().unwrap().amount, Some(900_000));
        assert_eq!(matched.inputs().len(), 2);

        let response = app
            .router()
            .oneshot(request(
                &format!("/api/predictions/{id}/escrow"),
                prepare_body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let mut tampered = matched.clone();
        tampered.outputs_mut()[0].amount = Some(100_000);
        for (pset, expected) in [
            (tampered, StatusCode::BAD_REQUEST),
            (matched.clone(), StatusCode::BAD_REQUEST),
        ] {
            let response = app.router().oneshot(request(&format!("/api/predictions/{id}/escrow/commit"), serde_json::json!({ "funding_id": body["funding_id"], "pset": pset.to_string() }))).await.unwrap();
            assert_eq!(response.status(), expected);
        }
        app.state.db.set_deadline(&id, 0).await.unwrap();
        let response = app.router().oneshot(request(&format!("/api/predictions/{id}/escrow/commit"), serde_json::json!({ "funding_id": body["funding_id"], "pset": matched.to_string() }))).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        task.abort();
    }

    #[tokio::test]
    #[ignore = "requires funded local Elements regtest host and bootstrap wallets; locks a 1000-sat host match"]
    async fn live_regtest_co_signing_opens_a_doubled_escrow() {
        let mut config = Config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("config.toml"))
            .await
            .unwrap();
        config.database_url = "sqlite::memory:".into();
        config.database_max_connections = 1;
        let app = App::new(config).await.unwrap();
        assert_eq!(
            rpc(&app.state, "getblockchaininfo", serde_json::json!([]))
                .await
                .unwrap()["chain"],
            "elementsregtest"
        );
        let mut holder = app.state.clone();
        holder.config.escrow.as_mut().unwrap().wallet = "bootstrap".into();
        let outputs = rpc(&holder, "listunspent", serde_json::json!([1, 9999999]))
            .await
            .unwrap();
        let mut source = None;
        for candidate in outputs
            .as_array()
            .unwrap()
            .iter()
            .filter(|output| output["spendable"] == true)
        {
            let txid: Txid = candidate["txid"].as_str().unwrap().parse().unwrap();
            let vout = candidate["vout"].as_u64().unwrap() as u32;
            let raw = rpc(
                &holder,
                "getrawtransaction",
                serde_json::json!([txid.to_string()]),
            )
            .await
            .unwrap();
            let transaction: Transaction = simplex::simplicityhl::elements::encode::deserialize(
                &hex::decode(raw.as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let output = transaction.output[vout as usize].clone();
            if output.asset.explicit() == Some(app.state.network.policy_asset())
                && output.value.explicit().is_some_and(|value| value > 15_000)
            {
                source = Some((txid, vout, output));
                break;
            }
        }
        let (txid, vout, source) =
            source.expect("bootstrap needs a confirmed explicit policy-asset output");
        let address = rpc(
            &holder,
            "getnewaddress",
            serde_json::json!(["escrow-verification", "bech32"]),
        )
        .await
        .unwrap();
        let info = rpc(&holder, "getaddressinfo", serde_json::json!([address]))
            .await
            .unwrap();
        let payout = parse_script(info["scriptPubKey"].as_str().unwrap(), "holder").unwrap();
        let id = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
        let account = price::account(&app.state, crate::tests::HOLDER_PUBLIC_KEY)
            .await
            .unwrap();
        let mut terms = super::super::tests::price_terms();
        terms.tick_asset_id = account.tick_asset_id;
        terms.verifier_asset_id = account.oracle_verifier_asset_id;
        terms.storm_eye_asset_id = account.storm_eye_asset_id;
        app.state
            .db
            .insert(&Prediction {
                id: id.clone(),
                title: "Live escrow verification".into(),
                created_at: unix_time().unwrap(),
                deadline: unix_time().unwrap() + 3600,
                price: terms,
            })
            .await
            .unwrap();
        let parameters = || DeriveContractRequest {
            payout_script_pubkey: hex::encode(payout.as_bytes()),
            owner_public_key: Some(crate::tests::HOLDER_PUBLIC_KEY.into()),
        };
        let derived = derive_contract(
            State(app.state.clone()),
            AxumPath(id.clone()),
            Json(parameters()),
        )
        .await
        .unwrap()
        .0;
        let mut pset = Pset::new_v2();
        pset.add_input(Input {
            previous_txid: txid,
            previous_output_index: vout,
            witness_utxo: Some(source.clone()),
            sighash_type: Some(EcdsaSighashType::All.into()),
            ..Input::default()
        });
        let policy = app.state.network.policy_asset();
        for (script, amount) in [
            (
                parse_script(&derived.script_pubkey, "position").unwrap(),
                1000,
            ),
            (payout.clone(), 10_000),
            (payout.clone(), source.value.explicit().unwrap() - 12_000),
            (Script::new(), 1000),
        ] {
            pset.add_output(Output::new_explicit(script, amount, policy, None));
        }
        let funding = prepare(
            State(app.state.clone()),
            AxumPath(id.clone()),
            Json(PrepareRequest {
                pset: pset.to_string(),
                stake_sats: 1000,
                contract: parameters(),
            }),
        )
        .await
        .unwrap()
        .0;
        let expected_host_change = parse_pset(&funding.pset)
            .unwrap()
            .outputs()
            .last()
            .unwrap()
            .amount;
        let signed = rpc(
            &holder,
            "walletprocesspsbt",
            serde_json::json!([funding.pset, true, "ALL", true, false]),
        )
        .await
        .unwrap();
        let result = commit(
            State(app.state.clone()),
            AxumPath(id),
            Json(CommitRequest {
                funding_id: funding.funding_id,
                pset: signed["psbt"].as_str().unwrap().to_owned(),
            }),
        )
        .await
        .unwrap()
        .0;
        let raw = rpc(
            &app.state,
            "getrawtransaction",
            serde_json::json!([result.txid]),
        )
        .await
        .unwrap();
        let transaction: Transaction = simplex::simplicityhl::elements::encode::deserialize(
            &hex::decode(raw.as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(transaction.input.len(), 2);
        assert_eq!(transaction.output[0].value.explicit(), Some(2000));
        assert_eq!(
            transaction.output.last().unwrap().value.explicit(),
            expected_host_change
        );
    }
}
