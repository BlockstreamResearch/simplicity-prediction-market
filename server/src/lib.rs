use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{OriginalUri, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    routing::{delete, get, post},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simplex::program::ProgramTrait;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{
    AssetId, BlockHash, EcdsaSighashType, OutPoint, Script, Transaction, TxOut, TxOutSecrets,
    TxOutWitness, Txid,
    bitcoin::PublicKey as BitcoinPublicKey,
    confidential::{Asset, Nonce, Value},
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    secp256k1_zkp::{Secp256k1 as ZkpSecp256k1, rand::thread_rng},
};
use simplex::simplicityhl::simplicity::hashes::Hash as _;
use simplex::simplicityhl::str::WitnessName;
use simplex::simplicityhl::types::TypeInner;
use simplex::simplicityhl::value::{UIntValue, ValueConstructible};
use simplex::simplicityhl::{Value as SimplicityValue, WitnessValues};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};
use simplex::utils::hash_script;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use prediction_demo_contracts::{
    PredictionContract, PredictionParameters, PredictionPayoutProofs, PredictionSpend,
};
use price_oracle_contracts::artifacts::voucher::VoucherProgram;
use price_oracle_contracts::voucher::{
    Voucher, VoucherAuthMethod, VoucherParameters, VoucherSpendPath,
};

const SESSION_BYTES: usize = 32;
mod escrow;
mod price;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub listen_address: SocketAddr,
    pub data_file: PathBuf,
    pub admin_login: String,
    pub admin_password: String,
    pub admin_private_key: String,
    pub policy_asset_id: String,
    pub genesis_block_hash: String,
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_seconds: u64,
    #[serde(default)]
    pub chain_backend: ChainBackendConfig,
    #[serde(default = "price::default_oracle_url")]
    pub oracle_url: String,
    #[serde(default)]
    pub escrow: Option<escrow::EscrowConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct ChainBackendConfig {
    pub esplora_url: String,
    pub rpc_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
}

impl Default for ChainBackendConfig {
    fn default() -> Self {
        Self {
            esplora_url: "http://127.0.0.1:3001".into(),
            rpc_url: "http://127.0.0.1:18884".into(),
            rpc_username: "high-storm".into(),
            rpc_password: "high-storm".into(),
        }
    }
}

fn default_session_lifetime() -> u64 {
    3_600
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self, AppError> {
        let contents = tokio::fs::read_to_string(path).await?;
        Ok(toml::from_str(&contents)?)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Resolution {
    pub occurred_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Prediction {
    pub id: String,
    pub title: String,
    pub deadline: u64,
    pub created_at: u64,
    pub resolution: Option<Resolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<price::PriceMarket>,
}

#[derive(Default)]
struct Store {
    predictions: Vec<Prediction>,
    sessions: HashMap<String, u64>,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    network: SimplicityNetwork,
    keypair: Keypair,
    admin_public_key: String,
    store: Arc<RwLock<Store>>,
    chain_client: reqwest::Client,
    escrows: escrow::Proposals,
    reserve_wallet: Option<escrow::LocalWallet>,
}

impl AppState {
    fn oracle_network(&self) -> &'static str {
        let testnet = SimplicityNetwork::LiquidTestnet;
        if self.network.policy_asset() == testnet.policy_asset()
            && self.network.genesis_block_hash() == testnet.genesis_block_hash()
        {
            "liquidtestnet"
        } else {
            "elementsregtest"
        }
    }
}

pub struct App {
    state: AppState,
}

impl App {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        let policy_asset = config
            .policy_asset_id
            .parse::<AssetId>()
            .map_err(|_| AppError::InvalidPolicyAsset)?;
        let genesis_hash = config
            .genesis_block_hash
            .parse::<BlockHash>()
            .map_err(|_| AppError::InvalidGenesisHash)?;
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset,
            genesis_hash,
        };
        let key_bytes: [u8; 32] = hex::decode(&config.admin_private_key)
            .map_err(|_| AppError::InvalidAdminKey)?
            .try_into()
            .map_err(|_| AppError::InvalidAdminKey)?;
        let secret_key = SecretKey::from_byte_array(key_bytes)?;
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret_key);
        let admin_public_key = hex::encode(keypair.x_only_public_key().0.serialize());
        let reserve_wallet = if let Some(escrow) = &config.escrow {
            if let Some(path) = &escrow.private_key_file {
                if !escrow.wallet.is_empty() {
                    return Err(AppError::InvalidEscrowKey);
                }
                Some(escrow::LocalWallet::load(path, network, &key_bytes).await?)
            } else {
                None
            }
        } else {
            None
        };
        let predictions = match tokio::fs::read(&config.data_file).await {
            Ok(data) => serde_json::from_slice(&data)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };

        Ok(Self {
            state: AppState {
                config,
                network,
                keypair,
                admin_public_key,
                escrows: Arc::default(),
                reserve_wallet,
                chain_client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(15))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?,
                store: Arc::new(RwLock::new(Store {
                    predictions,
                    sessions: HashMap::new(),
                })),
            },
        })
    }

    #[must_use]
    pub fn listen_address(&self) -> SocketAddr {
        self.state.config.listen_address
    }

    #[must_use]
    pub fn router(&self) -> Router {
        Router::new()
            .route("/api/config", get(public_config))
            .route("/api/chain/tx", post(broadcast_transaction))
            .route("/api/chain/{*path}", get(read_chain))
            .route("/api/predictions", get(list_predictions))
            .route("/api/prices", get(price::feeds))
            .route("/api/prices/{id}", get(price::feed))
            .route("/api/predictions/{id}/claim", post(price::claim))
            .route("/api/predictions/{id}/sweep", post(price::sweep))
            .route("/api/predictions/{id}/contract", post(derive_contract))
            .route("/api/predictions/{id}/escrow", post(escrow::prepare))
            .route("/api/predictions/{id}/escrow/commit", post(escrow::commit))
            .route(
                "/api/predictions/{id}/escrow/{funding_id}",
                delete(escrow::cancel),
            )
            .route(
                "/api/predictions/{id}/redemption",
                post(assemble_redemption),
            )
            .route("/api/predictions/{id}/resolution", get(get_resolution))
            .route("/api/admin/login", post(login))
            .route("/api/admin/escrow", get(escrow::status))
            .route("/api/admin/predictions", post(create_prediction))
            .route(
                "/api/admin/predictions/{id}/resolve",
                post(resolve_prediction),
            )
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_headers(Any)
                    .allow_methods(Any),
            )
            .with_state(self.state.clone())
    }
}

#[derive(Serialize)]
struct PublicConfig {
    admin_public_key: String,
    policy_asset_id: String,
    genesis_block_hash: String,
    network: &'static str,
    oracle_url: String,
    matched_escrow_enabled: bool,
}

async fn public_config(State(state): State<AppState>) -> Json<PublicConfig> {
    let network = state.oracle_network();
    let matched_escrow_enabled = state.config.escrow.is_some()
        && (state.reserve_wallet.is_some() || network == "elementsregtest");

    Json(PublicConfig {
        admin_public_key: state.admin_public_key,
        policy_asset_id: state.config.policy_asset_id,
        genesis_block_hash: state.config.genesis_block_hash,
        network,
        oracle_url: state.config.oracle_url,
        matched_escrow_enabled,
    })
}

async fn read_chain(
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
    OriginalUri(uri): OriginalUri,
) -> Result<(StatusCode, axum::body::Bytes), ApiError> {
    if path.split('/').any(|part| part == "." || part == "..") || path.contains(['\\', '?', '#']) {
        return Err(ApiError::bad_request("invalid chain lookup path"));
    }
    let mut url = reqwest::Url::parse(&state.config.chain_backend.esplora_url)
        .map_err(|_| ApiError::internal("invalid chain index configuration"))?;
    url.set_path(&format!("{}/{}", url.path().trim_end_matches('/'), path));
    url.set_query(uri.query());
    let response = state
        .chain_client
        .get(url)
        .send()
        .await
        .map_err(|_| ApiError::internal("chain index unavailable"))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|_| ApiError::internal("chain index response failed"))?;
    Ok((status, body))
}

fn tick_burn_allowance(outputs: &[TxOut], policy_asset: AssetId) -> Result<u64, ApiError> {
    let mut allowance = 0u64;
    let mut tags = Vec::new();
    for output in outputs
        .iter()
        .filter(|output| !output.is_fee() && output.script_pubkey.is_provably_unspendable())
    {
        let amount = output
            .value
            .explicit()
            .ok_or_else(|| ApiError::bad_request("burn amount must be explicit"))?;
        if amount == 0 {
            continue;
        }
        let tag = if output.script_pubkey == Voucher::get_burn_script(1) {
            1
        } else if output.script_pubkey == Voucher::get_burn_script(2) {
            2
        } else {
            0
        };
        if output.asset.explicit().is_none()
            || output.asset.explicit() == Some(policy_asset)
            || tag == 0
            || tags.contains(&tag)
            || amount > u64::from(u32::MAX)
        {
            return Err(ApiError::bad_request(
                "only bounded, uniquely tagged non-LBTC voucher burns are allowed",
            ));
        }
        tags.push(tag);
        allowance = allowance
            .checked_add(amount)
            .ok_or_else(|| ApiError::bad_request("voucher burn allowance overflows"))?;
    }
    Ok(allowance)
}

fn voucher_burn_allowance(
    outputs: &[TxOut],
    policy: AssetId,
    tick: AssetId,
    verifier: AssetId,
) -> Result<u64, ApiError> {
    let allowance = tick_burn_allowance(outputs, policy)?;
    let mut assets = Vec::new();
    for output in outputs.iter().filter(|output| {
        !output.is_fee()
            && output.script_pubkey.is_provably_unspendable()
            && output.value.explicit() != Some(0)
    }) {
        let asset = output.asset.explicit();
        if assets.contains(&asset)
            || (asset != Some(tick)
                && !(asset == Some(verifier) && output.value.explicit() == Some(1)))
            || (output.script_pubkey == Voucher::get_burn_script(2) && asset != Some(tick))
        {
            return Err(ApiError::bad_request(
                "burn must be a deployed Tick or a one-unit Oracle Verifier",
            ));
        }
        assets.push(asset);
    }
    if assets.len() == 2 {
        let tick_output = outputs
            .iter()
            .find(|output| {
                output.asset.explicit() == Some(tick)
                    && output.script_pubkey.is_provably_unspendable()
            })
            .expect("checked Tick burn");
        if tick_output.script_pubkey != Voucher::get_burn_script(2) {
            return Err(ApiError::bad_request("paired Tick burn must tag input 2"));
        }
    } else if outputs.iter().any(|output| {
        output.script_pubkey == Voucher::get_burn_script(2) && output.value.explicit() != Some(0)
    }) {
        return Err(ApiError::bad_request(
            "input 2 burn requires a paired Verifier burn",
        ));
    }
    Ok(allowance)
}

async fn broadcast_transaction(
    State(state): State<AppState>,
    body: String,
) -> Result<String, ApiError> {
    let tx_hex = body.trim();
    let bytes =
        hex::decode(tx_hex).map_err(|_| ApiError::bad_request("invalid transaction hex"))?;
    let tx: Transaction = simplex::simplicityhl::elements::encode::deserialize(&bytes)
        .map_err(|_| ApiError::bad_request("invalid Elements transaction"))?;
    let mut burn = tick_burn_allowance(&tx.output, state.network.policy_asset())?;
    if burn > 0 {
        let account = price::account(&state, &state.admin_public_key).await?;
        burn = voucher_burn_allowance(
            &tx.output,
            state.network.policy_asset(),
            parse_asset(&account.tick_asset_id, "Tick asset")?,
            parse_asset(&account.oracle_verifier_asset_id, "Verifier asset")?,
        )?;
    }
    let backend = &state.config.chain_backend;
    if backend.rpc_url.is_empty() {
        if burn > 0 {
            return Err(ApiError::conflict(
                "voucher settlements require an Elements RPC on the configured chain",
            ));
        }
        let response = state
            .chain_client
            .post(format!("{}/tx", backend.esplora_url.trim_end_matches('/')))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(tx_hex.to_owned())
            .send()
            .await
            .map_err(|_| ApiError::internal("chain broadcaster unavailable"))?;
        let status = response.status();
        let result = response
            .text()
            .await
            .map_err(|_| ApiError::internal("invalid broadcaster response"))?;
        if !status.is_success() {
            return Err(ApiError::bad_request(result));
        }
        let txid = result
            .trim()
            .parse::<Txid>()
            .map_err(|_| ApiError::internal("broadcaster returned no transaction ID"))?;
        if txid != tx.txid() {
            return Err(ApiError::internal(
                "broadcaster returned a different transaction ID",
            ));
        }
        return Ok(txid.to_string());
    }

    let mut params = vec![
        serde_json::json!(tx_hex),
        serde_json::json!(0.1),
        serde_json::json!(burn as f64 / 100_000_000.0),
    ];
    let response = loop {
        let response: serde_json::Value = state
            .chain_client
            .post(&backend.rpc_url)
            .basic_auth(&backend.rpc_username, Some(&backend.rpc_password))
            .json(&serde_json::json!({
                "jsonrpc": "1.0", "id": "prediction-broadcast", "method": "sendrawtransaction",
                "params": params,
            }))
            .send()
            .await
            .map_err(|_| ApiError::internal("chain broadcaster unavailable"))?
            .json()
            .await
            .map_err(|_| ApiError::internal("invalid broadcaster response"))?;
        if params.len() == 3
            && response["error"]["code"] == -1
            && response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("sendrawtransaction "))
        {
            params.pop();
            continue;
        }
        break response;
    };
    if !response["error"].is_null() {
        return Err(ApiError::bad_request(
            response["error"]["message"]
                .as_str()
                .unwrap_or("transaction rejected"),
        ));
    }
    response["result"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::internal("broadcaster returned no transaction ID"))
}

async fn list_predictions(State(state): State<AppState>) -> Json<Vec<Prediction>> {
    Json(state.store.read().await.predictions.clone())
}

async fn get_resolution(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Resolution>, ApiError> {
    let store = state.store.read().await;
    let prediction = store
        .predictions
        .iter()
        .find(|prediction| prediction.id == id)
        .ok_or_else(|| ApiError::not_found("prediction does not exist"))?;
    prediction
        .resolution
        .clone()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("prediction has not been resolved"))
}

#[derive(Deserialize)]
struct DeriveContractRequest {
    payout_script_pubkey: String,
    tick_asset_id: String,
    tick_script_pubkey: String,
    #[serde(default)]
    confidential_payout: bool,
    owner_public_key: Option<String>,
}

#[derive(Serialize)]
struct DerivedContract {
    script_pubkey: String,
    tick_asset_id: String,
    tick_script_pubkey: String,
    confidential_payout: bool,
}

async fn derive_contract(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<DeriveContractRequest>,
) -> Result<Json<DerivedContract>, ApiError> {
    let prediction_id = parse_prediction_id(&id)?;
    let prediction = state
        .store
        .read()
        .await
        .predictions
        .iter()
        .find(|prediction| prediction.id == id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("prediction does not exist"))?;
    if prediction.price.is_some() {
        return price::derive(&state, &prediction, &request).await;
    }
    let admin_pubkey = state.keypair.x_only_public_key().0.serialize();
    let tick_asset_id = parse_asset(&request.tick_asset_id, "Tick asset ID")?;
    let tick_script = parse_script(&request.tick_script_pubkey, "Tick script")?;
    let payout_script = parse_script(&request.payout_script_pubkey, "payout script")?;
    let parameters = PredictionParameters {
        prediction_id,
        admin_pubkey,
        deadline: prediction.deadline,
        tick_asset_id,
        tick_script_hash: hash_script(&tick_script),
        payout_script_hash: hash_script(&payout_script),
        network: state.network,
    };
    let contract = if request.confidential_payout {
        PredictionContract::new_confidential(parameters)
    } else {
        PredictionContract::new(parameters)
    };

    Ok(Json(DerivedContract {
        script_pubkey: hex::encode(contract.get_script_pubkey().into_bytes()),
        tick_asset_id: request.tick_asset_id,
        tick_script_pubkey: request.tick_script_pubkey,
        confidential_payout: request.confidential_payout,
    }))
}

fn parse_script(value: &str, name: &str) -> Result<Script, ApiError> {
    let bytes =
        hex::decode(value).map_err(|_| ApiError::bad_request(format!("{name} must be hex")))?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request(format!("{name} must not be empty")));
    }

    Ok(Script::from(bytes))
}

#[derive(Clone, Deserialize)]
struct ExplicitUtxo {
    txid: String,
    vout: u32,
    script_pubkey: String,
    amount_sats: u64,
    asset: String,
}

#[derive(Deserialize)]
struct RedemptionRequest {
    position: ExplicitUtxo,
    tick: ExplicitUtxo,
    fee: ExplicitUtxo,
    payout_script_pubkey: String,
    owner_public_key: String,
    storm_eye_asset_id: String,
    tick_signature: Option<String>,
    tick_auth_script_pubkey: Option<String>,
    payout_blinding_key: Option<String>,
}

#[derive(Serialize)]
struct RedemptionResponse {
    tick_signature_hash: String,
    pset: Option<String>,
}

async fn assemble_redemption(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<RedemptionRequest>,
) -> Result<Json<RedemptionResponse>, ApiError> {
    let prediction_id = parse_prediction_id(&id)?;
    let prediction = state
        .store
        .read()
        .await
        .predictions
        .iter()
        .find(|prediction| prediction.id == id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("prediction does not exist"))?;
    let resolution = prediction
        .resolution
        .ok_or_else(|| ApiError::conflict("prediction has not been resolved"))?;
    let network = state.network;
    let payout_script = parse_script(&request.payout_script_pubkey, "payout script")?;
    let storm_eye_asset_id = parse_asset(&request.storm_eye_asset_id, "Storm Eye asset ID")?;
    let owner_public_key = parse_hex_array::<32>(&request.owner_public_key, "owner public key")?;
    let admin_signature = parse_hex_array::<64>(&resolution.signature, "admin signature")?;
    let position_utxo = parse_utxo(&request.position, "position")?;
    let tick_utxo = parse_utxo(&request.tick, "Tick")?;
    let fee_utxo = parse_utxo(&request.fee, "fee")?;
    let tick_asset_id = tick_utxo.explicit_asset();
    if request.tick.amount_sats < resolution.occurred_at {
        return Err(ApiError::bad_request(
            "Tick timestamp predates the signed occurrence",
        ));
    }
    if fee_utxo.explicit_asset() != position_utxo.explicit_asset()
        || request.fee.amount_sats <= 1_000
    {
        return Err(ApiError::bad_request(
            "fee UTXO must fund at least 1,001 sats of the position asset",
        ));
    }

    let parameters = || PredictionParameters {
        prediction_id,
        admin_pubkey: state.keypair.x_only_public_key().0.serialize(),
        deadline: prediction.deadline,
        tick_asset_id,
        tick_script_hash: hash_script(&tick_utxo.txout.script_pubkey),
        payout_script_hash: hash_script(&payout_script),
        network,
    };
    let confidential_contract = PredictionContract::new_confidential(parameters());
    let confidential_payout =
        confidential_contract.get_script_pubkey() == position_utxo.txout.script_pubkey;
    let prediction_contract = if confidential_payout {
        confidential_contract
    } else {
        PredictionContract::new(parameters())
    };
    if prediction_contract.get_script_pubkey() != position_utxo.txout.script_pubkey {
        return Err(ApiError::bad_request(
            "position UTXO does not match the compiled prediction contract",
        ));
    }
    let auth_script = request
        .tick_auth_script_pubkey
        .as_deref()
        .map(|value| parse_script(value, "Tick authorization script"))
        .transpose()?;
    if confidential_payout && auth_script.is_none() {
        return Err(ApiError::bad_request(
            "confidential redemption requires a script-authorized Tick",
        ));
    }
    if let Some(auth_script) = &auth_script {
        if auth_script != &fee_utxo.txout.script_pubkey || auth_script != &payout_script {
            return Err(ApiError::bad_request(
                "Tick authorization must match the wallet fee input and payout script",
            ));
        }
    }
    let voucher_parameters = VoucherParameters {
        storm_eye_asset_id,
        auth_method: match &auth_script {
            Some(script) => VoucherAuthMethod::Script {
                auth_script_hash: hash_script(script),
            },
            None => VoucherAuthMethod::Signature {
                auth_pubkey: owner_public_key,
            },
        },
        network,
    };
    let voucher_program = VoucherProgram::new(&voucher_parameters.build_arguments());
    if voucher_program.get_script_pubkey(&network) != tick_utxo.txout.script_pubkey {
        return Err(ApiError::bad_request(
            "Tick UTXO does not match its authorization covenant",
        ));
    }

    let tick_signature = request
        .tick_signature
        .as_deref()
        .map(|value| parse_hex_array::<64>(value, "Tick signature"))
        .transpose()?;
    let tick_spend_path = match auth_script {
        Some(_) => VoucherSpendPath::ScriptAuth {
            auth_input_index: 2,
            voucher_output_index: 1,
        },
        None => VoucherSpendPath::SignatureAuth {
            voucher_output_index: 1,
        },
    };
    let mut transaction = FinalTransaction::new();
    let spend = || PredictionSpend {
        occurred_at: resolution.occurred_at,
        admin_signature,
        tick_input_index: 1,
        payout_output_index: 0,
    };
    prediction_contract.attach_spend(&mut transaction, &position_utxo, spend());
    transaction.add_program_input(
        PartialInput::new(tick_utxo.clone()),
        ProgramInput::new(
            Box::new(voucher_program.as_ref().clone()),
            Box::new(tick_spend_path.build_witness()),
        ),
        tick_spend_path.required_signature(),
    );
    transaction.add_input(
        PartialInput::new(fee_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );
    transaction.add_output(PartialOutput::new(
        payout_script.clone(),
        position_utxo.explicit_amount(),
        position_utxo.explicit_asset(),
    ));
    transaction.add_output(PartialOutput::new(
        Voucher::get_burn_script(1),
        tick_utxo.explicit_amount(),
        tick_utxo.explicit_asset(),
    ));
    transaction.add_output(PartialOutput::new(
        payout_script,
        request.fee.amount_sats - 1_000,
        position_utxo.explicit_asset(),
    ));
    transaction.add_output(PartialOutput::new(
        Script::new(),
        1_000,
        position_utxo.explicit_asset(),
    ));

    let (mut pset, _) = transaction.extract_pst();
    if confidential_payout {
        let blinding_key = request
            .payout_blinding_key
            .as_deref()
            .ok_or_else(|| {
                ApiError::bad_request("confidential payout requires a wallet blinding public key")
            })?
            .parse::<BitcoinPublicKey>()
            .map_err(|_| ApiError::bad_request("invalid payout blinding public key"))?;
        if !blinding_key.compressed {
            return Err(ApiError::bad_request(
                "payout blinding public key must be compressed",
            ));
        }
        let secp = ZkpSecp256k1::new();
        let mut rng = thread_rng();
        let secrets = HashMap::from([(
            2,
            TxOutSecrets {
                asset: fee_utxo.explicit_asset(),
                asset_bf: AssetBlindingFactor::zero(),
                value: fee_utxo.explicit_amount(),
                value_bf: ValueBlindingFactor::zero(),
            },
        )]);
        pset.outputs_mut()[0].blinding_key = Some(blinding_key);
        pset.outputs_mut()[0].blinder_index = Some(2);
        let factors = pset
            .blind_non_last(&mut rng, &secp, &secrets)
            .map_err(|error| ApiError::bad_request(format!("payout blinding: {error}")))?;
        let (abf, vbf) = factors[0];
        pset.outputs_mut()[0].blinder_index = None;
        pset.outputs_mut()[2].blinding_key = Some(blinding_key);
        pset.outputs_mut()[2].blinder_index = Some(2);
        pset.blind_last(&mut rng, &secp, &secrets)
            .map_err(|error| ApiError::bad_request(format!("fee change blinding: {error}")))?;
        for index in [0, 2] {
            pset.outputs_mut()[index].blinder_index = Some(0);
        }
        let proofs = PredictionPayoutProofs::new(prediction_id, resolution.occurred_at, abf, vbf)
            .map_err(|error| {
            ApiError::bad_request(format!("payout commitment proof: {error}"))
        })?;
        let mut confidential_spend = FinalTransaction::new();
        prediction_contract.attach_confidential_spend(
            &mut confidential_spend,
            &position_utxo,
            spend(),
            proofs,
        );
        transaction.inputs_mut()[0].program_input =
            confidential_spend.inputs()[0].program_input.clone();
    }
    let tick_hash = voucher_program
        .as_ref()
        .get_env(&pset, 1, &network)
        .map_err(|error| ApiError::bad_request(error.to_string()))?
        .c_tx_env()
        .sighash_all()
        .to_byte_array();
    if request.tick_signature.is_none() && request.tick_auth_script_pubkey.is_none() {
        return Ok(Json(RedemptionResponse {
            tick_signature_hash: hex::encode(tick_hash),
            pset: None,
        }));
    }

    for index in 0..2 {
        let program_input = transaction.inputs()[index]
            .program_input
            .as_ref()
            .expect("both covenant inputs have programs");
        let witness = if index == 1 && request.tick_auth_script_pubkey.is_none() {
            build_signed_voucher_witness(
                voucher_program.as_ref(),
                tick_signature.expect("checked above"),
                1,
            )?
        } else {
            program_input.witness.build_witness()
        };
        let finalized = program_input
            .program
            .finalize(&pset, &witness, index, &network)
            .map_err(|error| ApiError::bad_request(format!("covenant input {index}: {error}")))?;
        pset.inputs_mut()[index].final_script_witness = Some(finalized);
    }
    for input in pset.inputs_mut() {
        input.amount = None;
        input.asset = None;
    }
    pset.inputs_mut()[2].sighash_type = Some(EcdsaSighashType::All.into());

    Ok(Json(RedemptionResponse {
        tick_signature_hash: hex::encode(tick_hash),
        pset: Some(pset.to_string()),
    }))
}

fn build_signed_voucher_witness(
    program: &dyn ProgramTrait,
    signature: [u8; 64],
    voucher_output_index: u32,
) -> Result<WitnessValues, ApiError> {
    let witness_name = WitnessName::from_str_unchecked("PATH");
    let witness_types = program
        .get_witness_types()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let witness_type = witness_types
        .get(&witness_name)
        .ok_or_else(|| ApiError::bad_request("Voucher PATH witness is missing"))?;
    let TypeInner::Either(other_auth_type, signature_or_network_type) = witness_type.as_inner()
    else {
        return Err(ApiError::bad_request(
            "Voucher PATH witness has an invalid type",
        ));
    };
    let TypeInner::Either(_, network_auth_type) = signature_or_network_type.as_inner() else {
        return Err(ApiError::bad_request(
            "Voucher signature witness has an invalid type",
        ));
    };

    let signature_path = SimplicityValue::tuple([
        SimplicityValue::byte_array(signature),
        SimplicityValue::from(UIntValue::U32(voucher_output_index)),
    ]);
    let signature_or_network = SimplicityValue::left(signature_path, (**network_auth_type).clone());
    let signed_path = SimplicityValue::right((**other_auth_type).clone(), signature_or_network);
    if signed_path.ty() != witness_type {
        return Err(ApiError::bad_request(
            "Voucher signature does not match the PATH witness type",
        ));
    }

    Ok(WitnessValues::from(HashMap::from([(
        witness_name,
        signed_path,
    )])))
}

fn parse_asset(value: &str, name: &str) -> Result<AssetId, ApiError> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request(format!("{name} is invalid")))
}

fn parse_utxo(value: &ExplicitUtxo, name: &str) -> Result<UTXO, ApiError> {
    let txid = value
        .txid
        .parse::<Txid>()
        .map_err(|_| ApiError::bad_request(format!("{name} txid is invalid")))?;
    let script_pubkey = parse_script(&value.script_pubkey, &format!("{name} script"))?;
    let asset = parse_asset(&value.asset, &format!("{name} asset"))?;

    Ok(UTXO {
        outpoint: OutPoint::new(txid, value.vout),
        txout: TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(value.amount_sats),
            nonce: Nonce::Null,
            script_pubkey,
            witness: TxOutWitness::default(),
        },
        secrets: None,
    })
}

fn parse_hex_array<const LENGTH: usize>(value: &str, name: &str) -> Result<[u8; LENGTH], ApiError> {
    hex::decode(value)
        .map_err(|_| ApiError::bad_request(format!("{name} must be hex")))?
        .try_into()
        .map_err(|_| ApiError::bad_request(format!("{name} must be {LENGTH} bytes")))
}

#[derive(Deserialize)]
struct LoginRequest {
    login: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: u64,
}

async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    if !constant_time_equal(&request.login, &state.config.admin_login)
        || !constant_time_equal(&request.password, &state.config.admin_password)
    {
        return Err(ApiError::unauthorized("invalid login or password"));
    }

    let now = unix_time()?;
    let expires_at = now.saturating_add(state.config.session_lifetime_seconds);
    let token = random_token();
    state
        .store
        .write()
        .await
        .sessions
        .insert(token.clone(), expires_at);

    Ok(Json(LoginResponse { token, expires_at }))
}

#[derive(Deserialize)]
struct CreatePrediction {
    title: String,
    deadline: u64,
    price: Option<price::PriceMarketRequest>,
}

async fn create_prediction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePrediction>,
) -> Result<(StatusCode, Json<Prediction>), ApiError> {
    authenticate(&state, &headers).await?;
    let title = request.title.trim();
    if title.is_empty() || title.len() > 240 {
        return Err(ApiError::bad_request(
            "prediction title must contain 1 to 240 characters",
        ));
    }
    let now = unix_time()?;
    if request.deadline <= now {
        return Err(ApiError::bad_request("deadline must be in the future"));
    }
    let price = match request.price {
        Some(price) => Some(price::publish(&state, price, request.deadline).await?),
        None => None,
    };

    let id = prediction_id(title, request.deadline, Uuid::new_v4());
    let prediction = Prediction {
        id,
        title: title.to_string(),
        deadline: request.deadline,
        created_at: now,
        resolution: None,
        price,
    };
    {
        let mut store = state.store.write().await;
        store.predictions.push(prediction.clone());
        persist(&state.config.data_file, &store.predictions).await?;
    }

    Ok((StatusCode::CREATED, Json(prediction)))
}

#[derive(Deserialize)]
struct ResolvePrediction {
    occurred_at: u64,
}

async fn resolve_prediction(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ResolvePrediction>,
) -> Result<Json<Resolution>, ApiError> {
    authenticate(&state, &headers).await?;
    let prediction_id = parse_prediction_id(&id)?;
    let message = resolution_digest(prediction_id, request.occurred_at);
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(&message, &state.keypair);
    let resolution = Resolution {
        occurred_at: request.occurred_at,
        signature: signature.to_string(),
    };

    {
        let mut store = state.store.write().await;
        let prediction = store
            .predictions
            .iter_mut()
            .find(|prediction| prediction.id == id)
            .ok_or_else(|| ApiError::not_found("prediction does not exist"))?;
        if prediction.price.is_some() {
            return Err(ApiError::bad_request(
                "price markets resolve through the oracle, not the admin",
            ));
        }
        if request.occurred_at > prediction.deadline {
            return Err(ApiError::bad_request(
                "occurrence time is after the prediction deadline",
            ));
        }
        if prediction.resolution.is_some() {
            return Err(ApiError::conflict("prediction is already resolved"));
        }
        prediction.resolution = Some(resolution.clone());
        persist(&state.config.data_file, &store.predictions).await?;
    }

    Ok(Json(resolution))
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing admin token"))?;
    let now = unix_time()?;
    let mut store = state.store.write().await;
    store.sessions.retain(|_, expires_at| *expires_at > now);
    if store.sessions.contains_key(token) {
        Ok(())
    } else {
        Err(ApiError::unauthorized("admin token is invalid or expired"))
    }
}

async fn persist(path: &Path, predictions: &[Prediction]) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(predictions)?).await?;
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

fn prediction_id(title: &str, deadline: u64, nonce: Uuid) -> String {
    let mut hash = Sha256::new();
    hash.update(title.as_bytes());
    hash.update(deadline.to_be_bytes());
    hash.update(nonce.as_bytes());
    hex::encode(hash.finalize())
}

fn parse_prediction_id(id: &str) -> Result<[u8; 32], ApiError> {
    hex::decode(id)
        .map_err(|_| ApiError::bad_request("invalid prediction id"))?
        .try_into()
        .map_err(|_| ApiError::bad_request("invalid prediction id"))
}

#[must_use]
pub fn resolution_digest(prediction_id: [u8; 32], occurred_at: u64) -> [u8; 32] {
    let mut occurred_at_bytes = [0u8; 32];
    occurred_at_bytes[24..].copy_from_slice(&occurred_at.to_be_bytes());
    let mut hash = Sha256::new();
    hash.update(prediction_id);
    hash.update(occurred_at_bytes);
    hash.finalize().into()
}

fn random_token() -> String {
    let mut bytes = [0u8; SESSION_BYTES];
    secp256k1::rand::fill(&mut bytes);
    hex::encode(bytes)
}

fn constant_time_equal(actual: &str, expected: &str) -> bool {
    let actual_hash = Sha256::digest(actual.as_bytes());
    let expected_hash = Sha256::digest(expected.as_bytes());
    bool::from(actual_hash.ct_eq(&expected_hash))
}

fn unix_time() -> Result<u64, ApiError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system clock is before Unix epoch"))?
        .as_secs())
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error("admin_private_key must be a valid 32-byte secp256k1 secret key")]
    InvalidAdminKey,
    #[error(
        "escrow private key file must contain a valid separate 32-byte secret key; choose either a local key file or a node wallet"
    )]
    InvalidEscrowKey,
    #[error("policy_asset_id must be a valid Elements asset ID")]
    InvalidPolicyAsset,
    #[error("genesis_block_hash must be a valid Elements block hash")]
    InvalidGenesisHash,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<std::time::SystemTimeError> for ApiError {
    fn from(error: std::time::SystemTimeError) -> Self {
        Self::internal(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use secp256k1::{Secp256k1, schnorr::Signature};
    use tower::ServiceExt;

    use super::*;

    pub(super) fn config(data_file: PathBuf) -> Config {
        Config {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            data_file,
            admin_login: "oracle-admin".into(),
            admin_password: "test-password".into(),
            admin_private_key: "11".repeat(32),
            policy_asset_id: "66".repeat(32),
            genesis_block_hash: "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f"
                .into(),
            session_lifetime_seconds: 60,
            chain_backend: ChainBackendConfig::default(),
            oracle_url: price::default_oracle_url(),
            escrow: None,
        }
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn public_config_exposes_chain_identity_without_credentials() {
        let temp = std::env::temp_dir().join(format!("prediction-demo-{}.json", Uuid::new_v4()));
        let app = App::new(config(temp)).await.unwrap();
        let response = app
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await,
            serde_json::json!({
                "admin_public_key": app.state.admin_public_key,
                "policy_asset_id": app.state.config.policy_asset_id,
                "genesis_block_hash": app.state.config.genesis_block_hash,
                "network": "elementsregtest",
                "oracle_url": app.state.config.oracle_url,
                "matched_escrow_enabled": false,
            })
        );
    }

    #[test]
    fn broadcast_allows_only_a_bounded_tagged_non_policy_burn() {
        let policy = AssetId::from_str(&"66".repeat(32)).unwrap();
        let tick = AssetId::from_str(&"77".repeat(32)).unwrap();
        let output = TxOut {
            asset: Asset::Explicit(tick),
            value: Value::Explicit(1_790_000_000),
            nonce: Nonce::Null,
            script_pubkey: Voucher::get_burn_script(1),
            witness: TxOutWitness::default(),
        };
        assert_eq!(
            tick_burn_allowance(&[output.clone()], policy).unwrap(),
            1_790_000_000
        );
        let mut invalid = output.clone();
        invalid.asset = Asset::Explicit(policy);
        assert!(tick_burn_allowance(&[invalid], policy).is_err());
        let mut invalid = output.clone();
        invalid.script_pubkey = Script::from(vec![0x6a]);
        assert!(tick_burn_allowance(&[invalid], policy).is_err());
        let mut invalid = output.clone();
        invalid.value = Value::Explicit(u64::from(u32::MAX) + 1);
        assert!(tick_burn_allowance(&[invalid], policy).is_err());
        let mut invalid = output.clone();
        invalid.asset = Asset::Explicit(policy);
        invalid.script_pubkey = Script::from(vec![0x51; 10_001]);
        assert!(tick_burn_allowance(&[output.clone(), invalid], policy).is_err());
        let mut fee = output.clone();
        fee.asset = Asset::Explicit(policy);
        fee.script_pubkey = Script::new();
        assert_eq!(
            tick_burn_allowance(&[output.clone(), fee], policy).unwrap(),
            1_790_000_000
        );
        assert!(tick_burn_allowance(&[output.clone(), output], policy).is_err());
        assert_eq!(tick_burn_allowance(&[], policy).unwrap(), 0);
    }

    #[tokio::test]
    async fn rpc_broadcast_supports_elements_23_without_retrying_rejections() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let transaction = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };
        let tx_hex = hex::encode(simplex::simplicityhl::elements::encode::serialize(
            &transaction,
        ));
        for (error, expected_status, expected_calls) in [
            (
                serde_json::json!({"code": -1, "message": "sendrawtransaction \"hexstring\" ( maxfeerate )"}),
                StatusCode::OK,
                2,
            ),
            (serde_json::Value::Null, StatusCode::OK, 1),
            (
                serde_json::json!({"code": -26, "message": "transaction rejected"}),
                StatusCode::BAD_REQUEST,
                1,
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let txid = transaction.txid().to_string();
            let chain = Router::new().route(
                "/",
                post(move |Json(request): Json<serde_json::Value>| {
                    let count = count.clone();
                    let error = error.clone();
                    let txid = txid.clone();
                    async move {
                        assert_eq!(request["method"], "sendrawtransaction");
                        let attempt = count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(
                            request["params"].as_array().unwrap().len(),
                            if attempt == 0 { 3 } else { 2 }
                        );
                        Json(if attempt == 0 && !error.is_null() {
                            serde_json::json!({"result": null, "error": error})
                        } else {
                            serde_json::json!({"result": txid, "error": null})
                        })
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, chain).await.unwrap() });
            let mut config =
                config(std::env::temp_dir().join(format!("rpc-broadcast-{}.json", Uuid::new_v4())));
            config.chain_backend.rpc_url = url;
            let response = App::new(config)
                .await
                .unwrap()
                .router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/chain/tx")
                        .body(Body::from(tx_hex.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), expected_status);
            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
            task.abort();
        }
    }

    #[tokio::test]
    async fn esplora_broadcast_without_rpc_rejects_voucher_burns() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let policy = AssetId::from_str(&"66".repeat(32)).unwrap();
        let transaction = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![TxOut {
                asset: Asset::Explicit(policy),
                value: Value::Explicit(1000),
                nonce: Nonce::Null,
                script_pubkey: Script::new(),
                witness: TxOutWitness::default(),
            }],
        };
        let expected_hex = hex::encode(simplex::simplicityhl::elements::encode::serialize(
            &transaction,
        ));
        let expected_txid = transaction.txid().to_string();
        let broadcasts = Arc::new(AtomicUsize::new(0));
        let count = broadcasts.clone();
        let txid = expected_txid.clone();
        let chain = Router::new()
            .route(
                "/tx",
                post(move |body: String| {
                    let expected_hex = expected_hex.clone();
                    let txid = txid.clone();
                    let count = count.clone();
                    async move {
                        assert_eq!(body, expected_hex);
                        count.fetch_add(1, Ordering::Relaxed);
                        txid
                    }
                }),
            )
            .route(
                "/users/account/{owner}",
                get(|| async {
                    Json(serde_json::json!({
                        "network": "elementsregtest",
                        "tick_asset_id": "77".repeat(32),
                        "oracle_verifier_asset_id": "33".repeat(32),
                        "storm_eye_asset_id": "44".repeat(32),
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, chain).await.unwrap() });
        let mut config =
            config(std::env::temp_dir().join(format!("esplora-broadcast-{}.json", Uuid::new_v4())));
        config.chain_backend.esplora_url = url.clone();
        config.chain_backend.rpc_url.clear();
        config.oracle_url = url;
        let router = App::new(config).await.unwrap().router();
        let request = |tx: &Transaction| {
            Request::builder()
                .method("POST")
                .uri("/api/chain/tx")
                .body(Body::from(hex::encode(
                    simplex::simplicityhl::elements::encode::serialize(tx),
                )))
                .unwrap()
        };

        let response = router.clone().oneshot(request(&transaction)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), expected_txid.as_bytes());

        let mut burn = transaction;
        burn.output.push(TxOut {
            asset: Asset::Explicit(AssetId::from_str(&"77".repeat(32)).unwrap()),
            value: Value::Explicit(1000),
            nonce: Nonce::Null,
            script_pubkey: Voucher::get_burn_script(1),
            witness: TxOutWitness::default(),
        });
        let response = router.oneshot(request(&burn)).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(broadcasts.load(Ordering::Relaxed), 1);
        task.abort();
    }

    #[tokio::test]
    async fn admin_creates_and_resolves_prediction_with_verifiable_signature() {
        let temp = std::env::temp_dir().join(format!("prediction-demo-{}.json", Uuid::new_v4()));
        let app = App::new(config(temp.clone())).await.unwrap();
        let public_key = app.state.keypair.x_only_public_key().0;
        let router = app.router();

        let login = router
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/admin/login",
                serde_json::json!({"login":"oracle-admin","password":"test-password"}),
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let token = response_json(login).await["token"]
            .as_str()
            .unwrap()
            .to_string();
        let deadline = unix_time().unwrap() + 3_600;

        let mut create = json_request(
            "POST",
            "/api/admin/predictions",
            serde_json::json!({"title":"Event A happens","deadline":deadline}),
        );
        create.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let created = router.clone().oneshot(create).await.unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let prediction = response_json(created).await;
        let id = prediction["id"].as_str().unwrap();
        let occurred_at = deadline - 10;

        let mut resolve = json_request(
            "POST",
            &format!("/api/admin/predictions/{id}/resolve"),
            serde_json::json!({"occurred_at":occurred_at}),
        );
        resolve.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let resolved = router.oneshot(resolve).await.unwrap();
        assert_eq!(resolved.status(), StatusCode::OK);
        let resolved = response_json(resolved).await;
        let signature = Signature::from_str(resolved["signature"].as_str().unwrap()).unwrap();
        let prediction_id: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        let message = resolution_digest(prediction_id, occurred_at);
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &public_key)
            .unwrap();

        let _ = tokio::fs::remove_file(temp).await;
    }

    #[tokio::test]
    async fn rejects_invalid_admin_credentials() {
        let temp = std::env::temp_dir().join(format!("prediction-demo-{}.json", Uuid::new_v4()));
        let app = App::new(config(temp)).await.unwrap();
        let response = app
            .router()
            .oneshot(json_request(
                "POST",
                "/api/admin/login",
                serde_json::json!({"login":"oracle-admin","password":"wrong"}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn assembles_redemption_after_owner_signs_the_tick_hash() {
        assert_redemption(false, false).await;
    }

    #[tokio::test]
    async fn assembles_redemption_authorized_by_the_wallet_fee_input() {
        assert_redemption(true, false).await;
    }

    #[tokio::test]
    async fn assembles_confidential_redemption_without_changing_legacy_positions() {
        assert_redemption(true, true).await;
    }

    async fn assert_redemption(script_auth: bool, confidential_payout: bool) {
        let temp = std::env::temp_dir().join(format!("prediction-demo-{}.json", Uuid::new_v4()));
        let owner_secret = SecretKey::from_byte_array([0x22; 32]).unwrap();
        let owner_keypair = Keypair::from_secret_key(&Secp256k1::new(), &owner_secret);
        let owner_public_key = owner_keypair.x_only_public_key().0.serialize();
        let payout_script = Script::from(hex::decode(format!("0014{}", "55".repeat(20))).unwrap());
        let tick_asset = parse_asset(&"33".repeat(32), "Tick asset").unwrap();
        let storm_eye_asset = parse_asset(&"44".repeat(32), "Storm Eye asset").unwrap();
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset: parse_asset(&"66".repeat(32), "policy asset").unwrap(),
            genesis_hash: "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f"
                .parse()
                .unwrap(),
        };
        let voucher = VoucherProgram::new(
            &VoucherParameters {
                storm_eye_asset_id: storm_eye_asset,
                auth_method: if script_auth {
                    VoucherAuthMethod::Script {
                        auth_script_hash: hash_script(&payout_script),
                    }
                } else {
                    VoucherAuthMethod::Signature {
                        auth_pubkey: owner_public_key,
                    }
                },
                network,
            }
            .build_arguments(),
        );
        let tick_script = voucher.get_script_pubkey(&network);
        let app_config = config(temp.clone());
        let app = App::new(app_config).await.unwrap();
        let prediction_id = [0x77; 32];
        let prediction_id_hex = hex::encode(prediction_id);
        let occurred_at = 1_700_000_000;
        let deadline = occurred_at + 60;
        let resolution_signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(
                &resolution_digest(prediction_id, occurred_at),
                &app.state.keypair,
            )
            .to_string();
        app.state.store.write().await.predictions.push(Prediction {
            id: prediction_id_hex.clone(),
            title: "Event A happens".into(),
            deadline,
            created_at: occurred_at - 60,
            price: None,
            resolution: Some(Resolution {
                occurred_at,
                signature: resolution_signature,
            }),
        });
        let position_asset = parse_asset(&"66".repeat(32), "position asset").unwrap();
        let parameters = PredictionParameters {
            prediction_id,
            admin_pubkey: app.state.keypair.x_only_public_key().0.serialize(),
            deadline,
            tick_asset_id: tick_asset,
            tick_script_hash: hash_script(&tick_script),
            payout_script_hash: hash_script(&payout_script),
            network,
        };
        let prediction_contract = if confidential_payout {
            PredictionContract::new_confidential(parameters)
        } else {
            PredictionContract::new(parameters)
        };
        let mut request = serde_json::json!({
            "position": {
                "txid": "01".repeat(32), "vout": 0,
                "script_pubkey": hex::encode(prediction_contract.get_script_pubkey().into_bytes()),
                "amount_sats": 50_000, "asset": position_asset.to_string()
            },
            "tick": {
                "txid": "02".repeat(32), "vout": 1,
                "script_pubkey": hex::encode(tick_script.into_bytes()),
                "amount_sats": occurred_at + 10, "asset": tick_asset.to_string()
            },
            "fee": {
                "txid": "03".repeat(32), "vout": 2,
                "script_pubkey": hex::encode(payout_script.clone().into_bytes()),
                "amount_sats": 10_000, "asset": position_asset.to_string()
            },
            "payout_script_pubkey": hex::encode(payout_script.clone().into_bytes()),
            "owner_public_key": hex::encode(owner_public_key),
            "storm_eye_asset_id": storm_eye_asset.to_string()
        });
        let uri = format!("/api/predictions/{prediction_id_hex}/redemption");
        if confidential_payout {
            let blind_secret =
                simplex::simplicityhl::elements::secp256k1_zkp::SecretKey::from_slice(&[0x77; 32])
                    .unwrap();
            let blind_public =
                simplex::simplicityhl::elements::secp256k1_zkp::PublicKey::from_secret_key(
                    &ZkpSecp256k1::new(),
                    &blind_secret,
                );
            request["payout_blinding_key"] = serde_json::json!(blind_public.to_string());
        }
        if script_auth {
            request["tick_auth_script_pubkey"] =
                serde_json::json!(hex::encode(payout_script.into_bytes()));
            let mut wrong_wallet = request.clone();
            wrong_wallet["tick_auth_script_pubkey"] =
                serde_json::json!(format!("0014{}", "99".repeat(20)));
            let rejected = app
                .router()
                .oneshot(json_request("POST", &uri, wrong_wallet))
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        }
        if confidential_payout {
            for field in ["payout_blinding_key", "tick_auth_script_pubkey"] {
                let mut invalid = request.clone();
                invalid.as_object_mut().unwrap().remove(field);
                let rejected = app
                    .router()
                    .oneshot(json_request("POST", &uri, invalid))
                    .await
                    .unwrap();
                assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
            }
        }
        let prepared = app
            .router()
            .oneshot(json_request("POST", &uri, request.clone()))
            .await
            .unwrap();
        let prepared_status = prepared.status();
        let prepared = response_json(prepared).await;
        assert_eq!(prepared_status, StatusCode::OK, "{prepared}");
        let tick_hash: [u8; 32] = hex::decode(prepared["tick_signature_hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let tick_signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&tick_hash, &owner_keypair)
            .to_string();
        let tick_signature_bytes = hex::decode(&tick_signature).unwrap();
        let mut signed_request = request;
        signed_request["tick_signature"] = serde_json::Value::String(tick_signature);
        let finalized = app
            .router()
            .oneshot(json_request("POST", &uri, signed_request))
            .await
            .unwrap();
        let finalized_status = finalized.status();
        let mut finalized = response_json(finalized).await;
        assert_eq!(finalized_status, StatusCode::OK, "{finalized}");
        if script_auth {
            finalized = prepared;
        }
        let pset = finalized["pset"]
            .as_str()
            .unwrap()
            .parse::<simplex::simplicityhl::elements::pset::PartiallySignedTransaction>()
            .unwrap();
        let expected_final_tick_witness = if script_auth {
            pset.inputs()[1]
                .final_script_witness
                .clone()
                .expect("script authorization must finalize the Tick without a wallet signature")
        } else {
            let tick_signature_bytes: [u8; 64] = tick_signature_bytes.try_into().unwrap();
            let expected_tick_witness =
                build_signed_voucher_witness(voucher.as_ref(), tick_signature_bytes, 1).unwrap();
            voucher
                .as_ref()
                .finalize(&pset, &expected_tick_witness, 1, &network)
                .unwrap()
        };
        assert_eq!(
            pset.inputs()[2].sighash_type,
            Some(EcdsaSighashType::All.into())
        );
        assert_eq!(pset.outputs()[1].script_pubkey, Voucher::get_burn_script(1));
        assert_eq!(pset.outputs()[0].amount_comm.is_some(), confidential_payout);
        assert_eq!(pset.outputs()[2].amount_comm.is_some(), confidential_payout);
        assert!(pset.outputs()[1].amount_comm.is_none());
        assert!(pset.outputs()[3].amount_comm.is_none());
        if confidential_payout {
            for index in [0, 2] {
                assert_eq!(pset.outputs()[index].blinder_index, Some(0));
            }
            let secp = ZkpSecp256k1::new();
            let transaction = pset.extract_tx().unwrap();
            let previous = pset
                .inputs()
                .iter()
                .map(|input| input.witness_utxo.clone().unwrap())
                .collect::<Vec<_>>();
            transaction.verify_tx_amt_proofs(&secp, &previous).unwrap();
            let blind_secret =
                simplex::simplicityhl::elements::secp256k1_zkp::SecretKey::from_slice(&[0x77; 32])
                    .unwrap();
            for (index, expected) in [(0, 50_000), (2, 9_000)] {
                let secrets = transaction.output[index]
                    .unblind(&secp, blind_secret)
                    .unwrap();
                assert_eq!(secrets.value, expected);
                assert_eq!(secrets.asset, position_asset);
            }
        }
        assert!(
            pset.inputs()
                .iter()
                .all(|input| input.amount.is_none() && input.asset.is_none())
        );
        assert_eq!(
            pset.inputs()[1].final_script_witness.as_ref(),
            Some(&expected_final_tick_witness),
            "Tick covenant witness should be finalized with the supplied signature"
        );

        let _ = tokio::fs::remove_file(temp).await;
    }
}
