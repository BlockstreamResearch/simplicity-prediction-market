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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{
    AssetId, BlockHash, EcdsaSighashType, OutPoint, Script, Transaction, TxOut, TxOutWitness, Txid,
    bitcoin::PublicKey as BitcoinPublicKey,
    confidential::{Asset, Nonce, Value},
    secp256k1_zkp::{Secp256k1 as ZkpSecp256k1, rand::thread_rng},
};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};
use simplex::utils::hash_script;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use price_oracle_contracts::artifacts::voucher::VoucherProgram;
use price_oracle_contracts::voucher::{
    Voucher, VoucherAuthMethod, VoucherParameters, VoucherSpendPath,
};

const SESSION_BYTES: usize = 32;
mod db;
mod escrow;
mod price;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub listen_address: SocketAddr,
    pub database_url: String,
    #[serde(default = "default_database_max_connections")]
    pub database_max_connections: u32,
    pub admin_login: String,
    pub admin_password: String,
    pub policy_asset_id: String,
    pub genesis_block_hash: String,
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_seconds: u64,
    #[serde(default)]
    pub chain_backend: ChainBackendConfig,
    #[serde(default = "price::default_oracle_url")]
    pub oracle_url: String,
    #[serde(default)]
    pub trust_coordinator: bool,
    #[serde(default)]
    pub oracle_verification: Option<price::OracleVerificationConfig>,
    #[serde(default)]
    pub escrow: Option<escrow::EscrowConfig>,
    #[serde(default)]
    pub auto_publish: price::AutoPublishConfig,
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

fn default_database_max_connections() -> u32 {
    5
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self, AppError> {
        let contents = tokio::fs::read_to_string(path).await?;
        Ok(toml::from_str(&contents)?)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Prediction {
    pub id: String,
    pub title: String,
    pub deadline: u64,
    pub created_at: u64,
    pub price: price::PriceMarket,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    network: SimplicityNetwork,
    db: db::Database,
    sessions: Arc<RwLock<HashMap<String, u64>>>,
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
        if config.trust_coordinator && config.oracle_verification.is_some() {
            return Err(AppError::ConflictingOracleTrust);
        }

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
        let reserve_wallet = if let Some(escrow) = &config.escrow {
            if let Some(path) = &escrow.private_key_file {
                if !escrow.wallet.is_empty() {
                    return Err(AppError::InvalidEscrowKey);
                }
                Some(escrow::LocalWallet::load(path, network).await?)
            } else {
                None
            }
        } else {
            None
        };
        let db =
            db::Database::connect(&config.database_url, config.database_max_connections).await?;

        Ok(Self {
            state: AppState {
                config,
                network,
                escrows: Arc::default(),
                reserve_wallet,
                chain_client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(15))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?,
                db,
                sessions: Arc::default(),
            },
        })
    }

    #[must_use]
    pub fn listen_address(&self) -> SocketAddr {
        self.state.config.listen_address
    }

    pub async fn run_auto_publisher(&self) {
        price::run_auto_publisher(&self.state).await;
    }

    #[must_use]
    pub fn router(&self) -> Router {
        Router::new()
            .route("/api/config", get(public_config))
            .route("/api/oracle/verification", post(price::verification))
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
            .route("/api/admin/login", post(login))
            .route("/api/admin/escrow", get(escrow::status))
            .route("/api/admin/predictions", post(create_prediction))
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
    let burn = tick_burn_allowance(&tx.output, state.network.policy_asset())?;
    if burn > 0 {
        let account = price::network(&state).await?;
        voucher_burn_allowance(
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

    let response: serde_json::Value = state
        .chain_client
        .post(&backend.rpc_url)
        .basic_auth(&backend.rpc_username, Some(&backend.rpc_password))
        .json(&serde_json::json!({
            "jsonrpc": "1.0", "id": "prediction-broadcast", "method": "sendrawtransaction",
            "params": [tx_hex, 0.1],
        }))
        .send()
        .await
        .map_err(|_| ApiError::internal("chain broadcaster unavailable"))?
        .json()
        .await
        .map_err(|_| ApiError::internal("invalid broadcaster response"))?;
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

async fn list_predictions(
    State(state): State<AppState>,
) -> Result<Json<Vec<Prediction>>, ApiError> {
    Ok(Json(state.db.list().await?))
}

async fn find_prediction(state: &AppState, id: &str) -> Result<Prediction, ApiError> {
    state
        .db
        .find(id)
        .await?
        .ok_or_else(|| ApiError::not_found("prediction does not exist"))
}

#[derive(Deserialize)]
struct DeriveContractRequest {
    payout_script_pubkey: String,
    owner_public_key: Option<String>,
}

#[derive(Serialize)]
struct DerivedContract {
    script_pubkey: String,
}

async fn derive_contract(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<DeriveContractRequest>,
) -> Result<Json<DerivedContract>, ApiError> {
    let prediction = find_prediction(&state, &id).await?;
    price::derive(&state, &prediction, &request).await
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

#[derive(Serialize)]
struct RedemptionResponse {
    tick_signature_hash: String,
    pset: Option<String>,
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
        .sessions
        .write()
        .await
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
    let price = request
        .price
        .ok_or_else(|| ApiError::bad_request("predictions require oracle price terms"))?;
    let price = price::publish(&state, price, request.deadline).await?;

    let id = prediction_id(title, request.deadline, Uuid::new_v4());
    let prediction = Prediction {
        id,
        title: title.to_string(),
        deadline: request.deadline,
        created_at: now,
        price,
    };
    if !state.db.insert(&prediction).await? {
        return Err(ApiError::conflict("prediction already exists"));
    }

    Ok((StatusCode::CREATED, Json(prediction)))
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing admin token"))?;
    let now = unix_time()?;
    let mut sessions = state.sessions.write().await;
    sessions.retain(|_, expires_at| *expires_at > now);
    if sessions.contains_key(token) {
        Ok(())
    } else {
        Err(ApiError::unauthorized("admin token is invalid or expired"))
    }
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
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error(
        "escrow private key file must contain a valid 32-byte secret key; choose either a local key file or a node wallet"
    )]
    InvalidEscrowKey,
    #[error("policy_asset_id must be a valid Elements asset ID")]
    InvalidPolicyAsset,
    #[error("genesis_block_hash must be a valid Elements block hash")]
    InvalidGenesisHash,
    #[error("choose either trust_coordinator = true or pinned [oracle_verification], not both")]
    ConflictingOracleTrust,
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

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database operation failed");
        Self::internal("database operation failed")
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
    use tower::ServiceExt;

    use super::*;

    pub(super) const HOLDER_PUBLIC_KEY: &str =
        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    pub(super) fn config() -> Config {
        Config {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            database_url: "sqlite::memory:".into(),
            database_max_connections: 1,
            auto_publish: price::AutoPublishConfig::default(),
            admin_login: "oracle-admin".into(),
            admin_password: "test-password".into(),
            policy_asset_id: "66".repeat(32),
            genesis_block_hash: "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f"
                .into(),
            session_lifetime_seconds: 60,
            chain_backend: ChainBackendConfig::default(),
            oracle_url: price::default_oracle_url(),
            trust_coordinator: false,
            oracle_verification: None,
            escrow: None,
        }
    }

    pub(super) fn price_terms() -> price::PriceMarket {
        price::PriceMarket {
            feed_id: 0,
            decimals: 8,
            strike: "10000000000".into(),
            above: true,
            opens_at: 1000,
            claim_grace: 600,
            house_script_pubkey: format!("0014{}", "55".repeat(20)),
            tick_asset_id: "33".repeat(32),
            verifier_asset_id: "44".repeat(32),
            storm_eye_asset_id: "55".repeat(32),
        }
    }

    pub(super) fn oracle_routes(network: &'static str) -> Router {
        let metadata = move || async move {
            let terms = price_terms();
            Json(serde_json::json!({
                "network": network,
                "tick_asset_id": terms.tick_asset_id,
                "oracle_verifier_asset_id": terms.verifier_asset_id,
                "storm_eye_asset_id": terms.storm_eye_asset_id,
            }))
        };
        Router::new()
            .route("/users/network", get(metadata))
            .route("/users/account/{owner}", get(metadata))
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
        let app = App::new(config()).await.unwrap();
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
    async fn rpc_broadcast_uses_elements_parameters_without_retrying_errors() {
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
                StatusCode::BAD_REQUEST,
                1,
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
                        count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(request["params"].as_array().unwrap().len(), 2);
                        Json(if !error.is_null() {
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
            let mut config = config();
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
        let mut config = config();
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
    async fn rejects_predictions_without_oracle_price_terms() {
        let app = App::new(config()).await.unwrap();
        let now = unix_time().unwrap();
        app.state
            .sessions
            .write()
            .await
            .insert("test-session".into(), now + 3600);
        let mut request = json_request(
            "POST",
            "/api/admin/predictions",
            serde_json::json!({ "title": "Unsupported event", "deadline": now + 3600 }),
        );
        request.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer test-session".parse().unwrap(),
        );
        assert_eq!(
            app.router().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        assert!(app.state.db.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn event_routes_are_unavailable() {
        let app = App::new(config()).await.unwrap();
        let market = Prediction {
            id: "88".repeat(32),
            title: "Price market".into(),
            deadline: unix_time().unwrap() + 3600,
            created_at: 1000,
            price: price_terms(),
        };
        app.state.db.insert(&market).await.unwrap();
        let router = app.router();
        let response = router
            .clone()
            .oneshot(json_request(
                "GET",
                "/api/predictions",
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(response_json(response).await, serde_json::json!([market]));

        for (method, path, body) in [
            (
                "GET",
                format!("/api/predictions/{}/resolution", market.id),
                serde_json::json!({}),
            ),
            (
                "POST",
                format!("/api/admin/predictions/{}/resolve", market.id),
                serde_json::json!({ "occurred_at": 1500 }),
            ),
            (
                "POST",
                format!("/api/predictions/{}/redemption", market.id),
                serde_json::json!({}),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(json_request(method, &path, body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(app.state.db.find(&market.id).await.unwrap(), Some(market));
    }

    #[tokio::test]
    async fn rejects_invalid_admin_credentials() {
        let app = App::new(config()).await.unwrap();
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
    async fn database_preserves_predictions_across_restarts() {
        let directory =
            std::env::temp_dir().join(format!("prediction-database-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let mut config = config();
        config.database_url = format!(
            "sqlite://{}/predictions.sqlite3?mode=rwc",
            directory.display()
        );
        let prediction = Prediction {
            id: "77".repeat(32),
            title: "BTC/USD reaches its target".into(),
            deadline: 2000,
            created_at: 1000,
            price: price_terms(),
        };

        let app = App::new(config.clone()).await.unwrap();
        assert!(app.state.db.insert(&prediction).await.unwrap());
        let restored = App::new(config).await.unwrap();
        assert_eq!(
            restored.state.db.list().await.unwrap(),
            vec![prediction.clone()]
        );
        assert_eq!(
            restored.state.db.find(&prediction.id).await.unwrap(),
            Some(prediction)
        );
        drop(app);
        drop(restored);
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }
}
