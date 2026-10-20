use super::*;
use prediction_demo_contracts::{PriceMarketContract, PriceMarketParameters, PriceMarketSpend};
use price_feed::PriceFeedData;
use price_oracle_contracts::sdk::SignedPrice;
use simplex::simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;

const AUTO_PUBLISH_INTERVAL: u64 = 12 * 60 * 60;

#[derive(Clone, Deserialize)]
pub struct OracleVerificationConfig {
    pub storm_eye_asset_id: String,
    pub tick_asset_id: String,
    pub verifier_asset_id: String,
    pub storm_tree_root: String,
}

#[derive(Deserialize)]
struct CoordinatorVerification {
    #[serde(flatten)]
    account: OracleAccount,
    storm_tree_root: String,
}

#[derive(Deserialize)]
pub(super) struct VerificationRequest {
    owner_public_key: String,
    auth_script_pubkey: String,
}

pub(super) async fn verification(
    State(state): State<AppState>,
    Json(request): Json<VerificationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use price_oracle_contracts::artifacts::account::{
        AccountProgram, derived_account::AccountArguments,
    };

    let owner = parse_hex_array::<32>(&request.owner_public_key, "owner public key")?;
    XOnlyPublicKey::from_slice(&owner)
        .map_err(|_| ApiError::bad_request("invalid owner public key"))?;
    let auth = parse_script(&request.auth_script_pubkey, "authentication script")?;
    if !auth.is_v0_p2wpkh() {
        return Err(ApiError::bad_request(
            "authentication requires a Humid P2WPKH script",
        ));
    }
    let trusted = if state.config.trust_coordinator {
        let metadata: CoordinatorVerification =
            serde_json::from_value(oracle_json(&state, "/users/network").await?)
                .map_err(|_| ApiError::internal("invalid oracle verification metadata"))?;
        let account = validate_network(&state, metadata.account)?;
        OracleVerificationConfig {
            storm_eye_asset_id: account.storm_eye_asset_id,
            tick_asset_id: account.tick_asset_id,
            verifier_asset_id: account.oracle_verifier_asset_id,
            storm_tree_root: metadata.storm_tree_root,
        }
    } else {
        state.config.oracle_verification.clone().ok_or_else(|| {
            ApiError::conflict("independent oracle verification anchors are not configured")
        })?
    };
    let storm_eye = parse_asset(&trusted.storm_eye_asset_id, "trusted Storm Eye asset")?;
    let tick = parse_asset(&trusted.tick_asset_id, "trusted Tick asset")?;
    let verifier = parse_asset(&trusted.verifier_asset_id, "trusted Verifier asset")?;
    let root = parse_hex_array::<32>(&trusted.storm_tree_root, "trusted Storm Tree root")?;
    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye.to_byte_array(),
        account_owner_pubkey: owner,
    });
    let voucher = Voucher::new(VoucherParameters {
        storm_eye_asset_id: storm_eye,
        auth_method: VoucherAuthMethod::Script {
            auth_script_hash: hash_script(&auth),
        },
        network: state.network,
    });

    Ok(Json(serde_json::json!({
        "ownerPublicKey": hex::encode(owner),
        "network": state.oracle_network(),
        "stormEyeAssetId": storm_eye.to_string(),
        "tickAssetId": tick.to_string(),
        "verifierAssetId": verifier.to_string(),
        "stormTreeRoot": hex::encode(root),
        "accountTapleafHash": hex::encode(account.get_tapleaf_hash()),
        "tickTapleafHash": hex::encode(voucher.get_tapleaf_hash()),
        "authScriptPubKey": hex::encode(auth.as_bytes()),
    })))
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct AutoPublishConfig {
    pub enabled: bool,
    pub feed_id: u32,
}

pub(super) async fn run_auto_publisher(state: &AppState) {
    if !state.config.auto_publish.enabled {
        std::future::pending::<()>().await;
        return;
    }

    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let result = match unix_time() {
            Ok(now) => publish_scheduled(state, now).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::warn!(%error.message, "automatic prediction publication failed; retrying next minute");
        }
    }
}

async fn publish_scheduled(state: &AppState, now: u64) -> Result<bool, ApiError> {
    if !state.config.auto_publish.enabled {
        return Ok(false);
    }
    let feed_id = state.config.auto_publish.feed_id;
    let slot = now / AUTO_PUBLISH_INTERVAL * AUTO_PUBLISH_INTERVAL;
    let deadline = slot
        .checked_add(AUTO_PUBLISH_INTERVAL)
        .ok_or_else(|| ApiError::internal("automatic prediction deadline overflow"))?;
    let id = hex::encode(Sha256::digest(format!(
        "auto-price-v1:{}:{feed_id}:{slot}",
        state.config.genesis_block_hash,
    )));
    if state.db.find(&id).await?.is_some() {
        return Ok(false);
    }
    let wallet = state.reserve_wallet.as_ref().ok_or_else(|| {
        ApiError::internal("automatic publishing requires a local reserve wallet")
    })?;
    let started_at = tokio::time::Instant::now();
    let latest = oracle_json(state, &format!("/price-feeds/{feed_id}")).await?;
    let data: PriceFeedData = serde_json::from_value(latest["main"]["feed"].clone())
        .map_err(|_| ApiError::internal("invalid latest oracle price"))?;
    if data.feed_id != feed_id
        || data.price == 0
        || data.received_at > now
        || data.valid_until <= now
    {
        return Err(ApiError::conflict(
            "latest oracle price is stale or invalid",
        ));
    }
    let above = secp256k1::rand::random::<bool>();
    let strike = automatic_strike(data.price, above)?;
    let price = publish(
        state,
        PriceMarketRequest {
            feed_id,
            strike: strike.to_string(),
            above,
            opens_at: now,
            claim_grace: default_grace(),
            house_script_pubkey: hex::encode(wallet.script_pubkey().as_bytes()),
        },
        deadline,
    )
    .await?;
    if price.decimals != data.decimals {
        return Err(ApiError::conflict("oracle feed decimals changed"));
    }
    if now.saturating_add(started_at.elapsed().as_secs()) >= deadline {
        return Err(ApiError::conflict(
            "automatic prediction window has expired",
        ));
    }

    let market = if feed_id == 0 {
        "BTC/USD".into()
    } else {
        format!("Price feed {feed_id}")
    };
    let title = format!(
        "{market} reaches {}1% by {:02}:{:02} UTC",
        if above { "+" } else { "-" },
        deadline / 3600 % 24,
        deadline / 60 % 60,
    );
    let inserted = state
        .db
        .insert(&Prediction {
            id: id.clone(),
            title,
            deadline,
            created_at: now,
            price,
        })
        .await?;
    if inserted {
        tracing::info!(%id, feed_id, deadline, "automatically published prediction");
    }
    Ok(inserted)
}

fn automatic_strike(price: u64, above: bool) -> Result<u64, ApiError> {
    let strike = if above {
        (u128::from(price) * 101).div_ceil(100)
    } else {
        u128::from(price) * 99 / 100
    };
    u64::try_from(strike).map_err(|_| ApiError::internal("automatic prediction strike overflow"))
}

pub(super) fn default_oracle_url() -> String {
    "http://127.0.0.1:9100".into()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PriceMarket {
    pub feed_id: u32,
    pub decimals: u32,
    pub strike: String,
    pub above: bool,
    pub opens_at: u64,
    pub claim_grace: u64,
    pub house_script_pubkey: String,
    pub tick_asset_id: String,
    pub verifier_asset_id: String,
    pub storm_eye_asset_id: String,
}

#[derive(Deserialize)]
pub(super) struct PriceMarketRequest {
    feed_id: u32,
    strike: String,
    above: bool,
    opens_at: u64,
    #[serde(default = "default_grace")]
    claim_grace: u64,
    house_script_pubkey: String,
}

fn default_grace() -> u64 {
    600
}

#[derive(Deserialize)]
pub(super) struct OracleAccount {
    pub tick_asset_id: String,
    pub oracle_verifier_asset_id: String,
    pub storm_eye_asset_id: String,
    network: String,
}

async fn oracle_response(state: &AppState, path: &str) -> Result<reqwest::Response, ApiError> {
    state
        .chain_client
        .get(format!(
            "{}{path}",
            state.config.oracle_url.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|_| ApiError::internal("oracle unavailable"))
}

async fn oracle_json(state: &AppState, path: &str) -> Result<serde_json::Value, ApiError> {
    let response = oracle_response(state, path).await?;
    if !response.status().is_success() {
        return Err(ApiError::conflict("oracle feed or network is unavailable"));
    }
    response
        .json()
        .await
        .map_err(|_| ApiError::internal("invalid oracle response"))
}

pub(super) async fn account(state: &AppState, owner: &str) -> Result<OracleAccount, ApiError> {
    let bytes = parse_hex_array::<32>(owner, "owner public key")?;
    XOnlyPublicKey::from_slice(&bytes)
        .map_err(|_| ApiError::bad_request("invalid owner public key"))?;
    let account =
        serde_json::from_value(oracle_json(state, &format!("/users/account/{owner}")).await?)
            .map_err(|_| ApiError::internal("invalid oracle account"))?;
    validate_network(state, account)
}

pub(super) async fn network(state: &AppState) -> Result<OracleAccount, ApiError> {
    let response = oracle_response(state, "/users/network").await?;
    if !response.status().is_success() {
        return Err(ApiError::conflict("oracle network metadata is unavailable"));
    }
    let metadata = response
        .json()
        .await
        .map_err(|_| ApiError::internal("invalid oracle network metadata"))?;
    validate_network(state, metadata)
}

fn validate_network(state: &AppState, account: OracleAccount) -> Result<OracleAccount, ApiError> {
    if account.network != state.oracle_network() {
        return Err(ApiError::bad_request(
            "oracle network does not match the configured prediction chain",
        ));
    }
    for (value, name) in [
        (&account.tick_asset_id, "Tick asset"),
        (&account.oracle_verifier_asset_id, "Verifier asset"),
        (&account.storm_eye_asset_id, "Storm Eye asset"),
    ] {
        parse_asset(value, name)?;
    }
    if let Some(trusted) = &state.config.oracle_verification {
        for (actual, expected) in [
            (&account.tick_asset_id, &trusted.tick_asset_id),
            (
                &account.oracle_verifier_asset_id,
                &trusted.verifier_asset_id,
            ),
            (&account.storm_eye_asset_id, &trusted.storm_eye_asset_id),
        ] {
            if parse_asset(actual, "oracle asset")?
                != parse_asset(expected, "trusted oracle asset")?
            {
                return Err(ApiError::bad_request(
                    "oracle assets do not match the configured trust anchors",
                ));
            }
        }
    }
    Ok(account)
}

pub(super) async fn feeds(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(oracle_json(&state, "/price-feeds").await?))
}

pub(super) async fn feed(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<u32>,
) -> Result<
    (
        [(header::HeaderName, &'static str); 1],
        Json<serde_json::Value>,
    ),
    ApiError,
> {
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(oracle_json(&state, &format!("/price-feeds/{id}")).await?),
    ))
}

pub(super) async fn publish(
    state: &AppState,
    request: PriceMarketRequest,
    deadline: u64,
) -> Result<PriceMarket, ApiError> {
    if request.opens_at >= deadline
        || request.claim_grace < 1
        || request.claim_grace > 3600
        || deadline.checked_add(request.claim_grace).is_none()
    {
        return Err(ApiError::bad_request(
            "invalid price window or claim grace (1-3600 seconds)",
        ));
    }
    let strike = request.strike.parse::<u64>().map_err(|_| {
        ApiError::bad_request("strike must be a scaled unsigned 64-bit integer string")
    })?;
    if strike == 0 {
        return Err(ApiError::bad_request("strike must be positive"));
    }
    let house = parse_script(&request.house_script_pubkey, "house script")?;
    if !house.is_v0_p2wpkh() {
        return Err(ApiError::bad_request(
            "house must be a Humid P2WPKH wallet script",
        ));
    }
    let registry = oracle_json(state, "/price-feeds").await?;
    let definition = registry
        .as_array()
        .and_then(|feeds| {
            feeds
                .iter()
                .find(|feed| feed["id"].as_u64() == Some(u64::from(request.feed_id)))
        })
        .ok_or_else(|| ApiError::bad_request("unsupported price feed"))?;
    let decimals = definition["decimals"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ApiError::internal("invalid feed decimals"))?;
    let account = network(state).await?;
    Ok(PriceMarket {
        feed_id: request.feed_id,
        decimals,
        strike: strike.to_string(),
        above: request.above,
        opens_at: request.opens_at,
        claim_grace: request.claim_grace,
        house_script_pubkey: request.house_script_pubkey,
        tick_asset_id: account.tick_asset_id,
        verifier_asset_id: account.oracle_verifier_asset_id,
        storm_eye_asset_id: account.storm_eye_asset_id,
    })
}

fn contract(
    state: &AppState,
    prediction: &Prediction,
    payout: &Script,
) -> Result<PriceMarketContract, ApiError> {
    let terms = &prediction.price;
    let parameters = PriceMarketParameters {
        prediction_id: parse_prediction_id(&prediction.id)?,
        feed_id: terms.feed_id,
        decimals: terms.decimals,
        strike: terms
            .strike
            .parse()
            .map_err(|_| ApiError::internal("invalid stored strike"))?,
        above: terms.above,
        opens_at: terms.opens_at,
        deadline: prediction.deadline,
        claim_grace: terms.claim_grace,
        verifier_asset_id: parse_asset(&terms.verifier_asset_id, "Verifier asset")?,
        tick_asset_id: parse_asset(&terms.tick_asset_id, "Tick asset")?,
        payout_script_hash: hash_script(payout),
        house_script_hash: hash_script(&parse_script(&terms.house_script_pubkey, "house script")?),
        network: state.network,
    };
    Ok(PriceMarketContract::new_with_tick(parameters))
}

pub(super) async fn derive(
    state: &AppState,
    prediction: &Prediction,
    request: &DeriveContractRequest,
) -> Result<Json<DerivedContract>, ApiError> {
    let terms = &prediction.price;
    let payout = parse_script(&request.payout_script_pubkey, "payout script")?;
    if !payout.is_v0_p2wpkh() {
        return Err(ApiError::bad_request(
            "payout must be a Humid P2WPKH wallet script",
        ));
    }
    let account = account(
        state,
        request
            .owner_public_key
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("owner public key required"))?,
    )
    .await?;
    if account.tick_asset_id != terms.tick_asset_id
        || account.oracle_verifier_asset_id != terms.verifier_asset_id
    {
        return Err(ApiError::conflict(
            "oracle deployment changed since publication",
        ));
    }
    Ok(Json(DerivedContract {
        script_pubkey: hex::encode(
            contract(state, prediction, &payout)?
                .get_script_pubkey()
                .as_bytes(),
        ),
    }))
}

#[derive(Deserialize)]
pub(super) struct SignedPriceRequest {
    price_data: String,
    signer: String,
    signature: String,
}

#[derive(Deserialize)]
pub(super) struct SettlementRequest {
    position: ExplicitUtxo,
    voucher: ExplicitUtxo,
    tick: Option<ExplicitUtxo>,
    fee: ExplicitUtxo,
    payout_script_pubkey: String,
    auth_script_pubkey: String,
    signed_price: Option<SignedPriceRequest>,
}

fn signed_price(
    request: &SignedPriceRequest,
    terms: &PriceMarket,
    deadline: u64,
) -> Result<SignedPrice, ApiError> {
    let bytes = parse_hex_array::<32>(&request.price_data, "price data")?;
    let data = PriceFeedData::from_bytes(&bytes)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let signed = SignedPrice::new(
        data,
        parse_hex_array::<32>(&request.signer, "signer")?,
        parse_hex_array::<64>(&request.signature, "price signature")?,
    );
    signed
        .verify()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let strike: u64 = terms
        .strike
        .parse()
        .map_err(|_| ApiError::internal("invalid stored strike"))?;
    if data.feed_id != terms.feed_id
        || data.decimals != terms.decimals
        || data.received_at < terms.opens_at
        || data.received_at > deadline
        || (if terms.above {
            data.price < strike
        } else {
            data.price > strike
        })
    {
        return Err(ApiError::bad_request(
            "signed price does not meet the market feed, window and strike",
        ));
    }
    Ok(signed)
}

fn verify_claim_tick(
    tick: &UTXO,
    signed: &SignedPrice,
    terms: &PriceMarket,
) -> Result<(), ApiError> {
    let price = signed.get_price();
    let cutoff = price
        .valid_until
        .checked_add(3300)
        .ok_or_else(|| ApiError::bad_request("extended price validity overflows"))?;
    if tick.explicit_asset() != parse_asset(&terms.tick_asset_id, "Tick asset")?
        || tick.explicit_amount() < price.received_at
        || tick.explicit_amount() >= cutoff
    {
        return Err(ApiError::bad_request(
            "Tick must be within the signed price validity plus 55 minutes",
        ));
    }
    Ok(())
}

async fn verify_prevout(state: &AppState, utxo: &UTXO) -> Result<(), ApiError> {
    let base = state.config.chain_backend.esplora_url.trim_end_matches('/');
    let transaction: serde_json::Value = state
        .chain_client
        .get(format!("{base}/tx/{}", utxo.outpoint.txid))
        .send()
        .await
        .map_err(|_| ApiError::internal("chain index unavailable"))?
        .error_for_status()
        .map_err(|_| ApiError::bad_request("prevout transaction not found"))?
        .json()
        .await
        .map_err(|_| ApiError::internal("invalid chain transaction"))?;
    let output = transaction["vout"]
        .get(utxo.outpoint.vout as usize)
        .ok_or_else(|| ApiError::bad_request("prevout index not found"))?;
    if transaction["status"]["confirmed"] != true
        || output["scriptpubkey"].as_str()
            != Some(&hex::encode(utxo.txout.script_pubkey.as_bytes()))
        || output["asset"].as_str() != Some(&utxo.explicit_asset().to_string())
        || output["value"].as_u64() != Some(utxo.explicit_amount())
    {
        return Err(ApiError::bad_request(
            "prevout must match a confirmed explicit chain output",
        ));
    }
    let spent: serde_json::Value = state
        .chain_client
        .get(format!(
            "{base}/tx/{}/outspend/{}",
            utxo.outpoint.txid, utxo.outpoint.vout
        ))
        .send()
        .await
        .map_err(|_| ApiError::internal("chain index unavailable"))?
        .error_for_status()
        .map_err(|_| ApiError::bad_request("prevout status not found"))?
        .json()
        .await
        .map_err(|_| ApiError::internal("invalid prevout status"))?;
    if spent["spent"] != false {
        return Err(ApiError::conflict("prevout is already spent"));
    }
    Ok(())
}

pub(super) async fn claim(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<SettlementRequest>,
) -> Result<Json<RedemptionResponse>, ApiError> {
    settle(&state, &id, request, false).await
}

pub(super) async fn sweep(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<SettlementRequest>,
) -> Result<Json<RedemptionResponse>, ApiError> {
    authenticate(&state, &headers).await?;
    settle(&state, &id, request, true).await
}

async fn settle(
    state: &AppState,
    id: &str,
    request: SettlementRequest,
    sweep: bool,
) -> Result<Json<RedemptionResponse>, ApiError> {
    let prediction = find_prediction(state, id).await?;
    let terms = &prediction.price;
    let payout = parse_script(&request.payout_script_pubkey, "position payout script")?;
    let auth = parse_script(&request.auth_script_pubkey, "voucher authorization script")?;
    let position = parse_utxo(&request.position, "position")?;
    let proof = parse_utxo(&request.voucher, "voucher")?;
    let fee = parse_utxo(&request.fee, "fee")?;
    let contract = contract(state, &prediction, &payout)?;
    let tick = if !sweep {
        Some(parse_utxo(
            request
                .tick
                .as_ref()
                .ok_or_else(|| ApiError::bad_request("price claim requires a Tick"))?,
            "Tick",
        )?)
    } else {
        None
    };
    if position.txout.script_pubkey != contract.get_script_pubkey()
        || position.explicit_asset() != state.network.policy_asset()
        || fee.explicit_asset() != state.network.policy_asset()
        || fee.explicit_amount() <= 1000
        || fee.txout.script_pubkey != auth
    {
        return Err(ApiError::bad_request(
            "position or wallet fee input does not match the market",
        ));
    }
    let mut inputs = vec![&position, &proof, &fee];
    if let Some(tick) = &tick {
        inputs.push(tick);
    }
    for (index, input) in inputs.iter().enumerate() {
        if inputs[..index]
            .iter()
            .any(|other| other.outpoint == input.outpoint)
        {
            return Err(ApiError::bad_request("duplicate transaction inputs"));
        }
    }
    let voucher_parameters = VoucherParameters {
        storm_eye_asset_id: parse_asset(&terms.storm_eye_asset_id, "Storm Eye asset")?,
        auth_method: VoucherAuthMethod::Script {
            auth_script_hash: hash_script(&auth),
        },
        network: state.network,
    };
    let mut program = VoucherProgram::new(voucher_parameters.build_arguments());
    let tick_program = tick
        .as_ref()
        .map(|_| VoucherProgram::new(voucher_parameters.build_arguments()));
    let destination;
    let spend;
    if sweep {
        destination = parse_script(&terms.house_script_pubkey, "house script")?;
        if auth != destination
            || proof.explicit_asset() != parse_asset(&terms.tick_asset_id, "Tick asset")?
            || proof.explicit_amount()
                <= prediction
                    .deadline
                    .checked_add(terms.claim_grace)
                    .ok_or_else(|| ApiError::bad_request("invalid sweep time"))?
        {
            return Err(ApiError::bad_request(
                "sweep requires a house-authorized post-grace Tick",
            ));
        }
        spend = PriceMarketSpend::Sweep {
            tick_input_index: 1,
            house_output_index: 0,
        };
    } else {
        if auth != payout {
            return Err(ApiError::bad_request(
                "claim must be authorized by the payout wallet",
            ));
        }
        let signed = signed_price(
            request
                .signed_price
                .as_ref()
                .ok_or_else(|| ApiError::bad_request("signed price required"))?,
            terms,
            prediction.deadline,
        )?;
        if proof.explicit_asset() != parse_asset(&terms.verifier_asset_id, "Verifier asset")?
            || proof.explicit_amount() != 1
        {
            return Err(ApiError::bad_request(
                "Verifier must have the market asset and amount 1",
            ));
        }
        program = program.with_taproot_pubkey(
            XOnlyPublicKey::from_slice(&signed.get_signer())
                .map_err(|_| ApiError::bad_request("invalid signer"))?,
        );
        verify_claim_tick(
            tick.as_ref().expect("claim Tick was parsed"),
            &signed,
            terms,
        )?;
        spend = PriceMarketSpend::ClaimWithTick {
            tick_input_index: 2,
            verifier_input_index: 1,
            verifier_tapleaf_hash: program.get_tapleaf_hash(),
            signed,
            payout_output_index: 0,
        };
        destination = payout;
    }
    if program.get_script_pubkey(&state.network) != proof.txout.script_pubkey {
        return Err(ApiError::bad_request(
            "voucher script does not match the signer and wallet authorization",
        ));
    }
    if let (Some(tick), Some(program)) = (&tick, &tick_program) {
        if tick.txout.script_pubkey != program.get_script_pubkey(&state.network) {
            return Err(ApiError::bad_request(
                "Tick script does not match wallet authorization",
            ));
        }
    }
    for utxo in inputs {
        verify_prevout(state, utxo).await?;
    }
    Ok(Json(assemble(
        state,
        &contract,
        position,
        proof,
        fee,
        program,
        tick.zip(tick_program),
        spend,
        destination,
        auth,
    )?))
}

fn assemble(
    state: &AppState,
    contract: &PriceMarketContract,
    position: UTXO,
    proof: UTXO,
    fee: UTXO,
    voucher: VoucherProgram,
    tick: Option<(UTXO, VoucherProgram)>,
    spend: PriceMarketSpend,
    destination: Script,
    change: Script,
) -> Result<RedemptionResponse, ApiError> {
    let mut transaction = FinalTransaction::new();
    contract.attach_spend(&mut transaction, &position, spend);
    let fee_index = if tick.is_some() { 3 } else { 2 };
    let path = VoucherSpendPath::ScriptAuth {
        auth_input_index: fee_index,
        voucher_output_index: 1,
    };
    transaction.add_program_input(
        PartialInput::new(proof.clone()),
        ProgramInput::new(Box::new(voucher.as_ref().clone()), path.build_witness()),
        RequiredSignature::None,
    );
    if let Some((tick, program)) = &tick {
        transaction.add_program_input(
            PartialInput::new(tick.clone()),
            ProgramInput::new(
                Box::new(program.as_ref().clone()),
                VoucherSpendPath::ScriptAuth {
                    auth_input_index: fee_index,
                    voucher_output_index: 2,
                }
                .build_witness(),
            ),
            RequiredSignature::None,
        );
    }
    transaction.add_input(
        PartialInput::new(fee.clone()),
        RequiredSignature::NativeEcdsa,
    );
    transaction.add_output(PartialOutput::new(
        destination,
        position.explicit_amount(),
        position.explicit_asset(),
    ));
    transaction.add_output(PartialOutput::new(
        Voucher::get_burn_script(1),
        proof.explicit_amount(),
        proof.explicit_asset(),
    ));
    if let Some((tick, _)) = &tick {
        transaction.add_output(PartialOutput::new(
            Voucher::get_burn_script(2),
            tick.explicit_amount(),
            tick.explicit_asset(),
        ));
    }
    transaction.add_output(PartialOutput::new(
        change,
        fee.explicit_amount() - 1000,
        state.network.policy_asset(),
    ));
    transaction.add_output(PartialOutput::new(
        Script::new(),
        1000,
        state.network.policy_asset(),
    ));
    let (mut pset, _) = transaction.extract_pst();
    for index in 0..fee_index as usize {
        let input = transaction.inputs()[index]
            .program_input
            .as_ref()
            .expect("covenant input");
        let witness = input
            .program
            .finalize(&pset, &input.witness, index, &state.network)
            .map_err(|error| ApiError::bad_request(format!("covenant input {index}: {error}")))?;
        pset.inputs_mut()[index].final_script_witness = Some(witness.into());
    }
    for input in pset.inputs_mut() {
        input.amount = None;
        input.asset = None;
    }
    pset.inputs_mut()[fee_index as usize].sighash_type = Some(EcdsaSighashType::All.into());
    Ok(RedemptionResponse {
        tick_signature_hash: String::new(),
        pset: Some(pset.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn coordinator_trust_is_explicit_refreshes_metadata_and_fails_closed() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let metadata = serde_json::json!({
            "network": "elementsregtest",
            "storm_eye_asset_id": "55".repeat(32),
            "tick_asset_id": "33".repeat(32),
            "oracle_verifier_asset_id": "44".repeat(32),
            "storm_tree_root": "77".repeat(32),
        });
        let response = Arc::new(RwLock::new((StatusCode::OK, metadata.clone())));
        let calls = Arc::new(AtomicUsize::new(0));
        let response_state = response.clone();
        let request_count = calls.clone();
        let oracle = Router::new().route(
            "/users/network",
            get(move || {
                let response = response_state.clone();
                let calls = request_count.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let (status, metadata) = response.read().await.clone();
                    (status, Json(metadata))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = super::super::tests::config();
        config.oracle_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, oracle).await.unwrap() });
        let request = || VerificationRequest {
            owner_public_key: super::super::tests::HOLDER_PUBLIC_KEY.into(),
            auth_script_pubkey: format!("0014{}", "11".repeat(20)),
        };

        let app = App::new(config.clone()).await.unwrap();
        assert!(
            verification(State(app.state), Json(request()))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        config.oracle_verification = Some(OracleVerificationConfig {
            storm_eye_asset_id: "55".repeat(32),
            tick_asset_id: "33".repeat(32),
            verifier_asset_id: "44".repeat(32),
            storm_tree_root: "77".repeat(32),
        });
        let pinned_app = App::new(config.clone()).await.unwrap();
        let Json(pinned_context) = verification(State(pinned_app.state), Json(request()))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        config.trust_coordinator = true;
        assert!(matches!(
            App::new(config.clone()).await,
            Err(AppError::ConflictingOracleTrust)
        ));
        config.oracle_verification = None;
        let app = App::new(config).await.unwrap();
        let Json(context) = verification(State(app.state.clone()), Json(request()))
            .await
            .unwrap();
        assert_eq!(context, pinned_context);
        assert_eq!(context["stormTreeRoot"], "77".repeat(32));
        assert_eq!(context["tickAssetId"], "33".repeat(32));
        assert_eq!(context["verifierAssetId"], "44".repeat(32));
        assert_eq!(context["accountTapleafHash"].as_str().unwrap().len(), 64);
        let mut updated = metadata.clone();
        updated["storm_tree_root"] = "88".repeat(32).into();
        *response.write().await = (StatusCode::OK, updated);
        let Json(context) = verification(State(app.state.clone()), Json(request()))
            .await
            .unwrap();
        assert_eq!(context["stormTreeRoot"], "88".repeat(32));

        for (field, value) in [
            ("storm_tree_root", serde_json::Value::Null),
            ("storm_tree_root", "invalid".into()),
            ("network", "liquidtestnet".into()),
            ("tick_asset_id", "invalid".into()),
        ] {
            let mut invalid = metadata.clone();
            invalid[field] = value;
            *response.write().await = (StatusCode::OK, invalid);
            assert!(
                verification(State(app.state.clone()), Json(request()))
                    .await
                    .is_err(),
                "{field}"
            );
        }
        *response.write().await = (StatusCode::SERVICE_UNAVAILABLE, metadata);
        assert!(
            verification(State(app.state.clone()), Json(request()))
                .await
                .is_err()
        );
        task.abort();
        assert!(
            verification(State(app.state), Json(request()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verification_uses_configured_anchors_and_locally_compiled_leaves() {
        use price_oracle_contracts::account::{Account, AccountParameters};

        let mut config = super::super::tests::config();
        let request = || VerificationRequest {
            owner_public_key: super::super::tests::HOLDER_PUBLIC_KEY.into(),
            auth_script_pubkey: format!("0014{}", "11".repeat(20)),
        };
        let app = App::new(config.clone()).await.unwrap();
        assert!(
            verification(State(app.state), Json(request()))
                .await
                .is_err()
        );

        config.oracle_verification = Some(OracleVerificationConfig {
            storm_eye_asset_id: "55".repeat(32),
            tick_asset_id: "33".repeat(32),
            verifier_asset_id: "44".repeat(32),
            storm_tree_root: "77".repeat(32),
        });
        let app = App::new(config).await.unwrap();
        let Json(context) = verification(State(app.state.clone()), Json(request()))
            .await
            .unwrap();
        let account = Account::new(AccountParameters {
            storm_eye_asset_id: parse_asset(&"55".repeat(32), "asset").unwrap(),
            account_owner_pubkey: parse_hex_array::<32>(&request().owner_public_key, "owner")
                .unwrap(),
            network: app.state.network,
        });
        assert_eq!(context["stormTreeRoot"], "77".repeat(32));
        assert_eq!(context["tickAssetId"], "33".repeat(32));
        assert_eq!(context["verifierAssetId"], "44".repeat(32));
        assert_eq!(context["accountTapleafHash"].as_str().unwrap().len(), 64);
        assert!(!account.get_script_pubkey().is_empty());

        let mut invalid = request();
        invalid.auth_script_pubkey = "51".into();
        assert!(
            verification(State(app.state.clone()), Json(invalid))
                .await
                .is_err()
        );
        let mut metadata = OracleAccount {
            tick_asset_id: "33".repeat(32),
            oracle_verifier_asset_id: "44".repeat(32),
            storm_eye_asset_id: "55".repeat(32),
            network: "elementsregtest".into(),
        };
        metadata = validate_network(&app.state, metadata).unwrap();
        metadata.tick_asset_id = "66".repeat(32);
        assert!(validate_network(&app.state, metadata).is_err());
    }
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use simplex::simplicityhl::elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey};
    use tower::ServiceExt;

    fn terms() -> PriceMarket {
        PriceMarket {
            feed_id: 0,
            decimals: 8,
            strike: "100".into(),
            above: true,
            opens_at: 1000,
            claim_grace: 600,
            house_script_pubkey: "00141111111111111111111111111111111111111111".into(),
            tick_asset_id: "22".repeat(32),
            verifier_asset_id: "33".repeat(32),
            storm_eye_asset_id: "44".repeat(32),
        }
    }

    fn signed(data: PriceFeedData) -> SignedPriceRequest {
        let secp = Secp256k1::new();
        let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
        SignedPriceRequest {
            price_data: hex::encode(data.to_bytes()),
            signer: hex::encode(key.x_only_public_key().0.serialize()),
            signature: hex::encode(
                secp.sign_schnorr_no_aux_rand(
                    &Message::from_digest(SignedPrice::message_for(&data)),
                    &key,
                )
                .serialize(),
            ),
        }
    }

    #[test]
    fn verifies_price_signature_and_market_terms() {
        let data = PriceFeedData {
            feed_id: 0,
            decimals: 8,
            price: 100,
            received_at: 1050,
            valid_until: 1350,
        };
        assert!(signed_price(&signed(data), &terms(), 1100).is_ok());
        for data in [
            PriceFeedData { price: 99, ..data },
            PriceFeedData { feed_id: 1, ..data },
            PriceFeedData {
                received_at: 1101,
                ..data
            },
            PriceFeedData {
                decimals: 9,
                ..data
            },
        ] {
            assert!(signed_price(&signed(data), &terms(), 1100).is_err());
        }
        let mut tampered = signed(data);
        tampered.price_data = hex::encode(PriceFeedData { price: 101, ..data }.to_bytes());
        assert!(signed_price(&tampered, &terms(), 1100).is_err());
    }

    #[test]
    fn relay_accepts_only_network_vouchers() {
        let policy = parse_asset(&"66".repeat(32), "policy").unwrap();
        let tick = parse_asset(&terms().tick_asset_id, "tick").unwrap();
        let verifier = parse_asset(&terms().verifier_asset_id, "verifier").unwrap();
        let mut output = TxOut {
            asset: Asset::Explicit(verifier),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Voucher::get_burn_script(1),
            witness: TxOutWitness::default(),
        };
        assert_eq!(
            voucher_burn_allowance(&[output.clone()], policy, tick, verifier).unwrap(),
            1
        );
        output.value = Value::Explicit(2);
        assert!(voucher_burn_allowance(&[output.clone()], policy, tick, verifier).is_err());
        output.asset = Asset::Explicit(parse_asset(&"99".repeat(32), "fake").unwrap());
        assert!(voucher_burn_allowance(&[output.clone()], policy, tick, verifier).is_err());
        output.asset = Asset::Explicit(tick);
        assert_eq!(
            voucher_burn_allowance(&[output], policy, tick, verifier).unwrap(),
            2
        );
    }

    #[test]
    fn relay_accepts_only_the_uniquely_tagged_tick_and_verifier_pair() {
        let policy = parse_asset(&"66".repeat(32), "policy").unwrap();
        let tick = parse_asset(&terms().tick_asset_id, "tick").unwrap();
        let verifier = parse_asset(&terms().verifier_asset_id, "verifier").unwrap();
        let proof = TxOut {
            asset: Asset::Explicit(verifier),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Voucher::get_burn_script(1),
            witness: TxOutWitness::default(),
        };
        let time = TxOut {
            asset: Asset::Explicit(tick),
            value: Value::Explicit(1050),
            nonce: Nonce::Null,
            script_pubkey: Voucher::get_burn_script(2),
            witness: TxOutWitness::default(),
        };
        assert_eq!(
            voucher_burn_allowance(&[proof.clone(), time.clone()], policy, tick, verifier).unwrap(),
            1051
        );
        assert!(voucher_burn_allowance(&[time.clone()], policy, tick, verifier).is_err());
        for invalid in [
            TxOut {
                script_pubkey: Voucher::get_burn_script(1),
                ..time.clone()
            },
            TxOut {
                asset: Asset::Explicit(verifier),
                ..time.clone()
            },
            TxOut {
                asset: Asset::Explicit(policy),
                ..time.clone()
            },
            TxOut {
                value: Value::Explicit(u64::from(u32::MAX) + 1),
                ..time.clone()
            },
            TxOut {
                script_pubkey: Voucher::get_burn_script(3),
                ..time.clone()
            },
        ] {
            assert!(
                voucher_burn_allowance(&[proof.clone(), invalid], policy, tick, verifier).is_err()
            );
        }
        assert!(
            voucher_burn_allowance(&[proof, time.clone(), time], policy, tick, verifier).is_err()
        );
    }

    #[test]
    fn tick_validity_matches_the_extended_covenant_window() {
        let data = PriceFeedData {
            feed_id: 0,
            decimals: 8,
            price: 100,
            received_at: 1050,
            valid_until: 1350,
        };
        let signed = signed_price(&signed(data), &terms(), 1100).unwrap();
        let mut tick = UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([0; 32]), 2),
            txout: TxOut {
                asset: Asset::Explicit(parse_asset(&terms().tick_asset_id, "tick").unwrap()),
                value: Value::Explicit(1050),
                nonce: Nonce::Null,
                script_pubkey: Script::new(),
                witness: TxOutWitness::default(),
            },
            secrets: None,
        };
        for time in [1050, 1350, 4649] {
            tick.txout.value = Value::Explicit(time);
            assert!(verify_claim_tick(&tick, &signed, &terms()).is_ok());
        }
        for time in [1049, 4650, 4651] {
            tick.txout.value = Value::Explicit(time);
            assert!(verify_claim_tick(&tick, &signed, &terms()).is_err());
        }
        tick.txout.value = Value::Explicit(1050);
        tick.txout.asset = Asset::Explicit(parse_asset(&"99".repeat(32), "fake").unwrap());
        assert!(verify_claim_tick(&tick, &signed, &terms()).is_err());
        tick.txout.asset = Asset::Explicit(parse_asset(&terms().tick_asset_id, "tick").unwrap());
        let overflow = signed_price(
            &self::signed(PriceFeedData {
                valid_until: u64::MAX,
                ..data
            }),
            &terms(),
            1100,
        )
        .unwrap();
        assert!(verify_claim_tick(&tick, &overflow, &terms()).is_err());
    }

    #[tokio::test]
    async fn assembles_price_claim_and_house_sweep_psets() {
        let app = App::new(super::super::tests::config()).await.unwrap();
        let market = Prediction {
            id: "77".repeat(32),
            title: "Touch".into(),
            created_at: 1000,
            deadline: 1100,
            price: terms(),
        };
        let payout =
            parse_script("00145555555555555555555555555555555555555555", "wallet").unwrap();
        let policy = app.state.network.policy_asset();
        let utxo = |asset, amount, script, vout| UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([0; 32]), vout),
            txout: TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(amount),
                nonce: Nonce::Null,
                script_pubkey: script,
                witness: TxOutWitness::default(),
            },
            secrets: None,
        };
        let data = signed(PriceFeedData {
            feed_id: 0,
            decimals: 8,
            price: 100,
            received_at: 1050,
            valid_until: 1350,
        });
        let signed = signed_price(&data, &terms(), market.deadline).unwrap();
        let terms = terms();
        for sweep in [false, true] {
            let contract = contract(&app.state, &market, &payout).unwrap();
            let destination = if sweep {
                parse_script(&terms.house_script_pubkey, "house").unwrap()
            } else {
                payout.clone()
            };
            let mut voucher = VoucherProgram::new(
                VoucherParameters {
                    storm_eye_asset_id: parse_asset(&terms.storm_eye_asset_id, "storm").unwrap(),
                    auth_method: VoucherAuthMethod::Script {
                        auth_script_hash: hash_script(&destination),
                    },
                    network: app.state.network,
                }
                .build_arguments(),
            );
            if !sweep {
                voucher = voucher
                    .with_taproot_pubkey(XOnlyPublicKey::from_slice(&signed.get_signer()).unwrap());
            }
            let proof_amount = if sweep { 1701 } else { 1 };
            let proof_asset = parse_asset(
                if sweep {
                    &terms.tick_asset_id
                } else {
                    &terms.verifier_asset_id
                },
                "proof",
            )
            .unwrap();
            let spend = if sweep {
                PriceMarketSpend::Sweep {
                    tick_input_index: 1,
                    house_output_index: 0,
                }
            } else {
                PriceMarketSpend::ClaimWithTick {
                    tick_input_index: 2,
                    verifier_input_index: 1,
                    verifier_tapleaf_hash: voucher.get_tapleaf_hash(),
                    signed,
                    payout_output_index: 0,
                }
            };
            let proof = utxo(
                proof_asset,
                proof_amount,
                voucher.get_script_pubkey(&app.state.network),
                1,
            );
            let tick = if !sweep {
                let program = VoucherProgram::new(
                    VoucherParameters {
                        storm_eye_asset_id: parse_asset(&terms.storm_eye_asset_id, "storm")
                            .unwrap(),
                        auth_method: VoucherAuthMethod::Script {
                            auth_script_hash: hash_script(&destination),
                        },
                        network: app.state.network,
                    }
                    .build_arguments(),
                );
                Some((
                    utxo(
                        parse_asset(&terms.tick_asset_id, "tick").unwrap(),
                        1050,
                        program.get_script_pubkey(&app.state.network),
                        2,
                    ),
                    program,
                ))
            } else {
                None
            };
            let fee_index = if tick.is_some() { 3 } else { 2 };
            let response = assemble(
                &app.state,
                &contract,
                utxo(policy, 50000, contract.get_script_pubkey(), 0),
                proof,
                utxo(policy, 2000, destination.clone(), fee_index),
                voucher,
                tick,
                spend,
                destination.clone(),
                destination,
            )
            .unwrap();
            let pset: simplex::simplicityhl::elements::pset::PartiallySignedTransaction =
                response.pset.unwrap().parse().unwrap();
            assert!(pset.inputs()[0].final_script_witness.is_some());
            assert!(pset.inputs()[1].final_script_witness.is_some());
            assert!(
                pset.inputs()[fee_index as usize]
                    .final_script_witness
                    .is_none()
            );
            if fee_index == 3 {
                assert!(pset.inputs()[2].final_script_witness.is_some());
                assert_eq!(pset.outputs()[2].amount, Some(1050));
                assert_eq!(pset.outputs()[2].script_pubkey, Voucher::get_burn_script(2));
            }
            assert_eq!(pset.outputs()[1].amount, Some(proof_amount));
            assert_eq!(pset.outputs()[1].script_pubkey, Voucher::get_burn_script(1));
        }
    }

    #[test]
    fn predictions_require_price_terms() {
        assert!(
            serde_json::from_value::<Prediction>(serde_json::json!({
                "id": "77".repeat(32), "title": "Missing price terms",
                "deadline": 1100, "created_at": 1000,
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn oracle_accounts_must_match_the_configured_chain() {
        for (oracle_network, testnet, wrong_genesis, accepted) in [
            ("elementsregtest", false, false, true),
            ("liquidtestnet", true, false, true),
            ("liquidtestnet", false, false, false),
            ("elementsregtest", true, false, false),
            ("liquidtestnet", true, true, false),
            ("liquid", true, false, false),
        ] {
            let metadata = move || async move {
                Json(serde_json::json!({
                    "network": oracle_network,
                    "tick_asset_id": "22".repeat(32),
                    "oracle_verifier_asset_id": "33".repeat(32),
                    "storm_eye_asset_id": "44".repeat(32),
                }))
            };
            let oracle = Router::new()
                .route("/users/network", get(metadata))
                .route("/users/account/{owner}", get(metadata));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = super::super::tests::config();
            config.oracle_url = format!("http://{}", listener.local_addr().unwrap());
            if testnet {
                let network = SimplicityNetwork::LiquidTestnet;
                config.policy_asset_id = network.policy_asset().to_string();
                config.genesis_block_hash = network.genesis_block_hash().to_string();
            }
            if wrong_genesis {
                config.genesis_block_hash = "00".repeat(32);
            }
            let task = tokio::spawn(async move { axum::serve(listener, oracle).await.unwrap() });
            let app = App::new(config).await.unwrap();
            let result = account(&app.state, crate::tests::HOLDER_PUBLIC_KEY).await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "{oracle_network}, testnet={testnet}, wrong_genesis={wrong_genesis}"
            );
            assert_eq!(network(&app.state).await.is_ok(), accepted);
            task.abort();
        }
    }

    #[tokio::test]
    async fn network_metadata_rejects_missing_or_invalid_network_endpoint() {
        let metadata = serde_json::json!({
            "network": "elementsregtest",
            "tick_asset_id": "22".repeat(32),
            "oracle_verifier_asset_id": "33".repeat(32),
            "storm_eye_asset_id": "44".repeat(32),
        });
        let response = Arc::new(RwLock::new((StatusCode::NOT_FOUND, metadata.clone())));
        let response_state = response.clone();
        let owners = Arc::new(RwLock::new(Vec::<String>::new()));
        let requested_owners = owners.clone();
        let account_metadata = metadata.clone();
        let oracle = Router::new()
            .route(
                "/users/network",
                get(move || {
                    let response = response_state.clone();
                    async move {
                        let (status, metadata) = response.read().await.clone();
                        (status, Json(metadata))
                    }
                }),
            )
            .route(
                "/users/account/{owner}",
                get(move |AxumPath(owner): AxumPath<String>| {
                    let owners = requested_owners.clone();
                    let metadata = account_metadata.clone();
                    async move {
                        owners.write().await.push(owner);
                        Json(metadata)
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = super::super::tests::config();
        config.oracle_url = format!("http://{}", listener.local_addr().unwrap());
        let directory = std::env::temp_dir().join(format!("network-metadata-{}", Uuid::new_v4()));
        config.escrow = Some(
            serde_json::from_value(serde_json::json!({
                "private_key_file": directory.join("reserve.hex"),
                "max_stake_sats": 1000000,
            }))
            .unwrap(),
        );
        let task = tokio::spawn(async move { axum::serve(listener, oracle).await.unwrap() });
        let app = App::new(config.clone()).await.unwrap();

        assert!(network(&app.state).await.is_err());
        assert!(owners.read().await.is_empty());

        config.escrow = None;
        let no_wallet = App::new(config).await.unwrap();
        assert!(network(&no_wallet.state).await.is_err());
        assert!(owners.read().await.is_empty());

        for (status, body) in [
            (StatusCode::SERVICE_UNAVAILABLE, metadata.clone()),
            (
                StatusCode::OK,
                serde_json::json!({ "network": "elementsregtest" }),
            ),
            (
                StatusCode::OK,
                serde_json::json!({
                    "network": "liquidtestnet",
                    "tick_asset_id": "22".repeat(32),
                    "oracle_verifier_asset_id": "33".repeat(32),
                    "storm_eye_asset_id": "44".repeat(32),
                }),
            ),
            (
                StatusCode::OK,
                serde_json::json!({
                    "network": "elementsregtest",
                    "tick_asset_id": "invalid",
                    "oracle_verifier_asset_id": "33".repeat(32),
                    "storm_eye_asset_id": "44".repeat(32),
                }),
            ),
        ] {
            *response.write().await = (status, body);
            assert!(network(&app.state).await.is_err());
            assert!(owners.read().await.is_empty());
        }

        *response.write().await = (StatusCode::OK, metadata);
        assert!(network(&no_wallet.state).await.is_ok());
        assert!(owners.read().await.is_empty());
        task.abort();
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[test]
    fn automatic_strikes_require_one_percent_in_either_direction() {
        assert_eq!(automatic_strike(100000, true).unwrap(), 101000);
        assert_eq!(automatic_strike(100000, false).unwrap(), 99000);
        assert_eq!(automatic_strike(110001, true).unwrap(), 111102);
        assert_eq!(automatic_strike(110001, false).unwrap(), 108900);
        assert!(automatic_strike(u64::MAX, true).is_err());
        assert_eq!(
            automatic_strike(u64::MAX, false).unwrap(),
            (u128::from(u64::MAX) * 99 / 100) as u64,
        );
    }

    #[tokio::test]
    async fn automatic_publication_retries_and_persists_twelve_hour_slots() {
        let latest = Arc::new(RwLock::new(serde_json::json!({ "main": null })));
        let latest_response = latest.clone();
        let oracle = Router::new()
            .route(
                "/price-feeds",
                get(|| async { Json(serde_json::json!([{ "id": 0, "decimals": 8 }])) }),
            )
            .route(
                "/price-feeds/{id}",
                get(move || {
                    let latest = latest_response.clone();
                    async move { Json(latest.read().await.clone()) }
                }),
            )
            .route(
                "/users/network",
                get(|| async {
                    Json(serde_json::json!({
                        "network": "elementsregtest",
                        "tick_asset_id": "22".repeat(32),
                        "oracle_verifier_asset_id": "33".repeat(32),
                        "storm_eye_asset_id": "44".repeat(32),
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let directory = std::env::temp_dir().join(format!("auto-publish-{}", Uuid::new_v4()));
        let mut config = super::super::tests::config();
        config.database_url = format!(
            "sqlite://{}/predictions.sqlite3?mode=rwc",
            directory.display()
        );
        config.oracle_url = format!("http://{}", listener.local_addr().unwrap());
        config.auto_publish.enabled = true;
        config.escrow = Some(
            serde_json::from_value(serde_json::json!({
                "private_key_file": directory.join("escrow-private-key.hex"),
                "max_stake_sats": 1000000,
            }))
            .unwrap(),
        );
        let task = tokio::spawn(async move { axum::serve(listener, oracle).await.unwrap() });
        let app = App::new(config.clone()).await.unwrap();
        let now = 43_201;

        assert!(publish_scheduled(&app.state, now).await.is_err());
        assert!(app.state.db.list().await.unwrap().is_empty());
        *latest.write().await = serde_json::json!({ "main": { "feed": {
            "feed_id": 0, "price": 100000, "decimals": 8,
            "received_at": now - 1, "valid_until": now + 300,
        } } });
        let (first, second) = tokio::join!(
            publish_scheduled(&app.state, now),
            publish_scheduled(&app.state, now),
        );
        assert_ne!(first.unwrap(), second.unwrap());
        let predictions = app.state.db.list().await.unwrap();
        assert_eq!(predictions.len(), 1);
        let prediction = &predictions[0];
        assert_eq!(prediction.deadline, 86_400);
        assert_eq!(prediction.created_at, now);
        let price = &prediction.price;
        assert_eq!(price.strike, if price.above { "101000" } else { "99000" });
        assert_eq!(
            prediction.title,
            format!(
                "BTC/USD reaches {}1% by 00:00 UTC",
                if price.above { "+" } else { "-" },
            ),
        );
        assert_eq!(price.opens_at, now);
        assert_eq!(price.claim_grace, 600);
        assert_eq!(
            price.house_script_pubkey,
            hex::encode(
                app.state
                    .reserve_wallet
                    .as_ref()
                    .unwrap()
                    .script_pubkey()
                    .as_bytes(),
            )
        );

        let restored = App::new(config.clone()).await.unwrap();
        assert!(!publish_scheduled(&restored.state, now + 60).await.unwrap());
        assert!(!publish_scheduled(&restored.state, 64_800).await.unwrap());
        assert_eq!(restored.state.db.list().await.unwrap(), predictions);

        assert!(publish_scheduled(&restored.state, 86_400).await.is_err());
        assert_eq!(restored.state.db.list().await.unwrap().len(), 1);
        *latest.write().await = serde_json::json!({ "main": { "feed": {
            "feed_id": 0, "price": 110001, "decimals": 8,
            "received_at": 86_400, "valid_until": 86_700,
        } } });
        assert!(publish_scheduled(&restored.state, 86_400).await.unwrap());
        let predictions = restored.state.db.list().await.unwrap();
        assert_eq!(predictions.len(), 2);
        assert_eq!(predictions[1].deadline, 129_600);
        let price = &predictions[1].price;
        assert_eq!(price.strike, if price.above { "111102" } else { "108900" });
        assert_eq!(
            predictions[1].title,
            format!(
                "BTC/USD reaches {}1% by 12:00 UTC",
                if price.above { "+" } else { "-" },
            ),
        );

        config.auto_publish.enabled = false;
        let disabled = App::new(config).await.unwrap();
        assert!(!publish_scheduled(&disabled.state, 129_600).await.unwrap());
        assert_eq!(disabled.state.db.list().await.unwrap(), predictions);
        task.abort();
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[tokio::test]
    async fn publishes_immutable_price_terms_and_disallows_admin_resolution() {
        let metadata = || async {
            let terms = terms();
            Json(serde_json::json!({
                "network": "elementsregtest",
                "tick_asset_id": terms.tick_asset_id,
                "oracle_verifier_asset_id": terms.verifier_asset_id,
                "storm_eye_asset_id": terms.storm_eye_asset_id,
            }))
        };
        let oracle = Router::new()
            .route(
                "/price-feeds",
                get(|| async { Json(serde_json::json!([{ "id": 0, "decimals": 8 }])) }),
            )
            .route("/users/network", get(metadata))
            .route("/users/account/{owner}", get(metadata));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, oracle).await.unwrap() });
        let path = std::env::temp_dir().join(format!("price-publish-{}.sqlite3", Uuid::new_v4()));
        let mut config = super::super::tests::config();
        config.database_url = format!("sqlite://{}?mode=rwc", path.display());
        config.oracle_url = url;
        let app = App::new(config).await.unwrap();
        let now = unix_time().unwrap();
        app.state
            .sessions
            .write()
            .await
            .insert("test-session".into(), now + 3600);
        let router = app.router();
        let request = |uri: &str, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-session")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        };
        let body = serde_json::json!({ "title": "Oracle touch", "deadline": now + 3600, "price": { "feed_id": 0, "strike": "10000000000", "above": true, "opens_at": now, "claim_grace": 600,
            "house_script_pubkey": terms().house_script_pubkey } });
        let mut invalid = body.clone();
        invalid["price"]["feed_id"] = serde_json::json!(999);
        assert_eq!(
            router
                .clone()
                .oneshot(request("/api/admin/predictions", invalid))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let response = router
            .clone()
            .oneshot(request("/api/admin/predictions", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let prediction: Prediction = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            prediction.price.verifier_asset_id,
            terms().verifier_asset_id
        );
        let derive = serde_json::json!({ "payout_script_pubkey": "00145555555555555555555555555555555555555555", "owner_public_key": crate::tests::HOLDER_PUBLIC_KEY });
        let derived = router
            .clone()
            .oneshot(request(
                &format!("/api/predictions/{}/contract", prediction.id),
                derive,
            ))
            .await
            .unwrap();
        assert_eq!(derived.status(), StatusCode::OK);
        let derived: serde_json::Value =
            serde_json::from_slice(&derived.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let payout =
            parse_script("00145555555555555555555555555555555555555555", "wallet").unwrap();
        let expected = contract(&app.state, &prediction, &payout)
            .unwrap()
            .get_script_pubkey();
        assert_eq!(
            derived,
            serde_json::json!({ "script_pubkey": hex::encode(expected.as_bytes()) })
        );
        assert_eq!(
            router
                .oneshot(request(
                    &format!("/api/admin/predictions/{}/resolve", prediction.id),
                    serde_json::json!({ "occurred_at": now })
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let restored = App::new(app.state.config.clone()).await.unwrap();
        assert_eq!(
            restored
                .state
                .db
                .find(&prediction.id)
                .await
                .unwrap()
                .unwrap(),
            prediction
        );
        tokio::fs::remove_file(path).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn checks_confirmed_chain_prevouts_and_sweep_authentication() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let spent = Arc::new(AtomicBool::new(false));
        let flag = spent.clone();
        let chain = Router::new()
            .route("/tx/{txid}", get(|| async { Json(serde_json::json!({ "status": { "confirmed": true }, "vout": [{ "scriptpubkey": "51", "value": 50000, "asset": "66".repeat(32) }] })) }))
            .route("/tx/{txid}/outspend/{vout}", get(move || { let flag = flag.clone(); async move { Json(serde_json::json!({ "spent": flag.load(Ordering::Relaxed) })) } }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, chain).await.unwrap() });
        let mut config = super::super::tests::config();
        config.chain_backend.esplora_url = url;
        let app = App::new(config).await.unwrap();
        let utxo = UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([0; 32]), 0),
            txout: TxOut {
                asset: Asset::Explicit(app.state.network.policy_asset()),
                value: Value::Explicit(50000),
                nonce: Nonce::Null,
                script_pubkey: Script::from(vec![0x51]),
                witness: TxOutWitness::default(),
            },
            secrets: None,
        };
        assert!(verify_prevout(&app.state, &utxo).await.is_ok());
        let mut forged = utxo.clone();
        forged.txout.value = Value::Explicit(50001);
        assert!(verify_prevout(&app.state, &forged).await.is_err());
        spent.store(true, Ordering::Relaxed);
        assert_eq!(
            verify_prevout(&app.state, &utxo).await.unwrap_err().status,
            StatusCode::CONFLICT
        );
        let input = serde_json::json!({ "txid": "00".repeat(32), "vout": 0, "script_pubkey": "51", "amount_sats": 50000, "asset": "66".repeat(32) });
        let response = app.router().oneshot(Request::builder().method("POST").uri(format!("/api/predictions/{}/sweep", "77".repeat(32))).header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&serde_json::json!({ "position": input, "voucher": input, "fee": input, "payout_script_pubkey": "51", "auth_script_pubkey": "51" })).unwrap())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        task.abort();
    }
}
