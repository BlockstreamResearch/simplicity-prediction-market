use super::*;
use prediction_demo_contracts::{PriceMarketContract, PriceMarketParameters, PriceMarketSpend};
use price_feed::PriceFeedData;
use price_oracle_contracts::sdk::SignedPrice;
use simplex::simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;

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
    owner_public_key: String,
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

async fn oracle_json(state: &AppState, path: &str) -> Result<serde_json::Value, ApiError> {
    let response = state
        .chain_client
        .get(format!(
            "{}{path}",
            state.config.oracle_url.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|_| ApiError::internal("oracle unavailable"))?;
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
    let account: OracleAccount =
        serde_json::from_value(oracle_json(state, &format!("/users/account/{owner}")).await?)
            .map_err(|_| ApiError::internal("invalid oracle account"))?;
    if account.network != state.oracle_network() {
        return Err(ApiError::bad_request(
            "oracle network does not match the configured prediction chain",
        ));
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
    let account = account(state, &request.owner_public_key).await?;
    for (value, name) in [
        (&account.tick_asset_id, "Tick asset"),
        (&account.oracle_verifier_asset_id, "Verifier asset"),
        (&account.storm_eye_asset_id, "Storm Eye asset"),
    ] {
        parse_asset(value, name)?;
    }
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
    requires_tick: bool,
) -> Result<PriceMarketContract, ApiError> {
    let terms = prediction
        .price
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("not a price market"))?;
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
    Ok(if requires_tick {
        PriceMarketContract::new_with_tick(parameters)
    } else {
        PriceMarketContract::new(parameters)
    })
}

pub(super) async fn derive(
    state: &AppState,
    prediction: &Prediction,
    request: &DeriveContractRequest,
) -> Result<Json<DerivedContract>, ApiError> {
    let terms = prediction.price.as_ref().expect("checked price market");
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
            contract(state, prediction, &payout, true)?
                .get_script_pubkey()
                .as_bytes(),
        ),
        tick_asset_id: terms.tick_asset_id.clone(),
        tick_script_pubkey: request.tick_script_pubkey.clone(),
        confidential_payout: false,
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
    let prediction = state
        .store
        .read()
        .await
        .predictions
        .iter()
        .find(|item| item.id == id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("prediction does not exist"))?;
    let terms = prediction
        .price
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("not a price market"))?;
    let payout = parse_script(&request.payout_script_pubkey, "position payout script")?;
    let auth = parse_script(&request.auth_script_pubkey, "voucher authorization script")?;
    let position = parse_utxo(&request.position, "position")?;
    let proof = parse_utxo(&request.voucher, "voucher")?;
    let fee = parse_utxo(&request.fee, "fee")?;
    let mut contract = contract(state, &prediction, &payout, true)?;
    let legacy = position.txout.script_pubkey != contract.get_script_pubkey();
    if legacy {
        contract = self::contract(state, &prediction, &payout, false)?;
    }
    let requires_tick = !sweep && !legacy;
    let tick = if requires_tick {
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
    let mut program = VoucherProgram::new(&voucher_parameters.build_arguments());
    let tick_program = tick
        .as_ref()
        .map(|_| VoucherProgram::new(&voucher_parameters.build_arguments()));
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
        spend = if let Some(tick) = &tick {
            verify_claim_tick(tick, &signed, terms)?;
            PriceMarketSpend::ClaimWithTick {
                tick_input_index: 2,
                verifier_input_index: 1,
                verifier_tapleaf_hash: program.get_tapleaf_hash(),
                signed,
                payout_output_index: 0,
            }
        } else {
            PriceMarketSpend::Claim {
                verifier_input_index: 1,
                verifier_tapleaf_hash: program.get_tapleaf_hash(),
                signed,
                payout_output_index: 0,
            }
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
        ProgramInput::new(
            Box::new(voucher.as_ref().clone()),
            Box::new(path.build_witness()),
        ),
        RequiredSignature::None,
    );
    if let Some((tick, program)) = &tick {
        transaction.add_program_input(
            PartialInput::new(tick.clone()),
            ProgramInput::new(
                Box::new(program.as_ref().clone()),
                Box::new(
                    VoucherSpendPath::ScriptAuth {
                        auth_input_index: fee_index,
                        voucher_output_index: 2,
                    }
                    .build_witness(),
                ),
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
            .finalize(&pset, &input.witness.build_witness(), index, &state.network)
            .map_err(|error| ApiError::bad_request(format!("covenant input {index}: {error}")))?;
        pset.inputs_mut()[index].final_script_witness = Some(witness);
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
            outpoint: OutPoint::new(Txid::all_zeros(), 2),
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
        let app = App::new(super::super::tests::config(
            std::env::temp_dir().join(format!("price-{}.json", Uuid::new_v4())),
        ))
        .await
        .unwrap();
        let market = Prediction {
            id: "77".repeat(32),
            title: "Touch".into(),
            created_at: 1000,
            deadline: 1100,
            resolution: None,
            price: Some(terms()),
        };
        let payout =
            parse_script("00145555555555555555555555555555555555555555", "wallet").unwrap();
        let policy = app.state.network.policy_asset();
        let utxo = |asset, amount, script, vout| UTXO {
            outpoint: OutPoint::new(Txid::all_zeros(), vout),
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
        for (sweep, requires_tick) in [(false, false), (false, true), (true, true)] {
            let contract = contract(&app.state, &market, &payout, requires_tick).unwrap();
            let destination = if sweep {
                parse_script(&terms.house_script_pubkey, "house").unwrap()
            } else {
                payout.clone()
            };
            let mut voucher = VoucherProgram::new(
                &VoucherParameters {
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
            } else if requires_tick {
                PriceMarketSpend::ClaimWithTick {
                    tick_input_index: 2,
                    verifier_input_index: 1,
                    verifier_tapleaf_hash: voucher.get_tapleaf_hash(),
                    signed,
                    payout_output_index: 0,
                }
            } else {
                PriceMarketSpend::Claim {
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
            let tick = if !sweep && requires_tick {
                let program = VoucherProgram::new(
                    &VoucherParameters {
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
    fn old_predictions_deserialize_without_price_terms() {
        let prediction: Prediction = serde_json::from_value(serde_json::json!({ "id": "77".repeat(32), "title": "Legacy", "deadline": 1100, "created_at": 1000, "resolution": null })).unwrap();
        assert!(prediction.price.is_none());
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
            let oracle = Router::new().route(
                "/users/account/{owner}",
                get(move || async move {
                    Json(serde_json::json!({
                        "network": oracle_network,
                        "tick_asset_id": "22".repeat(32),
                        "oracle_verifier_asset_id": "33".repeat(32),
                        "storm_eye_asset_id": "44".repeat(32),
                    }))
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = super::super::tests::config(
                std::env::temp_dir().join(format!("oracle-network-{}.json", Uuid::new_v4())),
            );
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
            let result = account(&app.state, &app.state.admin_public_key).await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "{oracle_network}, testnet={testnet}, wrong_genesis={wrong_genesis}"
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn publishes_immutable_price_terms_and_disallows_admin_resolution() {
        let oracle = Router::new()
            .route("/price-feeds", get(|| async { Json(serde_json::json!([{ "id": 0, "decimals": 8 }])) }))
            .route("/users/account/{owner}", get(|| async { Json(serde_json::json!({ "network": "elementsregtest", "tick_asset_id": "22".repeat(32), "oracle_verifier_asset_id": "33".repeat(32), "storm_eye_asset_id": "44".repeat(32) })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, oracle).await.unwrap() });
        let path = std::env::temp_dir().join(format!("price-publish-{}.json", Uuid::new_v4()));
        let mut config = super::super::tests::config(path.clone());
        config.oracle_url = url;
        let app = App::new(config).await.unwrap();
        let now = unix_time().unwrap();
        app.state
            .store
            .write()
            .await
            .sessions
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
            "house_script_pubkey": terms().house_script_pubkey, "owner_public_key": app.state.admin_public_key } });
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
            prediction.price.as_ref().unwrap().verifier_asset_id,
            terms().verifier_asset_id
        );
        let derive = serde_json::json!({ "payout_script_pubkey": "00145555555555555555555555555555555555555555", "tick_asset_id": "99".repeat(32), "tick_script_pubkey": "51", "confidential_payout": true, "owner_public_key": app.state.admin_public_key });
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
        assert_eq!(derived["tick_asset_id"], terms().tick_asset_id);
        assert_eq!(derived["confidential_payout"], false);
        assert_eq!(
            router
                .oneshot(request(
                    &format!("/api/admin/predictions/{}/resolve", prediction.id),
                    serde_json::json!({ "occurred_at": now })
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let restored = App::new(app.state.config.clone()).await.unwrap();
        assert_eq!(restored.state.store.read().await.predictions[0], prediction);
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
        let mut config = super::super::tests::config(
            std::env::temp_dir().join(format!("price-chain-{}.json", Uuid::new_v4())),
        );
        config.chain_backend.esplora_url = url;
        let app = App::new(config).await.unwrap();
        let utxo = UTXO {
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
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
