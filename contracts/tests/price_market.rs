use prediction_demo_contracts::{PriceMarketContract, PriceMarketParameters, PriceMarketSpend};
use price_feed::PriceFeedData;
use price_oracle_contracts::sdk::SignedPrice;
use price_oracle_contracts::voucher::{
    Voucher, VoucherAuthMethod, VoucherParameters, VoucherSpendPath,
};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::confidential::{Asset, Nonce, Value};
use simplex::simplicityhl::elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey};
use simplex::simplicityhl::elements::{
    AssetId, BlockHash, OutPoint, Script, TxOut, TxOutWitness, Txid,
};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};
use simplex::utils::hash_script;

fn execute(data: PriceFeedData, above: bool, sweep: Option<u64>, defect: &str) -> bool {
    execute_with_tick(
        data,
        above,
        sweep,
        defect,
        sweep.is_none().then_some(data.received_at),
    )
}

fn execute_with_tick(
    data: PriceFeedData,
    above: bool,
    sweep: Option<u64>,
    defect: &str,
    claim_tick: Option<u64>,
) -> bool {
    let asset = |byte| AssetId::from_byte_array([byte; 32]);
    let network = SimplicityNetwork::ElementsCustom {
        policy_asset: asset(0x66),
        genesis_hash: BlockHash::from_byte_array([0; 32]),
    };
    let wallet = Script::from(vec![0x51]);
    let house = Script::from(vec![0x52]);
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
    let other = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2; 32]).unwrap());
    let verifier_key = if defect == "key" {
        other.x_only_public_key().0
    } else {
        key.x_only_public_key().0
    };
    let voucher_params = || VoucherParameters {
        storm_eye_asset_id: asset(0x44),
        auth_method: VoucherAuthMethod::Script {
            auth_script_hash: hash_script(&wallet),
        },
        network,
    };
    let voucher = if sweep.is_some() {
        Voucher::new(voucher_params())
    } else {
        Voucher::new_with_taproot_pubkey(voucher_params(), verifier_key)
    };
    let parameters = PriceMarketParameters {
        prediction_id: [7; 32],
        feed_id: 0,
        decimals: 8,
        strike: 100,
        above,
        opens_at: 1000,
        deadline: if defect == "overflow" { u64::MAX } else { 1100 },
        claim_grace: 600,
        verifier_asset_id: asset(0x33),
        tick_asset_id: asset(0x22),
        payout_script_hash: hash_script(&wallet),
        house_script_hash: hash_script(&house),
        network,
    };
    let contract = PriceMarketContract::new_with_tick(parameters);
    let utxo = |asset, value, script_pubkey, vout| UTXO {
        outpoint: OutPoint::new(Txid::from_byte_array([0; 32]), vout),
        txout: TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey,
            witness: TxOutWitness::default(),
        },
        secrets: None,
    };
    let mut signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(SignedPrice::message_for(&data)), &key)
        .serialize();
    if defect == "signature" {
        signature[0] ^= 1;
    }
    let spend = match sweep {
        Some(_) => PriceMarketSpend::Sweep {
            tick_input_index: 1,
            house_output_index: 0,
        },
        None => PriceMarketSpend::ClaimWithTick {
            tick_input_index: 2,
            verifier_input_index: 1,
            verifier_tapleaf_hash: if defect == "leaf" {
                [0; 32]
            } else {
                voucher.get_tapleaf_hash()
            },
            signed: SignedPrice::new(data, key.x_only_public_key().0.serialize(), signature),
            payout_output_index: 0,
        },
    };
    let mut transaction = FinalTransaction::new();
    contract.attach_spend(
        &mut transaction,
        &utxo(asset(0x66), 50000, contract.get_script_pubkey(), 0),
        spend,
    );
    let voucher_asset = if defect == "asset" {
        asset(0x55)
    } else if sweep.is_some() {
        asset(0x22)
    } else {
        asset(0x33)
    };
    let voucher_amount = sweep.unwrap_or(if defect == "amount" { 2 } else { 1 });
    let proof = utxo(
        voucher_asset,
        voucher_amount,
        voucher.get_script_pubkey(),
        1,
    );
    let fee_input_index = if claim_tick.is_some() { 3 } else { 2 };
    voucher.attach_spend(
        &mut transaction,
        &proof,
        VoucherSpendPath::ScriptAuth {
            auth_input_index: fee_input_index,
            voucher_output_index: 1,
        },
    );
    if let Some(time) = claim_tick {
        let tick = Voucher::new(voucher_params());
        tick.attach_spend(
            &mut transaction,
            &utxo(
                if defect == "tick_asset" {
                    asset(0x55)
                } else {
                    asset(0x22)
                },
                time,
                tick.get_script_pubkey(),
                2,
            ),
            VoucherSpendPath::ScriptAuth {
                auth_input_index: fee_input_index,
                voucher_output_index: 2,
            },
        );
    }
    transaction.add_input(
        PartialInput::new(utxo(asset(0x66), 2000, wallet.clone(), fee_input_index)),
        RequiredSignature::None,
    );
    let destination = if defect == "payout" {
        Script::from(vec![0x53])
    } else if sweep.is_some() {
        house
    } else {
        wallet
    };
    transaction.add_output(PartialOutput::new(
        destination,
        if defect == "value" { 49999 } else { 50000 },
        if defect == "payout_asset" {
            asset(0x55)
        } else {
            asset(0x66)
        },
    ));
    transaction.add_output(PartialOutput::new(
        Voucher::get_burn_script(if defect == "burn" { 2 } else { 1 }),
        voucher_amount,
        voucher_asset,
    ));
    if let Some(time) = claim_tick {
        transaction.add_output(PartialOutput::new(
            Voucher::get_burn_script(2),
            time,
            asset(0x22),
        ));
    }
    let (pset, _) = transaction.extract_pst();
    (0..fee_input_index as usize).all(|index| {
        let input = transaction.inputs()[index].program_input.as_ref().unwrap();
        input
            .program
            .finalize(&pset, &input.witness, index, &network)
            .is_ok()
    })
}

const PRICE: PriceFeedData = PriceFeedData {
    feed_id: 0,
    price: 100,
    decimals: 8,
    received_at: 1050,
    valid_until: 1350,
};

#[test]
fn accepts_touch_boundaries_and_historical_prices() {
    for received_at in [1000, 1050, 1100] {
        for above in [true, false] {
            assert!(execute(
                PriceFeedData {
                    received_at,
                    valid_until: received_at + 300,
                    ..PRICE
                },
                above,
                None,
                ""
            ));
        }
    }
}

#[test]
fn rejects_invalid_price_and_verifier_proofs() {
    for defect in [
        "key",
        "leaf",
        "asset",
        "amount",
        "signature",
        "payout",
        "value",
        "payout_asset",
        "burn",
    ] {
        assert!(!execute(PRICE, true, None, defect), "{defect}");
    }
    for data in [
        PriceFeedData { price: 99, ..PRICE },
        PriceFeedData {
            feed_id: 1,
            ..PRICE
        },
        PriceFeedData {
            decimals: 7,
            ..PRICE
        },
        PriceFeedData {
            received_at: 999,
            ..PRICE
        },
        PriceFeedData {
            received_at: 1101,
            ..PRICE
        },
    ] {
        assert!(!execute(data, true, None, ""));
    }
    assert!(!execute(
        PriceFeedData {
            price: 101,
            ..PRICE
        },
        false,
        None,
        ""
    ));
}

#[test]
fn sweep_requires_post_grace_tick_and_house_payout() {
    assert!(!execute(PRICE, true, Some(1700), ""));
    assert!(execute(PRICE, true, Some(1701), ""));
    assert!(!execute(PRICE, true, Some(u64::MAX), "overflow"));
    for defect in ["asset", "payout", "value", "payout_asset", "burn"] {
        assert!(!execute(PRICE, true, Some(1701), defect));
    }
}

#[test]
fn tick_claim_extends_signed_validity_by_exactly_fifty_five_minutes() {
    for time in [
        PRICE.received_at,
        PRICE.valid_until,
        PRICE.valid_until + 3299,
    ] {
        assert!(
            execute_with_tick(PRICE, true, None, "", Some(time)),
            "{time}"
        );
    }
    for time in [
        PRICE.received_at - 1,
        PRICE.valid_until + 3300,
        PRICE.valid_until + 3301,
    ] {
        assert!(
            !execute_with_tick(PRICE, true, None, "", Some(time)),
            "{time}"
        );
    }
    assert!(!execute_with_tick(
        PriceFeedData {
            valid_until: u64::MAX,
            ..PRICE
        },
        true,
        None,
        "",
        Some(PRICE.received_at)
    ));
}

#[test]
fn tick_claim_preserves_price_verifier_and_payout_checks() {
    assert!(!execute_with_tick(PRICE, true, None, "", None));

    for defect in [
        "tick_asset",
        "key",
        "leaf",
        "asset",
        "amount",
        "signature",
        "payout",
        "value",
        "payout_asset",
        "burn",
    ] {
        assert!(
            !execute_with_tick(PRICE, true, None, defect, Some(PRICE.received_at)),
            "{defect}"
        );
    }
}

/// Spends two equal-valued expired positions in one sweep transaction.
/// `house_outputs[i]` is the output index that position input `i` names as its house payout.
/// Output 1 goes to the house only when `second_to_house` is true; otherwise it pays an
/// unrelated script (the attacker in the XF-02 scenario).
fn sweep_two_positions(house_outputs: [u32; 2], second_to_house: bool) -> [bool; 2] {
    let asset = |byte| AssetId::from_byte_array([byte; 32]);
    let network = SimplicityNetwork::ElementsCustom {
        policy_asset: asset(0x66),
        genesis_hash: BlockHash::from_byte_array([0; 32]),
    };
    let wallet = Script::from(vec![0x51]);
    let house = Script::from(vec![0x52]);
    let attacker = Script::from(vec![0x53]);
    let contract = PriceMarketContract::new_with_tick(PriceMarketParameters {
        prediction_id: [7; 32],
        feed_id: 0,
        decimals: 8,
        strike: 100,
        above: true,
        opens_at: 1000,
        deadline: 1100,
        claim_grace: 600,
        verifier_asset_id: asset(0x33),
        tick_asset_id: asset(0x22),
        payout_script_hash: hash_script(&wallet),
        house_script_hash: hash_script(&house),
        network,
    });
    let tick = Voucher::new(VoucherParameters {
        storm_eye_asset_id: asset(0x44),
        auth_method: VoucherAuthMethod::Script {
            auth_script_hash: hash_script(&attacker),
        },
        network,
    });
    let utxo = |asset, value, script_pubkey, vout| UTXO {
        outpoint: OutPoint::new(Txid::from_byte_array([0; 32]), vout),
        txout: TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey,
            witness: TxOutWitness::default(),
        },
        secrets: None,
    };

    let mut transaction = FinalTransaction::new();
    for (vout, house_output_index) in house_outputs.into_iter().enumerate() {
        contract.attach_spend(
            &mut transaction,
            &utxo(
                asset(0x66),
                50000,
                contract.get_script_pubkey(),
                vout as u32,
            ),
            PriceMarketSpend::Sweep {
                tick_input_index: 2,
                house_output_index,
            },
        );
    }
    tick.attach_spend(
        &mut transaction,
        &utxo(asset(0x22), 1701, tick.get_script_pubkey(), 2),
        VoucherSpendPath::ScriptAuth {
            auth_input_index: 3,
            voucher_output_index: 2,
        },
    );
    transaction.add_input(
        PartialInput::new(utxo(asset(0x66), 2000, attacker.clone(), 3)),
        RequiredSignature::None,
    );
    transaction.add_output(PartialOutput::new(house.clone(), 50000, asset(0x66)));
    transaction.add_output(PartialOutput::new(
        if second_to_house { house } else { attacker },
        50000,
        asset(0x66),
    ));
    transaction.add_output(PartialOutput::new(
        Voucher::get_burn_script(2),
        1701,
        asset(0x22),
    ));
    let (pset, _) = transaction.extract_pst();
    [0usize, 1].map(|index| {
        let input = transaction.inputs()[index].program_input.as_ref().unwrap();
        input
            .program
            .finalize(&pset, &input.witness, index, &network)
            .is_ok()
    })
}

#[test]
fn each_position_must_pay_its_own_output() {
    // Honest batch: position i pays house output i.
    assert_eq!(sweep_two_positions([0, 1], true), [true, true]);
    // XF-02: both positions name output 0, and the second 50,000 sats go elsewhere.
    assert_eq!(sweep_two_positions([0, 0], false), [true, false]);
    // A position may not point at another position's output either.
    assert_eq!(sweep_two_positions([1, 0], true), [false, false]);
}
