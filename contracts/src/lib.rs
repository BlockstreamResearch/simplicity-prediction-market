pub mod artifacts;

use simplex::program::Program;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplex::simplicityhl::elements::hashes::{Hash, sha256};
use simplex::simplicityhl::elements::secp256k1_zkp::{
    Error, Keypair, Message, Secp256k1, SecretKey,
};
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature};

use artifacts::prediction::PredictionProgram;
use artifacts::prediction::derived_prediction::{PredictionArguments, PredictionWitness};
use artifacts::prediction_confidential::PredictionConfidentialProgram;
use artifacts::prediction_confidential::derived_prediction_confidential::PredictionConfidentialWitness;
use artifacts::prediction_price::PredictionPriceProgram;
use artifacts::prediction_price::derived_prediction_price::{
    PredictionPriceArguments, PredictionPriceWitness,
};
use artifacts::prediction_price_tick::PredictionPriceTickProgram;
use artifacts::prediction_price_tick::derived_prediction_price_tick::PredictionPriceTickWitness;
use price_oracle_contracts::sdk::SignedPrice;
use simplex::either::Either;

pub struct PriceMarketParameters {
    pub prediction_id: [u8; 32],
    pub feed_id: u32,
    pub decimals: u32,
    pub strike: u64,
    pub above: bool,
    pub opens_at: u64,
    pub deadline: u64,
    pub claim_grace: u64,
    pub verifier_asset_id: AssetId,
    pub tick_asset_id: AssetId,
    pub payout_script_hash: [u8; 32],
    pub house_script_hash: [u8; 32],
    pub network: SimplicityNetwork,
}

pub struct PriceMarketContract {
    program: Program,
    prediction_id: [u8; 32],
    network: SimplicityNetwork,
    requires_tick: bool,
}

pub enum PriceMarketSpend {
    Claim {
        verifier_input_index: u32,
        verifier_tapleaf_hash: [u8; 32],
        signed: SignedPrice,
        payout_output_index: u32,
    },
    ClaimWithTick {
        tick_input_index: u32,
        verifier_input_index: u32,
        verifier_tapleaf_hash: [u8; 32],
        signed: SignedPrice,
        payout_output_index: u32,
    },
    Sweep {
        tick_input_index: u32,
        house_output_index: u32,
    },
}

impl PriceMarketContract {
    pub fn new(parameters: PriceMarketParameters) -> Self {
        Self::build(parameters, false)
    }

    pub fn new_with_tick(parameters: PriceMarketParameters) -> Self {
        Self::build(parameters, true)
    }

    fn build(parameters: PriceMarketParameters, requires_tick: bool) -> Self {
        Self {
            program: Program::new(
                if requires_tick {
                    PredictionPriceTickProgram::SOURCE
                } else {
                    PredictionPriceProgram::SOURCE
                },
                &PredictionPriceArguments {
                    prediction_id: parameters.prediction_id,
                    feed_id: parameters.feed_id,
                    decimals: parameters.decimals,
                    strike: parameters.strike,
                    above: parameters.above,
                    opens_at: parameters.opens_at,
                    deadline: parameters.deadline,
                    claim_grace: parameters.claim_grace,
                    verifier_asset_id: parameters.verifier_asset_id.into_inner().to_byte_array(),
                    tick_asset_id: parameters.tick_asset_id.into_inner().to_byte_array(),
                    payout_script_hash: parameters.payout_script_hash,
                    house_script_hash: parameters.house_script_hash,
                },
            ),
            prediction_id: parameters.prediction_id,
            network: parameters.network,
            requires_tick,
        }
    }

    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.network)
    }

    pub fn attach_spend(
        &self,
        transaction: &mut FinalTransaction,
        position: &UTXO,
        spend: PriceMarketSpend,
    ) {
        if self.requires_tick {
            let path = match spend {
                PriceMarketSpend::ClaimWithTick {
                    tick_input_index,
                    verifier_input_index,
                    verifier_tapleaf_hash,
                    signed,
                    payout_output_index,
                } => Either::Left((
                    tick_input_index,
                    verifier_input_index,
                    verifier_tapleaf_hash,
                    signed.get_signer(),
                    signed.get_signature(),
                    signed.get_price_witness(),
                    payout_output_index,
                )),
                PriceMarketSpend::Sweep {
                    tick_input_index,
                    house_output_index,
                } => Either::Right((tick_input_index, house_output_index)),
                PriceMarketSpend::Claim { .. } => panic!("price claim requires a Tick"),
            };
            transaction.add_program_input(
                PartialInput::new(position.clone()),
                ProgramInput::new(
                    Box::new(self.program.clone()),
                    Box::new(PredictionPriceTickWitness {
                        prediction_id: self.prediction_id,
                        path,
                    }),
                ),
                RequiredSignature::None,
            );
            return;
        }
        let path = match spend {
            PriceMarketSpend::Claim {
                verifier_input_index,
                verifier_tapleaf_hash,
                signed,
                payout_output_index,
            } => Either::Left((
                verifier_input_index,
                verifier_tapleaf_hash,
                signed.get_signer(),
                signed.get_signature(),
                signed.get_price_witness(),
                payout_output_index,
            )),
            PriceMarketSpend::Sweep {
                tick_input_index,
                house_output_index,
            } => Either::Right((tick_input_index, house_output_index)),
            PriceMarketSpend::ClaimWithTick { .. } => {
                panic!("legacy price claim does not use a Tick")
            }
        };
        transaction.add_program_input(
            PartialInput::new(position.clone()),
            ProgramInput::new(
                Box::new(self.program.clone()),
                Box::new(PredictionPriceWitness {
                    prediction_id: self.prediction_id,
                    path,
                }),
            ),
            RequiredSignature::None,
        );
    }
}

pub struct PredictionContract {
    program: Program,
    network: SimplicityNetwork,
}

pub struct PredictionParameters {
    pub prediction_id: [u8; 32],
    pub admin_pubkey: [u8; 32],
    pub deadline: u64,
    pub tick_asset_id: AssetId,
    pub tick_script_hash: [u8; 32],
    pub payout_script_hash: [u8; 32],
    pub network: SimplicityNetwork,
}

pub struct PredictionSpend {
    pub occurred_at: u64,
    pub admin_signature: [u8; 64],
    pub tick_input_index: u32,
    pub payout_output_index: u32,
}

pub struct PredictionPayoutProofs {
    pub asset: [u8; 64],
    pub value: [u8; 64],
}

impl PredictionPayoutProofs {
    pub fn new(
        prediction_id: [u8; 32],
        occurred_at: u64,
        asset_blinding_factor: AssetBlindingFactor,
        value_blinding_factor: ValueBlindingFactor,
    ) -> Result<Self, Error> {
        let mut preimage = [0; 64];
        preimage[..32].copy_from_slice(&prediction_id);
        preimage[56..].copy_from_slice(&occurred_at.to_be_bytes());
        let message = Message::from_digest(sha256::Hash::hash(&preimage).to_byte_array());
        let secp = Secp256k1::new();
        let prove = |factor: &[u8]| -> Result<[u8; 64], Error> {
            let secret = SecretKey::from_slice(factor)?;
            let keypair = Keypair::from_secret_key(&secp, &secret);
            Ok(secp
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .serialize())
        };
        Ok(Self {
            asset: prove(asset_blinding_factor.into_inner().as_ref())?,
            value: prove(value_blinding_factor.into_inner().as_ref())?,
        })
    }
}

impl PredictionContract {
    #[must_use]
    pub fn new(parameters: PredictionParameters) -> Self {
        Self::build(parameters, PredictionProgram::SOURCE)
    }

    #[must_use]
    pub fn new_confidential(parameters: PredictionParameters) -> Self {
        Self::build(parameters, PredictionConfidentialProgram::SOURCE)
    }

    fn build(parameters: PredictionParameters, source: &'static str) -> Self {
        let program = Program::new(
            source,
            &PredictionArguments {
                prediction_id: parameters.prediction_id,
                admin_pubkey: parameters.admin_pubkey,
                deadline: parameters.deadline,
                tick_asset_id: parameters.tick_asset_id.into_inner().to_byte_array(),
                tick_script_hash: parameters.tick_script_hash,
                payout_script_hash: parameters.payout_script_hash,
            },
        );

        Self {
            program,
            network: parameters.network,
        }
    }

    #[must_use]
    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.network)
    }

    pub fn attach_spend(
        &self,
        transaction: &mut FinalTransaction,
        position_utxo: &UTXO,
        spend: PredictionSpend,
    ) {
        transaction.add_program_input(
            PartialInput::new(position_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.clone()),
                Box::new(PredictionWitness {
                    occurred_at: spend.occurred_at,
                    admin_signature: spend.admin_signature,
                    tick_input_index: spend.tick_input_index,
                    payout_output_index: spend.payout_output_index,
                }),
            ),
            RequiredSignature::None,
        );
    }

    pub fn attach_confidential_spend(
        &self,
        transaction: &mut FinalTransaction,
        position_utxo: &UTXO,
        spend: PredictionSpend,
        proofs: PredictionPayoutProofs,
    ) {
        transaction.add_program_input(
            PartialInput::new(position_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.clone()),
                Box::new(PredictionConfidentialWitness {
                    occurred_at: spend.occurred_at,
                    admin_signature: spend.admin_signature,
                    tick_input_index: spend.tick_input_index,
                    payout_output_index: spend.payout_output_index,
                    payout_asset_proof: proofs.asset,
                    payout_value_proof: proofs.value,
                }),
            ),
            RequiredSignature::None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simplex::simplicityhl::elements::confidential::{Asset, Nonce, Value};
    use simplex::simplicityhl::elements::secp256k1_zkp::{Generator, PedersenCommitment};
    use simplex::simplicityhl::elements::{BlockHash, OutPoint, TxOut, TxOutWitness, Txid};
    use simplex::transaction::PartialOutput;
    use simplex::utils::hash_script;

    fn finalize_payout(amount: u64, asset: AssetId, altered_proof: bool, factor: u8) -> bool {
        let secp = Secp256k1::new();
        let policy_asset = AssetId::from_slice(&[0x66; 32]).unwrap();
        let tick_asset = AssetId::from_slice(&[0x33; 32]).unwrap();
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset,
            genesis_hash: BlockHash::all_zeros(),
        };
        let script = Script::from(vec![0x51]);
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
        let contract = PredictionContract::new_confidential(PredictionParameters {
            prediction_id: [7; 32],
            admin_pubkey: keypair.x_only_public_key().0.serialize(),
            deadline: 1_700_000_050,
            tick_asset_id: tick_asset,
            tick_script_hash: hash_script(&script),
            payout_script_hash: hash_script(&script),
            network,
        });
        let utxo = |asset, value, script_pubkey, vout| UTXO {
            outpoint: OutPoint::new(Txid::all_zeros(), vout),
            txout: TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(value),
                nonce: Nonce::Null,
                script_pubkey,
                witness: TxOutWitness::default(),
            },
            secrets: None,
        };
        let abf = AssetBlindingFactor::from_slice(&[factor; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[factor + 1; 32]).unwrap();
        let mut proofs = PredictionPayoutProofs::new([7; 32], 1_700_000_000, abf, vbf).unwrap();
        if altered_proof {
            proofs.value[0] ^= 1;
        }
        let mut preimage = [0; 64];
        preimage[..32].fill(7);
        preimage[56..].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        let signature = secp
            .sign_schnorr_no_aux_rand(
                &Message::from_digest(sha256::Hash::hash(&preimage).to_byte_array()),
                &keypair,
            )
            .serialize();
        let mut transaction = FinalTransaction::new();
        contract.attach_confidential_spend(
            &mut transaction,
            &utxo(policy_asset, 50_000, contract.get_script_pubkey(), 0),
            PredictionSpend {
                occurred_at: 1_700_000_000,
                admin_signature: signature,
                tick_input_index: 1,
                payout_output_index: 0,
            },
            proofs,
        );
        transaction.add_input(
            PartialInput::new(utxo(tick_asset, 1_700_000_100, script.clone(), 1)),
            RequiredSignature::None,
        );
        transaction.add_output(PartialOutput::new(script, amount, asset));
        let (mut pset, _) = transaction.extract_pst();
        let generator = Generator::new_blinded(&secp, asset.into_tag(), abf.into_inner());
        pset.outputs_mut()[0].asset_comm = Some(generator);
        pset.outputs_mut()[0].amount_comm = Some(PedersenCommitment::new(
            &secp,
            amount,
            vbf.into_inner(),
            generator,
        ));
        let input = transaction.inputs()[0].program_input.as_ref().unwrap();
        input
            .program
            .finalize(&pset, &input.witness.build_witness(), 0, &network)
            .is_ok()
    }

    #[test]
    fn confidential_payout_preserves_asset_and_amount() {
        let asset = AssetId::from_slice(&[0x66; 32]).unwrap();
        for factor in 1..5 {
            assert!(finalize_payout(50_000, asset, false, factor));
        }
    }

    #[test]
    fn confidential_payout_rejects_wrong_amount_asset_or_proof() {
        let asset = AssetId::from_slice(&[0x66; 32]).unwrap();
        assert!(!finalize_payout(49_999, asset, false, 1));
        assert!(!finalize_payout(
            50_000,
            AssetId::from_slice(&[0x55; 32]).unwrap(),
            false,
            1
        ));
        assert!(!finalize_payout(50_000, asset, true, 1));
    }
}
