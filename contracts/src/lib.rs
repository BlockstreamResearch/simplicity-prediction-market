pub mod artifacts;

use simplex::program::Program;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature};

use artifacts::prediction_price_tick::PredictionPriceTickProgram;
use artifacts::prediction_price_tick::derived_prediction_price_tick::{
    PredictionPriceTickArguments, PredictionPriceTickWitness,
};
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
}

pub enum PriceMarketSpend {
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
    pub fn new_with_tick(parameters: PriceMarketParameters) -> Self {
        Self {
            program: Program::new(
                PredictionPriceTickProgram::SOURCE,
                PredictionPriceTickArguments {
                    prediction_id: parameters.prediction_id,
                    feed_id: parameters.feed_id,
                    decimals: parameters.decimals,
                    strike: parameters.strike,
                    above: parameters.above,
                    opens_at: parameters.opens_at,
                    deadline: parameters.deadline,
                    claim_grace: parameters.claim_grace,
                    verifier_asset_id: parameters.verifier_asset_id.to_byte_array(),
                    tick_asset_id: parameters.tick_asset_id.to_byte_array(),
                    payout_script_hash: parameters.payout_script_hash,
                    house_script_hash: parameters.house_script_hash,
                },
            ),
            prediction_id: parameters.prediction_id,
            network: parameters.network,
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
        };
        transaction.add_program_input(
            PartialInput::new(position.clone()),
            ProgramInput::new(
                Box::new(self.program.clone()),
                PredictionPriceTickWitness {
                    prediction_id: self.prediction_id,
                    path,
                },
            ),
            RequiredSignature::None,
        );
    }
}
