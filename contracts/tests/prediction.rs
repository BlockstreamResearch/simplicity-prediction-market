use sha2::{Digest, Sha256};
use simplex::signer::SignerError;
use simplex::simplicityhl::elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey};
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};
use simplex::utils::hash_script;

use prediction_demo_contracts::{PredictionContract, PredictionParameters, PredictionSpend};

const POSITION_AMOUNT: u64 = 50_000;
const TICK_TIMESTAMP: u64 = 1_700_000_100;
const OCCURRED_AT: u64 = 1_700_000_000;
const DEADLINE: u64 = 1_700_000_050;
const PREDICTION_ID: [u8; 32] = [7; 32];

struct Fixture {
    contract: PredictionContract,
    position_utxo: UTXO,
    tick_utxo: UTXO,
    admin_keypair: Keypair,
}

impl Fixture {
    fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        let signer = context.get_default_signer();
        let tick_asset = issue_asset(context, TICK_TIMESTAMP)?;
        let tick_utxo = signer.get_utxos_asset(tick_asset)?[0].clone();
        let admin_keypair =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[1; 32])?);
        let admin_pubkey = admin_keypair.x_only_public_key().0.serialize();
        let signer_script = signer.get_address().script_pubkey();
        let contract = PredictionContract::new(PredictionParameters {
            prediction_id: PREDICTION_ID,
            admin_pubkey,
            deadline: DEADLINE,
            tick_asset_id: tick_asset,
            tick_script_hash: hash_script(&signer_script),
            payout_script_hash: hash_script(&signer_script),
            network: *context.get_network(),
        });
        let position_utxo = fund_position(context, &contract)?;

        Ok(Self {
            contract,
            position_utxo,
            tick_utxo,
            admin_keypair,
        })
    }

    fn redemption(&self, context: &simplex::TestContext, occurred_at: u64) -> FinalTransaction {
        let signer = context.get_default_signer();
        let digest = resolution_digest(occurred_at);
        let message = Message::from_digest(digest);
        let signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&message, &self.admin_keypair)
            .serialize();
        let mut transaction = FinalTransaction::new();

        self.contract.attach_spend(
            &mut transaction,
            &self.position_utxo,
            PredictionSpend {
                occurred_at,
                admin_signature: signature,
                tick_input_index: 1,
                payout_output_index: 0,
            },
        );
        transaction.add_input(
            PartialInput::new(self.tick_utxo.clone()),
            RequiredSignature::NativeEcdsa,
        );
        transaction.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            self.position_utxo.explicit_amount(),
            self.position_utxo.explicit_asset(),
        ));
        transaction.add_output(PartialOutput::new(
            Script::new_op_return(&[]),
            self.tick_utxo.explicit_amount(),
            self.tick_utxo.explicit_asset(),
        ));

        transaction
    }
}

fn resolution_digest(occurred_at: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREDICTION_ID);
    hasher.update([0; 24]);
    hasher.update(occurred_at.to_be_bytes());
    hasher.finalize().into()
}

fn issue_asset(context: &simplex::TestContext, amount: u64) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();
    let mut transaction = FinalTransaction::new();
    let issuance = transaction.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(amount, 0, [3; 32]),
        RequiredSignature::NativeEcdsa,
    );

    transaction.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        amount,
        issuance.asset_id,
    ));
    signer.broadcast(&transaction)?.wait()?;

    Ok(issuance.asset_id)
}

fn fund_position(
    context: &simplex::TestContext,
    contract: &PredictionContract,
) -> anyhow::Result<UTXO> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();
    let mut transaction = FinalTransaction::new();

    transaction.add_input(
        PartialInput::new(funding_utxo),
        RequiredSignature::NativeEcdsa,
    );
    transaction.add_output(PartialOutput::new(
        contract.get_script_pubkey(),
        POSITION_AMOUNT,
        context.get_network().policy_asset(),
    ));
    signer.broadcast(&transaction)?.wait()?;

    context
        .get_default_provider()
        .fetch_scripthash_utxos(&contract.get_script_pubkey())?
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("funding transaction produced no position UTXO"))
}

#[track_caller]
fn assert_covenant_rejects(context: &simplex::TestContext, transaction: &FinalTransaction) {
    match context.get_default_signer().broadcast(transaction) {
        Err(SignerError::CovenantExecution { .. }) => {}
        Err(other) => panic!("expected covenant rejection, got {other}"),
        Ok(_) => panic!("expected covenant rejection, but transaction was accepted"),
    }
}

#[simplex::test]
fn redeems_after_the_signed_occurrence(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = Fixture::new(&context)?;
    let transaction = fixture.redemption(&context, OCCURRED_AT);

    context
        .get_default_signer()
        .broadcast(&transaction)?
        .wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_a_tick_before_the_signed_occurrence(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = Fixture::new(&context)?;
    let transaction = fixture.redemption(&context, TICK_TIMESTAMP + 1);

    assert_covenant_rejects(&context, &transaction);

    Ok(())
}
