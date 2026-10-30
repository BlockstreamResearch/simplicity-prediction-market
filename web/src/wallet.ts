import type { OracleUtxo } from "@price-oracle/sdk";
import { Buffer } from "buffer";
import {
  address,
  Creator,
  CreatorInput,
  CreatorOutput,
  Pset,
  Transaction,
  Updater,
} from "liquidjs-lib";
import type { HumidUtxo, HumidWallet } from "./humid";

export class EsploraClient {
  private readonly url: string;

  constructor(url: string) {
    const parsed = new URL(url);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password
    )
      throw new Error("The chain index must be a public HTTP endpoint");
    this.url = parsed.href.replace(/\/$/, "");
  }

  private async response(path: string): Promise<Response> {
    const response = await fetch(`${this.url}${path}`, {
      credentials: "omit",
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok && response.status !== 404)
      throw new Error(`Chain lookup failed (${response.status})`);
    return response;
  }

  private async lookup<Result>(path: string): Promise<Result | null> {
    const response = await this.response(path);
    return response.status === 404 ? null : response.json();
  }

  private checkTxid(txid: string): void {
    if (!/^[0-9a-f]{64}$/i.test(txid))
      throw new Error("Invalid transaction ID");
  }

  async validateGenesis(expected: string): Promise<void> {
    if (!/^[0-9a-f]{64}$/i.test(expected))
      throw new Error("The demo server returned invalid chain configuration");
    const response = await this.response("/block-height/0");
    if (
      !response.ok ||
      (await response.text()).trim().toLowerCase() !== expected.toLowerCase()
    )
      throw new Error("The chain index does not match the demo network");
  }

  async getTransactionConfirmations(txid: string): Promise<number> {
    this.checkTxid(txid);
    const status = await this.lookup<{
      confirmed: boolean;
      block_height?: number;
    }>(`/tx/${txid}/status`);
    if (!status?.confirmed) return 0;
    const tip = await this.lookup<number>("/blocks/tip/height");
    if (
      typeof tip !== "number" ||
      !Number.isSafeInteger(tip) ||
      !Number.isSafeInteger(status.block_height) ||
      status.block_height! < 0
    )
      throw new Error("The chain index returned an invalid block height");
    return Math.max(0, tip - status.block_height! + 1);
  }

  async getFundingTransaction(txid: string): Promise<Transaction> {
    this.checkTxid(txid);
    const response = await this.response(`/tx/${txid}/hex`);
    if (!response.ok) throw new Error("Funding transaction not found");
    const transaction = Transaction.fromHex((await response.text()).trim());
    if (transaction.getId() !== txid.toLowerCase())
      throw new Error("Funding transaction does not match its transaction ID");
    return transaction;
  }

  async isConfirmedUnspent(txid: string, vout: number): Promise<boolean> {
    this.checkTxid(txid);
    if (!Number.isSafeInteger(vout) || vout < 0)
      throw new Error("Invalid output index");
    const status = await this.lookup<{ confirmed: boolean }>(
      `/tx/${txid}/status`,
    );
    if (!status?.confirmed) return false;
    const spend = await this.lookup<{ spent: boolean }>(
      `/tx/${txid}/outspend/${vout}`,
    );
    return spend?.spent === false;
  }

  async getExplicitUtxo(txid: string, vout: number): Promise<OracleUtxo> {
    if (!(await this.isConfirmedUnspent(txid, vout)))
      throw new Error("Output must be confirmed and unspent");
    const transaction = await this.lookup<{
      vout: Array<{ scriptpubkey: string; value?: number; asset?: string }>;
    }>(`/tx/${txid}`);
    const output = transaction?.vout[vout];
    if (
      !output?.asset ||
      !Number.isSafeInteger(output.value) ||
      output.value! <= 0 ||
      !/^[0-9a-f]{64}$/i.test(output.asset)
    )
      throw new Error("Expected an explicit asset and amount");
    return {
      txid,
      vout,
      scriptPubKey: output.scriptpubkey,
      amountSats: output.value!,
      asset: output.asset,
    };
  }

  async getSpendingTransaction(
    txid: string,
    vout: number,
  ): Promise<{ txid: string; payoutScript: string } | null> {
    this.checkTxid(txid);
    if (!Number.isSafeInteger(vout) || vout < 0)
      throw new Error("Invalid output index");
    const spend = await this.lookup<{ spent: boolean; txid?: string }>(
      `/tx/${txid}/outspend/${vout}`,
    );
    if (!spend?.spent || !spend.txid) return null;
    this.checkTxid(spend.txid);
    const transaction = await this.lookup<{
      vout: Array<{ scriptpubkey: string }>;
    }>(`/tx/${spend.txid}`);
    if (!transaction?.vout[0]) return null;
    return { txid: spend.txid, payoutScript: transaction.vout[0].scriptpubkey };
  }
}

export function getPayoutBlindingKey(
  utxos: HumidUtxo[],
  fee: Pick<OracleUtxo, "txid" | "vout">,
  wallet: Pick<HumidWallet, "scriptPubKey" | "policyAssetId">,
): string {
  const reserve = utxos.find(
    (utxo) =>
      utxo.txid === fee.txid &&
      utxo.vout === fee.vout &&
      utxo.spendable &&
      utxo.scriptPubKey === wallet.scriptPubKey &&
      utxo.assetId === wallet.policyAssetId,
  );
  if (!reserve)
    throw new Error("The redemption fee reserve is not available in Humid");
  const confidential = address.fromConfidential(reserve.address);
  if (
    address
      .toOutputScript(confidential.unconfidentialAddress)
      .toString("hex") !== wallet.scriptPubKey
  )
    throw new Error(
      "The confidential payout address does not match the Humid wallet",
    );
  return confidential.blindingKey.toString("hex");
}

export function addWalletInputDerivation(
  pset: Pset,
  index: number,
  wallet: Pick<
    HumidWallet,
    "publicKey" | "masterFingerprint" | "derivationPath"
  >,
): void {
  new Updater(pset).addInBIP32Derivation(index, {
    pubkey: Buffer.from(wallet.publicKey, "hex"),
    masterFingerprint: Buffer.from(wallet.masterFingerprint, "hex"),
    path: wallet.derivationPath.replace(/^m\//, ""),
  });
}

export function createFundingPset(
  inputs: Pick<OracleUtxo, "txid" | "vout">[],
  outputs: CreatorOutput[],
): Pset {
  const pset = Creator.newPset({
    inputs: inputs.map((input) => new CreatorInput(input.txid, input.vout)),
    outputs,
  });
  const updater = new Updater(pset);
  for (let index = 0; index < inputs.length; index += 1)
    updater.addInSighashType(index, 1);
  return pset;
}

export async function hydrateFundingPset(
  pset: Pset,
  inputs: Pick<HumidUtxo, "txid" | "vout" | "scriptPubKey">[],
  chain: EsploraClient,
): Promise<void> {
  if (pset.inputs.length !== inputs.length)
    throw new Error("Funding input count does not match the wallet selection");

  const transactions = new Map<string, Promise<Transaction>>();
  const updater = new Updater(pset);
  for (const [index, input] of inputs.entries()) {
    if (!transactions.has(input.txid))
      transactions.set(input.txid, chain.getFundingTransaction(input.txid));
    const transaction = await transactions.get(input.txid)!;
    const output = transaction.outs[input.vout];
    const selected = pset.inputs[index];
    if (
      !output ||
      output.script.toString("hex") !== input.scriptPubKey ||
      selected.previousTxIndex !== input.vout ||
      !selected.previousTxid.equals(transaction.getHash())
    )
      throw new Error(
        "Funding prevout does not match the selected Humid input",
      );

    updater.addInWitnessUtxo(index, output);
  }
}

/** The message each holder funding input key signs so the host reserves funds only for owned coins. */
export function escrowOwnershipMessage(
  predictionId: string,
  stakeSats: number,
  payoutScript: string,
  inputs: Pick<OracleUtxo, "txid" | "vout">[],
): string {
  return [
    "Prediction escrow funding",
    `prediction: ${predictionId}`,
    `stake_sats: ${stakeSats}`,
    `payout: ${payoutScript.toLowerCase()}`,
    `inputs: ${inputs.map((input) => `${input.txid.toLowerCase()}:${input.vout}`).join(",")}`,
  ].join("\n");
}

export function verifyMatchedEscrow(
  original: Pset,
  funded: Pset,
  stakeSats: number,
): void {
  if (
    !Number.isSafeInteger(stakeSats * 2) ||
    stakeSats <= 0 ||
    funded.inputs.length !== original.inputs.length + 1 ||
    funded.outputs.length < original.outputs.length ||
    funded.outputs.length > original.outputs.length + 1 ||
    funded.globals.txVersion !== original.globals.txVersion ||
    funded.locktime() !== original.locktime()
  ) {
    throw new Error("Host returned an invalid matched escrow");
  }

  for (const [index, input] of original.inputs.entries()) {
    if (!input.toBuffer().equals(funded.inputs[index].toBuffer()))
      throw new Error("Host changed the holder funding inputs");
  }
  const expectedPset = Pset.fromBase64(original.toBase64());
  for (const [index, output] of original.outputs.entries()) {
    const expected = expectedPset.outputs[index];
    if (index === 0) expected.value = stakeSats * 2;
    if (!expected.toBuffer().equals(funded.outputs[index].toBuffer()))
      throw new Error("Host changed the escrow, fees or holder change");
    if (index === 0 && output.value !== stakeSats)
      throw new Error("Original escrow does not match the holder stake");
  }

  const host = funded.inputs.at(-1)!;
  const change = funded.outputs[original.outputs.length];
  const reserve = host.witnessUtxo;
  const asset = original.outputs[0].asset;
  if (
    !reserve ||
    !asset ||
    reserve.value.length !== 9 ||
    reserve.value[0] !== 1 ||
    !reserve.asset.equals(Buffer.concat([Buffer.from([1]), asset])) ||
    host.sighashType !== 1 ||
    host.hasIssuance() ||
    host.peginTx ||
    (change
      ? !change.asset?.equals(asset) ||
        change.valueCommitment ||
        change.assetCommitment ||
        change.blindingPubkey ||
        !change.script?.length ||
        !Number.isSafeInteger(change.value) ||
        change.value <= 0 ||
        BigInt(change.value) + BigInt(stakeSats) !==
          reserve.value.readBigUInt64BE(1)
      : BigInt(stakeSats) !== reserve.value.readBigUInt64BE(1))
  ) {
    throw new Error("Host reserve does not fund the full stake match");
  }
}

export function selectFundingUtxos(
  utxos: (OracleUtxo & { confidential?: boolean })[],
  policyAsset: string,
  requiredSats: number,
): OracleUtxo[] {
  if (!Number.isSafeInteger(requiredSats) || requiredSats <= 0) {
    throw new Error("Enter a valid stake amount");
  }

  const candidates = utxos
    .filter(
      (utxo) =>
        utxo.asset === policyAsset &&
        Number.isSafeInteger(utxo.amountSats) &&
        utxo.amountSats > 0,
    )
    .sort(
      (left, right) =>
        Number(Boolean(right.confidential)) -
          Number(Boolean(left.confidential)) ||
        right.amountSats - left.amountSats,
    );
  const selected: OracleUtxo[] = [];
  const seen = new Set<string>();
  let total = 0;

  for (const utxo of candidates) {
    const outpoint = `${utxo.txid}:${utxo.vout}`;
    if (seen.has(outpoint)) continue;
    seen.add(outpoint);
    selected.push(utxo);
    total += utxo.amountSats;
    if (!Number.isSafeInteger(total))
      throw new Error("Wallet balance exceeds the supported range");
    if (total >= requiredSats) return selected;
  }

  throw new Error("Insufficient confirmed LBTC for the stake and fees");
}
