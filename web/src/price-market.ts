import { Buffer } from "buffer";
import { address, CreatorOutput } from "liquidjs-lib";
import {
  decodePriceData,
  type OracleAccount,
  type SignedPriceData,
} from "@price-oracle/sdk";
import {
  getHumidUtxos,
  signAndBroadcastHumidPset,
  type HumidWallet,
} from "./humid";
import { createFundingPset, EsploraClient, selectFundingUtxos } from "./wallet";

export type PriceMarket = {
  feed_id: number;
  decimals: number;
  strike: string;
  above: boolean;
  opens_at: number;
  claim_grace: number;
  house_script_pubkey: string;
  tick_asset_id: string;
  verifier_asset_id: string;
  storm_eye_asset_id: string;
};
export type ExplicitUtxo = {
  txid: string;
  vout: number;
  script_pubkey: string;
  amount_sats: number;
  asset: string;
};
export type PriceClaim = {
  voucher: ExplicitUtxo;
  signedPrice: SignedPriceData;
  tick?: ExplicitUtxo;
};

export const PRICE_VALIDITY_EXTENSION_SECONDS = 55 * 60;

export function meetsPriceTick(
  price: SignedPriceData,
  tick: ExplicitUtxo,
  tickAssetId: string,
): boolean {
  const data = decodePriceData(price.price_data);
  const extension = BigInt(PRICE_VALIDITY_EXTENSION_SECONDS);
  return (
    tick.asset === tickAssetId &&
    Number.isSafeInteger(tick.amount_sats) &&
    tick.amount_sats > 0 &&
    tick.amount_sats <= 0xffffffff &&
    data.validUntil <= 0xffffffffffffffffn - extension &&
    BigInt(tick.amount_sats) >= data.receivedAt &&
    BigInt(tick.amount_sats) < data.validUntil + extension
  );
}

export function scaledPrice(value: string, decimals: number): string {
  if (
    !Number.isInteger(decimals) ||
    decimals < 0 ||
    decimals > 18 ||
    !/^\d+(\.\d+)?$/.test(value)
  )
    throw new Error("Enter a positive decimal price");
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals)
    throw new Error(`Price supports at most ${decimals} decimals`);
  const result = BigInt(`${whole}${fraction.padEnd(decimals, "0")}`);
  if (result <= 0n || result > 0xffffffffffffffffn)
    throw new Error("Price is outside the supported range");
  return result.toString();
}

export function displayPrice(value: string | bigint, decimals: number): string {
  const padded = BigInt(value)
    .toString()
    .padStart(decimals + 1, "0");
  const whole = decimals ? padded.slice(0, -decimals) : padded;
  const fraction = decimals ? padded.slice(-decimals).replace(/0+$/, "") : "";
  return `${whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",")}${fraction ? `.${fraction}` : ""}`;
}

export function meetsMarket(
  price: SignedPriceData,
  market: PriceMarket,
  deadline: number,
): boolean {
  const data = decodePriceData(price.price_data);
  return (
    data.feedId === market.feed_id &&
    data.decimals === market.decimals &&
    data.receivedAt >= BigInt(market.opens_at) &&
    data.receivedAt <= BigInt(deadline) &&
    (market.above
      ? data.price >= BigInt(market.strike)
      : data.price <= BigInt(market.strike))
  );
}

export function explicit(utxo: {
  txid: string;
  vout: number;
  scriptPubKey: string;
  amountSats: number;
  asset?: string;
}): ExplicitUtxo {
  if (!utxo.asset) throw new Error("Output has no explicit asset");
  return {
    txid: utxo.txid,
    vout: utxo.vout,
    script_pubkey: utxo.scriptPubKey,
    amount_sats: utxo.amountSats,
    asset: utxo.asset,
  };
}

export async function waitForOutput(
  chain: EsploraClient,
  txid: string,
  vout: number,
): Promise<ExplicitUtxo> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (await chain.isConfirmedUnspent(txid, vout))
      return explicit(await chain.getExplicitUtxo(txid, vout));
    await new Promise((resolve) => window.setTimeout(resolve, 1000));
  }
  throw new Error(`Output ${txid}:${vout} is still confirming`);
}

export async function fundOracleRequest(
  wallet: HumidWallet,
  account: OracleAccount,
  chainBackend: string,
): Promise<{ feeOutpoint: string; reserve: ExplicitUtxo }> {
  const chain = new EsploraClient(chainBackend);
  const utxos = await getHumidUtxos(wallet);
  const live = (
    await Promise.all(
      utxos.map(async (utxo) =>
        (await chain.isConfirmedUnspent(utxo.txid, utxo.vout)) ? utxo : null,
      ),
    )
  ).filter((utxo) => utxo !== null);
  const inputs = selectFundingUtxos(
    live.map((utxo) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      asset: utxo.assetId,
      amountSats: Number(utxo.amount),
      confidential: utxo.confidential,
      scriptPubKey: utxo.scriptPubKey,
    })),
    wallet.policyAssetId,
    13001,
  );
  const signing = inputs.map(
    (input) =>
      live.find(
        (utxo) => utxo.txid === input.txid && utxo.vout === input.vout,
      )!,
  );
  const change =
    inputs.reduce((sum, input) => sum + input.amountSats, 0) - 13000;
  const outputs = [
    new CreatorOutput(
      wallet.policyAssetId,
      10000,
      Buffer.from(account.script_pubkey, "hex"),
    ),
    new CreatorOutput(
      wallet.policyAssetId,
      2000,
      Buffer.from(wallet.scriptPubKey, "hex"),
    ),
  ];
  const confidential = signing.find((utxo) => utxo.confidential);
  if (confidential) {
    const recipient = address.fromConfidential(confidential.address);
    outputs.push(
      new CreatorOutput(
        wallet.policyAssetId,
        change,
        address.toOutputScript(recipient.unconfidentialAddress),
        recipient.blindingKey,
        0,
      ),
    );
  } else
    outputs.push(
      new CreatorOutput(
        wallet.policyAssetId,
        change,
        Buffer.from(wallet.scriptPubKey, "hex"),
      ),
    );
  outputs.push(new CreatorOutput(wallet.policyAssetId, 1000, Buffer.alloc(0)));
  const pset = createFundingPset(inputs, outputs);
  const txid = await signAndBroadcastHumidPset(
    wallet,
    pset.toBase64(),
    signing.map((utxo, index) => ({ index, address: utxo.address })),
    chainBackend,
  );
  return {
    feeOutpoint: `${txid}:0`,
    reserve: {
      txid,
      vout: 1,
      script_pubkey: wallet.scriptPubKey,
      asset: wallet.policyAssetId,
      amount_sats: 2000,
    },
  };
}
