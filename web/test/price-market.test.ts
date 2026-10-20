import { expect, spyOn, test } from "bun:test";
import { deriveAccount } from "@price-oracle/sdk";
import { bip341 } from "liquidjs-lib";
import { Buffer } from "buffer";
import * as ecc from "@bitcoinerlab/secp256k1";
import {
  displayPrice,
  loadOracleVerification,
  meetsMarket,
  meetsPriceTick,
  scaledPrice,
  verifyIssuedPriceOutputs,
  verifyMarketAssets,
  type OracleVerification,
  type PriceMarket,
} from "../src/price-market";
import type { HumidWallet } from "../src/humid";

test("verification context fails closed for missing anchors or a different wallet or chain", async () => {
  const owner =
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
  const wallet = {
    publicKey: `02${owner}`,
    scriptPubKey: `0014${"11".repeat(20)}`,
  } as HumidWallet;
  const context: OracleVerification = {
    ownerPublicKey: owner,
    authScriptPubKey: wallet.scriptPubKey,
    network: "elementsregtest",
    stormEyeAssetId: "55".repeat(32),
    tickAssetId: "33".repeat(32),
    verifierAssetId: "44".repeat(32),
    stormTreeRoot: "77".repeat(32),
    accountTapleafHash: "aa".repeat(32),
    tickTapleafHash: "bb".repeat(32),
  };
  const fetch = spyOn(globalThis, "fetch");
  try {
    fetch.mockResolvedValueOnce(Response.json(context));
    expect(
      await loadOracleVerification(
        "http://127.0.0.1:3100",
        wallet,
        "elementsregtest",
      ),
    ).toEqual(context);
    for (const change of [
      { ownerPublicKey: "66".repeat(32) },
      { authScriptPubKey: "51" },
      { network: "liquidtestnet" },
      { stormTreeRoot: "" },
      { accountTapleafHash: "" },
    ]) {
      fetch.mockResolvedValueOnce(Response.json({ ...context, ...change }));
      await expect(
        loadOracleVerification(
          "http://127.0.0.1:3100",
          wallet,
          "elementsregtest",
        ),
      ).rejects.toThrow();
    }
    fetch.mockResolvedValueOnce(
      Response.json({ error: "anchors are not configured" }, { status: 409 }),
    );
    await expect(
      loadOracleVerification(
        "http://127.0.0.1:3100",
        wallet,
        "elementsregtest",
      ),
    ).rejects.toThrow("anchors are not configured");
  } finally {
    fetch.mockRestore();
  }
});

test("issued proofs require trusted assets and both exact voucher scripts", () => {
  const context: OracleVerification = {
    ownerPublicKey:
      "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    network: "elementsregtest",
    stormEyeAssetId: "55".repeat(32),
    tickAssetId: "33".repeat(32),
    verifierAssetId: "44".repeat(32),
    stormTreeRoot: "77".repeat(32),
    accountTapleafHash: "aa".repeat(32),
    tickTapleafHash: "bb".repeat(32),
    authScriptPubKey: `0014${"11".repeat(20)}`,
  };
  const price = {
    price_data:
      "000000040000000800000002540be400000000006553f100000000006553f22c",
    storm_tree_bloom: {
      signature: "",
      branch: context.ownerPublicKey,
      proof: [],
    },
  };
  const voucher = {
    txid: "ab".repeat(32),
    vout: 0,
    amount_sats: 1,
    asset: context.verifierAssetId,
    script_pubkey: bip341
      .BIP341Factory(ecc)
      .taprootOutputScript(Buffer.from(`02${context.ownerPublicKey}`, "hex"), {
        hash: Buffer.from(context.tickTapleafHash, "hex"),
      })
      .toString("hex"),
  };
  const tick = {
    ...voucher,
    vout: 1,
    amount_sats: 1700000000,
    asset: context.tickAssetId,
    script_pubkey: deriveAccount(context).tick_script_pubkey,
  };
  expect(() =>
    verifyIssuedPriceOutputs(price, voucher, tick, context),
  ).not.toThrow();
  for (const change of [
    { amount_sats: 2 },
    { asset: context.tickAssetId },
    { script_pubkey: "51" },
  ])
    expect(() =>
      verifyIssuedPriceOutputs(price, { ...voucher, ...change }, tick, context),
    ).toThrow();
  for (const change of [
    { amount_sats: 1700003600 },
    { asset: context.verifierAssetId },
    { script_pubkey: voucher.script_pubkey },
  ])
    expect(() =>
      verifyIssuedPriceOutputs(price, voucher, { ...tick, ...change }, context),
    ).toThrow();
  expect(() =>
    verifyIssuedPriceOutputs(price, voucher, tick, {
      ...context,
      tickTapleafHash: "cc".repeat(32),
    }),
  ).toThrow();
  const assets = {
    storm_eye_asset_id: context.stormEyeAssetId,
    tick_asset_id: context.tickAssetId,
    verifier_asset_id: context.verifierAssetId,
  } as PriceMarket;
  expect(() => verifyMarketAssets(assets, context)).not.toThrow();
  for (const field of [
    "storm_eye_asset_id",
    "tick_asset_id",
    "verifier_asset_id",
  ])
    expect(() =>
      verifyMarketAssets({ ...assets, [field]: "66".repeat(32) }, context),
    ).toThrow();
});

test("price scaling and display preserve exact u64 amounts", () => {
  expect(scaledPrice("123456.12345678", 8)).toBe("12345612345678");
  expect(displayPrice("12345612345678", 8)).toBe("123,456.12345678");
  expect(scaledPrice("18446744073709551615", 0)).toBe("18446744073709551615");
  for (const price of ["0", "-1", "1e3", "18446744073709551616"])
    expect(() => scaledPrice(price, 0)).toThrow();
  expect(() => scaledPrice("1.123", 2)).toThrow();
});

test("touch rules bind the feed, scale, window and direction", () => {
  const market: PriceMarket = {
    feed_id: 4,
    decimals: 8,
    strike: "10000000000",
    above: true,
    opens_at: 1700000000,
    claim_grace: 600,
    house_script_pubkey: "",
    tick_asset_id: "",
    verifier_asset_id: "",
    storm_eye_asset_id: "",
  };
  const signed = {
    price_data:
      "000000040000000800000002540be400000000006553f100000000006553f22c",
    storm_tree_bloom: { signature: "", branch: "", proof: [] },
  };
  expect(meetsMarket(signed, market, 1700000000)).toBe(true);
  expect(meetsMarket(signed, { ...market, above: false }, 1700000000)).toBe(
    true,
  );
  for (const change of [
    { feed_id: 0 },
    { decimals: 7 },
    { strike: "10000000001" },
    { opens_at: 1700000001 },
  ])
    expect(meetsMarket(signed, { ...market, ...change }, 1700000010)).toBe(
      false,
    );
  expect(meetsMarket(signed, market, 1699999999)).toBe(false);
});

test("Tick time uses the signed expiry plus exactly 55 minutes", () => {
  const signed = {
    price_data:
      "000000040000000800000002540be400000000006553f100000000006553f22c",
    storm_tree_bloom: { signature: "", branch: "", proof: [] },
  };
  const tick = {
    txid: "ab".repeat(32),
    vout: 1,
    script_pubkey: "51",
    amount_sats: 1700000000,
    asset: "22".repeat(32),
  };
  for (const time of [1700000000, 1700000300, 1700003599])
    expect(
      meetsPriceTick(signed, { ...tick, amount_sats: time }, tick.asset),
    ).toBe(true);
  for (const time of [1699999999, 1700003600, 1700003601, NaN, 0x100000000])
    expect(
      meetsPriceTick(signed, { ...tick, amount_sats: time }, tick.asset),
    ).toBe(false);
  expect(
    meetsPriceTick(signed, { ...tick, asset: "33".repeat(32) }, tick.asset),
  ).toBe(false);
  expect(
    meetsPriceTick(
      {
        ...signed,
        price_data: signed.price_data.slice(0, 48) + "ffffffffffffffff",
      },
      tick,
      tick.asset,
    ),
  ).toBe(false);
});
