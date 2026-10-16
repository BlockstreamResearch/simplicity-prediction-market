import { expect, test } from "bun:test";
import {
  displayPrice,
  meetsMarket,
  meetsPriceTick,
  scaledPrice,
  type PriceMarket,
} from "../src/price-market";

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
