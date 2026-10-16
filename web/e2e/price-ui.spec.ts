import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import * as ecc from "@bitcoinerlab/secp256k1";
import {
  Creator,
  CreatorInput,
  CreatorOutput,
  ElementsValue,
  networks,
  payments,
  Pset,
  PsetInput,
  Transaction,
} from "liquidjs-lib";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/admin/escrow", (route) =>
    route.fulfill({
      json: {
        configured: false,
        funding_address: null,
        balance_sats: 0,
        available_sats: 0,
        reserved_sats: 0,
        utxo_count: 0,
        max_stake_sats: 0,
      },
    }),
  );
  await page.route("**/api/config", (route) =>
    route.fulfill({
      json: {
        policy_asset_id: "66".repeat(32),
        genesis_block_hash:
          "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f",
        network: "elementsregtest",
        oracle_url: "http://127.0.0.1:9100",
        matched_escrow_enabled: true,
      },
    }),
  );
});

test("admin escrow wallet shows a copyable funding address and refreshes reserve balances", async ({
  page,
  context,
}) => {
  const fundingAddress = payments.p2wpkh({
    hash: Buffer.alloc(20, 3),
    network: networks.testnet,
  }).address!;
  let available = 0;
  let reserved = 0;
  let fail = false;
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.route("**/api/predictions", (route) =>
    route.fulfill({ json: [] }),
  );
  await page.route("**/api/prices", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/admin/escrow", (route) => {
    expect(route.request().headers().authorization).toBe(
      "Bearer fixture-token",
    );
    return route.fulfill(
      fail
        ? { status: 503, json: { error: "Reserve index unavailable" } }
        : {
            json: {
              configured: true,
              funding_address: fundingAddress,
              balance_sats: available + reserved,
              available_sats: available,
              reserved_sats: reserved,
              utxo_count: available + reserved ? 1 : 0,
              max_stake_sats: 1000000,
            },
          },
    );
  });
  await page.addInitScript(() =>
    sessionStorage.setItem("admin-token", "fixture-token"),
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Demo", exact: true }).click();
  const reserves = page.getByRole("region", {
    name: "Escrow reserves",
    exact: true,
  });
  await expect(
    reserves.getByText(fundingAddress, { exact: true }),
  ).toBeVisible();
  await expect(reserves.getByText("Awaiting confirmed reserves")).toBeVisible();
  await reserves.getByRole("button", { name: "Copy funding address" }).click();
  await expect(reserves.getByRole("status")).toHaveText(
    "Funding address copied.",
  );
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    fundingAddress,
  );
  available = 1000000;
  await reserves
    .getByRole("button", { name: "Refresh escrow reserves" })
    .click();
  await expect(
    reserves.getByText("1 confirmed reserve output", { exact: true }),
  ).toBeVisible();
  await expect(
    reserves.locator(".reserve-balances > div").nth(1),
  ).toContainText("1,000,000 sats");
  available = 0;
  reserved = 100000;
  await reserves
    .getByRole("button", { name: "Refresh escrow reserves" })
    .click();
  await expect(
    reserves.getByText("Reserved for pending participation", { exact: true }),
  ).toBeVisible();
  await expect(reserves.getByText("Awaiting confirmed reserves")).toHaveCount(
    0,
  );
  await expect(
    reserves.locator(".reserve-balances > div").nth(0),
  ).toContainText("100,000 sats");
  available = 1000000;
  reserved = 0;
  fail = true;
  await reserves
    .getByRole("button", { name: "Refresh escrow reserves" })
    .click();
  await expect(reserves.getByRole("alert")).toHaveText(
    "Reserve index unavailable",
  );
  fail = false;
  await reserves
    .getByRole("button", { name: "Refresh escrow reserves" })
    .click();
  await expect(reserves.getByRole("alert")).toHaveCount(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect(
      reserves.getByText(fundingAddress, { exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: `test-results/escrow-reserves-${width}.png`,
      fullPage: true,
    });
  }
});

test("Liquid testnet isolates regtest positions and disables unsupported host matching", async ({
  page,
}) => {
  const genesis =
    "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
  const now = Math.floor(Date.now() / 1000);
  const legacy = JSON.stringify({
    selected: "regtest-market",
    stake: "0.002",
    fundedPredictionId: "regtest-market",
    positionOutpoint: `${"11".repeat(32)}:0`,
  });
  const legacySweep = JSON.stringify({
    marketId: "regtest-market",
    positionOutpoint: `${"11".repeat(32)}:0`,
  });
  await page.route("**/api/config", (route) =>
    route.fulfill({
      json: {
        policy_asset_id: networks.testnet.assetHash,
        genesis_block_hash: genesis,
        network: "liquidtestnet",
        oracle_url: "https://api.oracle-0.dev.blockstream.com",
        matched_escrow_enabled: false,
      },
    }),
  );
  await page.route("**/api/predictions", (route) =>
    route.fulfill({
      json: [
        {
          id: "testnet-market",
          title: "Testnet market",
          deadline: now + 3600,
          created_at: now,
          resolution: null,
        },
      ],
    }),
  );
  await page.route("**/api/prices", (route) =>
    route.fulfill({
      json: [
        {
          id: 0,
          symbol: "LBTC/USD",
          base: "LBTC",
          quote: "USD",
          decimals: 8,
          kind: "direct",
        },
        {
          id: 7,
          symbol: "USDC/USD",
          base: "USDC",
          quote: "USD",
          decimals: 8,
          kind: "direct",
        },
      ],
    }),
  );
  await page.route("**/api/prices/0", (route) =>
    route.fulfill({
      json: {
        main: {
          feed: {
            feed_id: 0,
            decimals: 8,
            price: 10000000000,
            received_at: now,
            valid_until: now + 300,
          },
        },
      },
    }),
  );
  await page.addInitScript(
    ({ legacy, legacySweep }) => {
      localStorage.setItem("signal-market:user-state:v3", legacy);
      localStorage.setItem("signal-market:house-sweep:v1", legacySweep);
      sessionStorage.setItem("admin-token", "fixture-token");
    },
    { legacy, legacySweep },
  );

  await page.goto("/");
  await expect(page.getByLabel("Stake, LBTC")).toHaveValue("0.001");
  await expect(
    page.getByRole("button", {
      name: "Host matching unavailable",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(page.getByText("Winning payout", { exact: true })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "View active position", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Demo", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: "Feed", exact: true }),
  ).toHaveValue("0");
  await expect(
    page.getByRole("textbox", { name: "Position outpoint", exact: true }),
  ).toHaveValue("");
  expect(
    await page.evaluate(() =>
      localStorage.getItem("signal-market:user-state:v3"),
    ),
  ).toBe(legacy);
  expect(
    await page.evaluate(() =>
      localStorage.getItem("signal-market:house-sweep:v1"),
    ),
  ).toBe(legacySweep);
  const testnetState = await page.evaluate(
    (genesis) =>
      JSON.parse(
        localStorage.getItem(`signal-market:user-state:v3:${genesis}`)!,
      ),
    genesis,
  );
  expect(testnetState.fundedPredictionId).toBe("");
});

test("new positions lock a host-matched escrow and sign only holder inputs", async ({
  page,
}) => {
  const now = Math.floor(Date.now() / 1000);
  const policy = "66".repeat(32);
  const publicKey = Buffer.from(
    ecc.pointFromScalar(Buffer.alloc(32, 1), true)!,
  );
  const payment = payments.p2wpkh({
    pubkey: publicKey,
    network: networks.regtest,
  });
  const wallet = {
    chainId: "escrow-regtest",
    accountIdentifier: "escrow-holder",
    policyAssetId: policy,
    address: payment.address!,
    scriptPubKey: payment.output!.toString("hex"),
    publicKey: publicKey.toString("hex"),
    masterFingerprint: "11223344",
    derivationPath: "m/84'/1'/0'/0/0",
  };
  const market = {
    id: "77".repeat(32),
    title: "Matched price position",
    deadline: now + 3600,
    created_at: now,
    resolution: null,
    price: {
      feed_id: 0,
      decimals: 8,
      strike: "10000000000",
      above: true,
      opens_at: now - 60,
      claim_grace: 600,
      house_script_pubkey: "0014" + "88".repeat(20),
      tick_asset_id: "22".repeat(32),
      verifier_asset_id: "33".repeat(32),
      storm_eye_asset_id: "44".repeat(32),
    },
  };
  const holderTransaction = new Transaction();
  holderTransaction.addInput(Buffer.alloc(32, 0xaa), 0);
  holderTransaction.addOutput(
    payment.output!,
    ElementsValue.fromNumber(1000000).bytes,
    Buffer.concat([Buffer.from([1]), Buffer.alloc(32, 0x66)]),
    Buffer.from([0]),
  );
  const holderTxid = holderTransaction.getId();
  const fundingTxid = "bb".repeat(32);
  let signed = false;
  let rejectSigning = true;
  let reserved = false;
  let cancellations = 0;
  await page.route("**/api/predictions", (route) =>
    route.fulfill({ json: [market] }),
  );
  await page.route("**/api/prices/0", (route) =>
    route.fulfill({
      json: {
        main: {
          feed: {
            feed_id: 0,
            decimals: 8,
            price: 10000000000,
            received_at: now,
            valid_until: now + 300,
          },
        },
      },
    }),
  );
  await page.route("**/api/chain/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith(`/tx/${holderTxid}/hex`))
      return route.fulfill({ body: holderTransaction.toHex() });
    return route.fulfill({
      json: path.endsWith("/status")
        ? { confirmed: true, block_height: 100 }
        : path.endsWith("/blocks/tip/height")
          ? 100
          : { spent: false },
    });
  });
  await page.route("**/api/predictions/*/contract", (route) =>
    route.fulfill({
      json: {
        script_pubkey: "5120" + "99".repeat(32),
        tick_asset_id: market.price.tick_asset_id,
        tick_script_pubkey: "51",
        confidential_payout: false,
      },
    }),
  );
  await page.route("**/api/predictions/*/escrow", (route) => {
    expect(reserved).toBe(false);
    reserved = true;
    const request = route.request().postDataJSON();
    expect(request.stake_sats).toBe(100000);
    const pset = Pset.fromBase64(request.pset);
    expect(pset.outputs[0].value).toBe(100000);
    pset.outputs[0].value = 200000;
    const input = new PsetInput(Buffer.alloc(32, 0xcc), 0);
    input.sighashType = 1;
    input.witnessUtxo = {
      script: Buffer.from(market.price.house_script_pubkey, "hex"),
      asset: Buffer.concat([Buffer.from([1]), pset.outputs[0].asset!]),
      value: ElementsValue.fromNumber(100000).bytes,
      nonce: Buffer.from([0]),
    };
    pset.addInput(input);
    return route.fulfill({
      json: {
        funding_id: "fixture-escrow",
        pset: pset.toBase64(),
        escrow_sats: 200000,
      },
    });
  });
  await page.route("**/api/predictions/*/escrow/fixture-escrow", (route) => {
    expect(route.request().method()).toBe("DELETE");
    expect(signed).toBe(false);
    reserved = false;
    cancellations += 1;
    return route.fulfill({ status: 204 });
  });
  await page.route("**/api/predictions/*/escrow/commit", (route) => {
    expect(signed).toBe(true);
    expect(reserved).toBe(true);
    reserved = false;
    const request = route.request().postDataJSON();
    expect(request.funding_id).toBe("fixture-escrow");
    expect(Pset.fromBase64(request.pset).outputs[0].value).toBe(200000);
    return route.fulfill({ json: { txid: fundingTxid } });
  });
  await page.exposeBinding(
    "escrowWallet",
    async (
      _source,
      args: {
        method: string;
        params?: {
          request?: {
            method: string;
            params: {
              pset?: string;
              broadcast?: boolean;
              signInputs?: Array<{ index: number }>;
            };
          };
        };
      },
    ) => {
      if (args.method === "wallet_getSession")
        return {
          sessionScopes: {
            [wallet.chainId]: {
              accounts: [wallet.accountIdentifier],
              methods: [
                "getWalletDescriptor",
                "getUTXOs",
                "signMessage",
                "signPset",
              ],
            },
          },
        };
      const request = args.params?.request;
      if (request?.method === "getUTXOs")
        return {
          chainId: wallet.chainId,
          accountIdentifier: wallet.accountIdentifier,
          policyAssetId: `${wallet.chainId}/elip144:${policy}`,
          utxos: [
            {
              txid: holderTxid,
              vout: 0,
              address: wallet.address,
              amount: "1000000",
              assetId: policy,
              confidential: false,
              scriptPubKey: wallet.scriptPubKey,
              spendable: true,
              txOut: "output",
            },
          ],
        };
      if (request?.method === "signPset") {
        expect(request.params.broadcast).toBe(false);
        expect(request.params.signInputs?.map((input) => input.index)).toEqual([
          0,
        ]);
        const pset = Pset.fromBase64(request.params.pset!);
        expect(pset.inputs).toHaveLength(2);
        expect(pset.outputs).toHaveLength(4);
        expect(pset.inputs.every((input) => input.witnessUtxo)).toBe(true);
        expect(pset.outputs[0].value).toBe(200000);
        expect(pset.outputs[2].value).toBe(889000);
        if (rejectSigning) throw new Error("Signing rejected");
        signed = true;
        return { pset: request.params.pset };
      }
      throw new Error(`Unexpected escrow wallet request: ${args.method}`);
    },
  );
  await page.addInitScript(
    ({ wallet, market }) => {
      localStorage.setItem("storm-humid-regtest-chain", wallet.chainId);
      localStorage.setItem(
        "storm-humid-regtest-backend",
        "http://127.0.0.1:3100/api/chain",
      );
      localStorage.setItem(
        "signal-market:user-state:v3",
        JSON.stringify({
          wallet,
          walletScript: wallet.scriptPubKey,
          selected: market.id,
          stake: "0.001",
          account: {
            network: "elementsregtest",
            script_pubkey: "51",
            tick_asset_id: market.price.tick_asset_id,
            tick_script_pubkey: "51",
          },
        }),
      );
      const bridge = window as unknown as {
        escrowWallet: (args: unknown) => Promise<unknown>;
        humid: unknown;
      };
      bridge.humid = {
        request: (args: unknown) => bridge.escrowWallet(args),
        on: () => () => {},
      };
    },
    { wallet, market },
  );
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Participate" })).toBeEnabled();
  await expect(page.getByText("Oracle fee", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Funding fee", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Settlement fee", { exact: true })).toHaveCount(
    0,
  );
  await page.getByRole("button", { name: "Participate" }).click();
  await expect(page.locator(".notice.error")).toContainText("Signing rejected");
  await expect(page.getByRole("button", { name: "Participate" })).toBeEnabled();
  expect(cancellations).toBe(1);
  expect(reserved).toBe(false);
  expect(signed).toBe(false);
  rejectSigning = false;
  await page.getByRole("button", { name: "Participate" }).click();
  await expect(
    page.getByRole("button", { name: "Request price proof" }),
  ).toBeEnabled();
  expect(cancellations).toBe(1);
  const state = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("signal-market:user-state:v3")!),
  );
  expect(state.positionUtxo.amount_sats).toBe(200000);
  expect(state.positionUtxo.stake_sats).toBe(100000);
  expect(state.feeOutpoint).toBe(`${fundingTxid}:1`);
  await expect(page.locator(".order-panel")).toContainText("0.00200000 LBTC");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: `test-results/matched-escrow-${width}.png`,
      fullPage: true,
    });
  }
});

test("price proof survives reload, resumes once and signs only the wallet fee input", async ({
  page,
}, testInfo) => {
  const now = Math.floor(Date.now() / 1000);
  const secret = Buffer.alloc(32, 1);
  const publicKey = Buffer.from(ecc.pointFromScalar(secret, true)!);
  const walletPayment = payments.p2wpkh({
    pubkey: publicKey,
    network: networks.regtest,
  });
  const policy = "66".repeat(32);
  const verifier = "33".repeat(32);
  const txid = "ab".repeat(32);
  const issuance = "cd".repeat(32);
  const claimTxid = "ef".repeat(32);
  const wallet = {
    chainId: "fixture-regtest",
    accountIdentifier: "public-fixture",
    policyAssetId: policy,
    address: walletPayment.address!,
    scriptPubKey: walletPayment.output!.toString("hex"),
    publicKey: publicKey.toString("hex"),
    masterFingerprint: "11223344",
    derivationPath: "m/84'/1'/0'/0/0",
  };
  const terms = {
    feed_id: 0,
    decimals: 8,
    strike: "10000000000",
    above: true,
    opens_at: now - 60,
    claim_grace: 600,
    house_script_pubkey: "0014" + "11".repeat(20),
    tick_asset_id: "22".repeat(32),
    verifier_asset_id: verifier,
    storm_eye_asset_id: "44".repeat(32),
  };
  const market = {
    id: "77".repeat(32),
    title: "Will LBTC/USD reach 100?",
    created_at: now,
    deadline: now + 3600,
    resolution: null,
    price: terms,
  };
  const position = {
    txid,
    vout: 0,
    script_pubkey: "51",
    asset: policy,
    amount_sats: 50000,
  };
  const fee = {
    txid,
    vout: 2,
    script_pubkey: wallet.scriptPubKey,
    asset: policy,
    amount_sats: 2000,
  };
  const bytes = Buffer.alloc(32);
  bytes.writeUInt32BE(0, 0);
  bytes.writeUInt32BE(8, 4);
  bytes.writeBigUInt64BE(10000000000n, 8);
  bytes.writeBigUInt64BE(BigInt(now), 16);
  bytes.writeBigUInt64BE(BigInt(now + 300), 24);
  const tag = createHash("sha256").update("OracleNetworkV1/Price").digest();
  const message = createHash("sha256")
    .update(Buffer.concat([tag, tag, bytes]))
    .digest();
  const signedPrice = {
    price_data: bytes.toString("hex"),
    storm_tree_bloom: {
      branch: publicKey.subarray(1).toString("hex"),
      signature: Buffer.from(ecc.signSchnorr(message, secret)).toString("hex"),
      proof: [],
    },
  };
  const pset = Creator.newPset({
    inputs: [
      new CreatorInput(txid, 0),
      new CreatorInput(issuance, 3),
      new CreatorInput(issuance, 4),
      new CreatorInput(txid, 2),
    ],
    outputs: [
      new CreatorOutput(policy, 50000, walletPayment.output!),
      new CreatorOutput(verifier, 1, Buffer.from("6a0400000001", "hex")),
      new CreatorOutput(
        terms.tick_asset_id,
        now + 3599,
        Buffer.from("6a0400000002", "hex"),
      ),
    ],
  });
  let executed = false;
  let tickTime = now + 3600;
  let submissions = 0;
  const approvals: string[] = [];
  page.on("request", (request) =>
    expect(request.url()).not.toContain(":18884"),
  );
  await page.route("**/api/predictions", (route) =>
    route.fulfill({ json: [market] }),
  );
  await page.route("**/api/prices/0", (route) =>
    route.fulfill({
      json: {
        main: {
          feed: {
            feed_id: 0,
            decimals: 8,
            price: 10000000000,
            received_at: now,
            valid_until: now + 7200,
          },
        },
      },
    }),
  );
  await page.route("**/users/requests", async (route) => {
    const request = route.request().postDataJSON();
    expect(request.requests.map((item: { kind: string }) => item.kind)).toEqual(
      ["signed-price-data", "tick-utxo"],
    );
    expect(JSON.parse(request.requests[0].payload).price_feed_id).toBe(0);
    submissions += 1;
    await route.fulfill({ json: { request_hash: "99".repeat(32) } });
  });
  await page.route("**/users/requests/*", (route) =>
    route.fulfill({
      json: {
        status: executed ? "executed" : "pending",
        payload: executed
          ? JSON.stringify({
              txid: issuance,
              results: [
                {
                  kind: "signed-price-data",
                  vout: 3,
                  payload: JSON.stringify(signedPrice),
                },
                {
                  kind: "tick-utxo",
                  vout: 4,
                  payload: JSON.stringify({ timestamp: tickTime }),
                },
              ],
            })
          : null,
      },
    }),
  );
  await page.route("**/api/chain/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (
      path.endsWith("/outspend/0") ||
      path.endsWith("/outspend/1") ||
      path.endsWith("/outspend/2") ||
      path.endsWith("/outspend/3") ||
      path.endsWith("/outspend/4")
    )
      return route.fulfill({ json: { spent: false } });
    if (path.endsWith("/status"))
      return route.fulfill({ json: { confirmed: true, block_height: 100 } });
    if (path.endsWith("/blocks/tip/height"))
      return route.fulfill({ json: 100 });
    return route.fulfill({
      json: {
        status: { confirmed: true },
        vout: path.endsWith(issuance)
          ? [
              {},
              {},
              {},
              {
                value: 1,
                asset: verifier,
                scriptpubkey: "5120" + "55".repeat(32),
              },
              {
                value: tickTime,
                asset: terms.tick_asset_id,
                scriptpubkey: "5120" + "66".repeat(32),
              },
            ]
          : [
              { value: 50000, asset: policy, scriptpubkey: "51" },
              { value: 10000, asset: policy, scriptpubkey: "51" },
              { value: 2000, asset: policy, scriptpubkey: wallet.scriptPubKey },
            ],
      },
    });
  });
  await page.route("**/api/predictions/*/claim", async (route) => {
    const request = route.request().postDataJSON();
    expect(request.signed_price.price_data).toBe(signedPrice.price_data);
    expect(request.voucher.amount_sats).toBe(1);
    expect(request.voucher.asset).toBe(verifier);
    expect(request.tick.asset).toBe(terms.tick_asset_id);
    expect(request.tick.amount_sats).toBe(now + 3599);
    expect(request.tick.vout).toBe(4);
    await route.fulfill({ json: { pset: pset.toBase64() } });
  });
  await page.exposeBinding(
    "priceTestWallet",
    async (
      _source,
      args: {
        method: string;
        params?: {
          request?: {
            method: string;
            params: {
              message?: string;
              signInputs?: Array<{ index: number }>;
              pset?: string;
            };
          };
        };
      },
    ) => {
      if (args.method === "wallet_getSession")
        return {
          sessionScopes: {
            [wallet.chainId]: {
              accounts: [wallet.accountIdentifier],
              methods: [
                "getWalletDescriptor",
                "getUTXOs",
                "signMessage",
                "signPset",
              ],
            },
          },
        };
      const request = args.params?.request;
      if (request?.method === "signMessage") {
        approvals.push("message");
        expect(request.params.message).toContain("signed-price-data");
        expect(request.params.message).toContain("tick-utxo");
        return {
          address: wallet.address,
          protocol: "ecdsa",
          signatureEncoding: "hex-recoverable-ecdsa-65",
          signature: "11".repeat(65),
        };
      }
      if (request?.method === "signPset") {
        expect(request.params.signInputs?.map(({ index }) => index)).toEqual([
          3,
        ]);
        approvals.push("claim");
        return { pset: request.params.pset, txid: claimTxid };
      }
      if (request?.method === "getUTXOs")
        return {
          chainId: wallet.chainId,
          accountIdentifier: wallet.accountIdentifier,
          policyAssetId: `${wallet.chainId}/elip144:${policy}`,
          utxos: [],
        };
      throw new Error(`Unexpected wallet request ${args.method}`);
    },
  );
  await page.addInitScript(
    ({ wallet, position, fee, market, txid }) => {
      localStorage.setItem("storm-humid-regtest-chain", wallet.chainId);
      localStorage.setItem(
        "storm-humid-regtest-backend",
        "http://127.0.0.1:3100/api/chain",
      );
      if (!localStorage.getItem("signal-market:user-state:v3"))
        localStorage.setItem(
          "signal-market:user-state:v3",
          JSON.stringify({
            wallet,
            walletScript: wallet.scriptPubKey,
            account: {
              network: "elementsregtest",
              script_pubkey: "51",
              tick_asset_id: market.price.tick_asset_id,
              oracle_verifier_asset_id: market.price.verifier_asset_id,
              storm_eye_asset_id: market.price.storm_eye_asset_id,
            },
            selected: market.id,
            fundedPredictionId: market.id,
            positionOutpoint: `${txid}:0`,
            positionUtxo: position,
            positionConfirmations: 1,
            redemptionFeeUtxo: fee,
            feeOutpoint: `${txid}:1`,
          }),
        );
      const bridge = window as unknown as {
        priceTestWallet: (args: unknown) => Promise<unknown>;
        humid: unknown;
      };
      bridge.humid = {
        request: (args: unknown) => bridge.priceTestWallet(args),
        on: () => () => {},
      };
    },
    { wallet, position, fee, market, txid },
  );
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "Request price proof" }),
  ).toBeEnabled();
  await expect(page.locator(".stage-list .stage")).toHaveCount(3);
  await expect(page.locator(".stage-list")).not.toContainText(
    "Price condition",
  );
  await expect(page.locator(".stage-list")).not.toContainText(
    "Oracle verification",
  );
  await expect(page.locator(".stage-list")).toContainText("Ready to request");
  await page.clock.install({ time: now * 1000 });
  await page.clock.setSystemTime((now + 3601) * 1000);
  await page.clock.runFor(1000);
  await expect(
    page.getByRole("button", { name: "Request price proof" }),
  ).toBeDisabled();
  await page.clock.setSystemTime(now * 1000);
  await page.clock.runFor(1000);
  await page.clock.resume();
  await page.getByRole("button", { name: "Request price proof" }).click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          JSON.parse(
            localStorage.getItem("signal-market:user-state:v3") ?? "{}",
          ).priceRequestHash,
      ),
    )
    .toBe("99".repeat(32));
  await expect(page.locator(".stage.pending")).toContainText("Price proof");
  await expect(page.locator(".stage.pending")).toContainText(
    "Waiting for signed price, Tick and Verifier",
  );
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: testInfo.outputPath(`price-request-${width}.png`),
      fullPage: true,
    });
  }
  await page.reload();
  await expect(page.locator(".stage.pending")).toContainText(
    "Request pending; ready to check again",
  );
  executed = true;
  await page.getByRole("button", { name: "Check price request" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "Tick is outside the signed price validity plus 55 minutes",
  );
  await expect(
    page.getByRole("button", { name: "Sign and claim" }),
  ).toHaveCount(0);
  tickTime = now + 3599;
  await page.getByRole("button", { name: "Check price request" }).click();
  await expect(
    page.getByRole("button", { name: "Sign and claim" }),
  ).toBeEnabled();
  await expect(
    page.locator(".stage.done").filter({ hasText: "Price proof" }),
  ).toContainText("Signed price, Tick and Verifier ready");
  await expect(
    page.locator(".stage").filter({ hasText: "Claim payout" }),
  ).toContainText("Ready to sign in Humid");
  expect(submissions).toBe(1);
  await page.clock.setSystemTime((now + 4201) * 1000);
  await page.clock.runFor(1000);
  await expect(
    page.getByRole("button", { name: "Sign and claim" }),
  ).toBeEnabled();
  await page.getByText("Oracle proof", { exact: true }).click();
  await expect(page.locator(".proof-details")).toContainText(issuance);
  await expect(page.locator(".proof-details")).toContainText(`${issuance}:4`);
  await expect(page.locator(".proof-details")).toContainText("Tick time");
  await expect(page.locator(".proof-details")).toContainText(
    "Extended price validity",
  );
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: testInfo.outputPath(`price-proof-${width}.png`),
      fullPage: true,
    });
  }
  await page.getByRole("button", { name: "Sign and claim" }).click();
  await expect(page.locator(".win-block strong")).toHaveText(
    "Position redeemed",
  );
  await expect(
    page.locator(".stage.done").filter({ hasText: "Claim payout" }),
  ).toContainText("Payout confirmed");
  expect(approvals).toEqual(["message", "claim"]);
  await page.reload();
  await expect(page.locator(".win-block strong")).toHaveText(
    "Position redeemed",
  );
  expect(
    await page.evaluate(
      () =>
        JSON.parse(localStorage.getItem("signal-market:user-state:v3") ?? "{}")
          .privateKey,
    ),
  ).toBeUndefined();
});

test("price desk controls fit desktop and mobile and never offer admin resolution", async ({
  page,
}, testInfo) => {
  const now = Math.floor(Date.now() / 1000);
  await page.addInitScript(() => {
    localStorage.setItem("signal-market:mode", "admin");
    sessionStorage.setItem("admin-token", "fixture-token");
  });
  await page.route("**/api/prices", (route) =>
    route.fulfill({
      json: [
        { id: 0, symbol: "LBTC/USD", decimals: 8 },
        { id: 7, symbol: "ETH/USD", decimals: 2 },
      ],
    }),
  );
  await page.route("**/api/prices/0", (route) =>
    route.fulfill({
      json: {
        main: {
          feed: {
            feed_id: 0,
            decimals: 8,
            price: 1234567890000,
            received_at: now,
            valid_until: now + 7200,
          },
        },
      },
    }),
  );
  await page.route("**/api/prices/7", (route) =>
    route.fulfill({
      json: {
        main: {
          feed: {
            feed_id: 7,
            decimals: 2,
            price: 234567,
            received_at: now,
            valid_until: now + 7200,
          },
        },
      },
    }),
  );
  await page.route("**/api/predictions", (route) =>
    route.fulfill({
      json: [
        {
          id: "77".repeat(32),
          title: "Oracle touch",
          deadline: 2000000000,
          created_at: 1700000000,
          resolution: null,
          price: {
            feed_id: 0,
            decimals: 8,
            strike: "10000000000",
            above: true,
            opens_at: 1700000000,
            claim_grace: 600,
          },
        },
      ],
    }),
  );
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Publish a price market" }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Resolve Yes" })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("combobox", { name: "Feed", exact: true }),
  ).toHaveValue("0");
  const currentPrice = page.getByRole("status", { name: "Current feed price" });
  await expect(currentPrice).toContainText("12,345.6789");
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: testInfo.outputPath(`price-desk-${width}.png`),
      fullPage: true,
    });
  }
  await page
    .getByRole("combobox", { name: "Feed", exact: true })
    .selectOption("7");
  await expect(currentPrice).toContainText("2,345.67");
  await expect(currentPrice).not.toContainText("12,345.6789");
});

test("price desk loads the first available feed and refreshes only current quotes", async ({
  page,
}) => {
  const now = Math.floor(Date.now() / 1000);
  let price = 234567;
  let validUntil = now + 7200;
  let unavailable = false;
  let releasePrice: () => void = () => {};
  const priceReady = new Promise<void>((resolve) => {
    releasePrice = resolve;
  });
  await page.clock.install({ time: now * 1000 });
  await page.addInitScript(() => {
    localStorage.setItem("signal-market:mode", "admin");
    sessionStorage.setItem("admin-token", "fixture-token");
  });
  await page.route("**/api/predictions", (route) =>
    route.fulfill({ json: [] }),
  );
  await page.route("**/api/prices", (route) =>
    route.fulfill({ json: [{ id: 7, symbol: "ETH/USD", decimals: 2 }] }),
  );
  await page.route("**/api/prices/7", async (route) => {
    await priceReady;
    if (unavailable)
      return route.fulfill({ status: 503, json: { error: "Offline" } });
    return route.fulfill({
      json: {
        main: {
          feed: {
            feed_id: 7,
            decimals: 2,
            price,
            received_at: now,
            valid_until: validUntil,
          },
        },
      },
    });
  });
  await page.goto("/");
  const currentPrice = page.getByRole("status", { name: "Current feed price" });
  await expect(
    page.getByRole("combobox", { name: "Feed", exact: true }),
  ).toHaveValue("7");
  await expect(currentPrice).toContainText("Loading...");
  releasePrice();
  await expect(currentPrice).toContainText("2,345.67");

  price = 245678;
  validUntil = now + 6;
  await page.clock.runFor(5000);
  await expect(currentPrice).toContainText("2,456.78");
  await page.clock.runFor(2000);
  await expect(currentPrice).toContainText("Unavailable");

  unavailable = true;
  await page.clock.runFor(3000);
  await expect(currentPrice).toContainText("Unavailable");
  unavailable = false;
  validUntil = now + 7200;
  await page.clock.runFor(5000);
  await expect(currentPrice).toContainText("2,456.78");

  unavailable = true;
  await page.clock.runFor(5000);
  await expect(currentPrice).toContainText("Unavailable");
});
