import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { expect, test, type Page } from "@playwright/test";
import { ECPairFactory } from "ecpair";
import * as ecc from "@bitcoinerlab/secp256k1";
import {
  address as liquidAddress,
  Blinder,
  confidential,
  networks,
  payments,
  Pset,
  Extractor,
  Finalizer,
  Signer,
  script,
  Transaction,
  Updater,
  ZKPGenerator,
  ZKPValidator,
} from "liquidjs-lib";
import BIP32Factory from "bip32";
import { ElementsRpcClient } from "@price-oracle/sdk";
import { descriptorChecksum } from "../src/humid";

const rpcUrl = process.env.TEST_ELEMENTS_RPC ?? "http://127.0.0.1:18884";
const rpcUser = process.env.TEST_RPC_USER ?? "high-storm";
const rpcPassword = process.env.TEST_RPC_PASSWORD ?? "high-storm";
const stateKey = "signal-market:user-state:v3";
const zkpFactory: typeof import("@vulpemventures/secp256k1-zkp").default =
  createRequire(import.meta.url)("@vulpemventures/secp256k1-zkp").default;

async function rpc<Result>(
  method: string,
  params: unknown[] = [],
  wallet = false,
): Promise<Result> {
  const response = await fetch(
    `${rpcUrl}${wallet ? `/wallet/${process.env.TEST_FUNDING_WALLET ?? "bootstrap"}` : ""}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Basic ${Buffer.from(`${rpcUser}:${rpcPassword}`).toString("base64")}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    },
  );
  const body = (await response.json()) as {
    result: Result;
    error: { message: string } | null;
  };
  if (!response.ok || body.error)
    throw new Error(`${method}: ${body.error?.message ?? response.status}`);
  return body.result;
}

function localDate(timestamp: number) {
  const date = new Date(timestamp);
  const part = (value: number) => value.toString().padStart(2, "0");
  const seconds = date.getSeconds();
  return `${date.getFullYear()}-${part(date.getMonth() + 1)}-${part(date.getDate())}T${part(date.getHours())}:${part(date.getMinutes())}${seconds ? `:${part(seconds)}` : ""}`;
}

async function mine() {
  const address = await rpc<string>("getnewaddress", ["", "bech32"], true);
  await rpc("generatetoaddress", [1, address]);
  const height = await rpc<number>("getblockcount");
  await expect
    .poll(async () => {
      const response = await fetch(
        `${process.env.TEST_ESPLORA_URL ?? "http://127.0.0.1:3001"}/blocks/tip/height`,
      );
      return Number(await response.text());
    })
    .toBeGreaterThanOrEqual(height);
}

async function walletState(page: Page) {
  return page.evaluate((key) => {
    const state = JSON.parse(localStorage.getItem(key) ?? "{}");
    return {
      positionOutpoint: state.positionOutpoint as string,
      redemptionTxid: state.redemptionTxid as string,
      redemptionConfirmations: state.redemptionConfirmations as number,
      tickTxid: state.tick?.txid as string | undefined,
    };
  }, stateKey);
}

test("local datetime values round-trip through browser inputs", async ({
  page,
}) => {
  await page.setContent(
    '<input type="datetime-local" aria-label="Date and time" step="1">',
  );
  const input = page.getByLabel("Date and time");

  for (const [seconds, expected] of [
    [0, "2026-10-12T11:34"],
    [1, "2026-10-12T11:34:01"],
    [59, "2026-10-12T11:34:59"],
  ] as const) {
    const timestamp = new Date(2026, 9, 12, 11, 34, seconds, 999).getTime();
    const value = localDate(timestamp);

    expect(value).toBe(expected);
    await input.fill(value);
    await expect(input).toHaveValue(expected);
  }
});

test("restored legacy Humid sessions require backend approval without losing the position", async ({
  page,
}) => {
  const root = BIP32Factory(ecc).fromSeed(
    new Uint8Array(randomBytes(32)),
    networks.regtest,
  );
  const node = root.derivePath("m/84'/1'/0'/0/0");
  const publicKey = Buffer.from(node.publicKey);
  const payment = payments.p2wpkh({
    pubkey: publicKey,
    network: networks.regtest,
  });
  const wallet = {
    chainId: "legacy-regtest",
    accountIdentifier: "disposable-account",
    policyAssetId: "66".repeat(32),
    address: payment.address!,
    scriptPubKey: payment.output!.toString("hex"),
    publicKey: publicKey.toString("hex"),
    masterFingerprint: Buffer.from(root.fingerprint).toString("hex"),
    derivationPath: "m/84'/1'/0'/0/0",
  };
  const txid = "ab".repeat(32);
  const tickTxid = "cd".repeat(32);
  await page.route("**/api/predictions", (route) =>
    route.fulfill({
      json: [
        {
          id: "saved-position",
          title: "Saved position",
          deadline: 2_000_000_000,
          created_at: 1_790_000_000,
          resolution: null,
        },
      ],
    }),
  );
  await page.addInitScript(
    ({ wallet, txid, tickTxid, stateKey }) => {
      if (!localStorage.getItem(stateKey)) {
        localStorage.setItem("storm-humid-regtest-chain", wallet.chainId);
        localStorage.setItem(
          stateKey,
          JSON.stringify({
            wallet,
            selected: "saved-position",
            fundedPredictionId: "saved-position",
            positionOutpoint: `${txid}:0`,
            positionConfirmations: 1,
            positionUtxo: {
              txid,
              vout: 0,
              amount_sats: 100_000,
              asset: wallet.policyAssetId,
              script_pubkey: wallet.scriptPubKey,
            },
            tick: { txid: tickTxid, vout: 0, timestamp: 1_790_000_000 },
          }),
        );
      }
      Object.defineProperty(window, "humid", {
        configurable: true,
        value: {
          request: async ({ method }: { method: string }) => {
            if (method !== "wallet_getSession")
              throw new Error("Unexpected wallet request");
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
          },
        },
      });
    },
    { wallet, txid, tickTxid, stateKey },
  );
  await page.goto(process.env.VITE_TEST_URL ?? "http://127.0.0.1:5173", {
    waitUntil: "networkidle",
  });
  const connect = page
    .getByRole("region", { name: "Wallet summary" })
    .getByRole("button", { name: "Connect Humid", exact: true });
  await expect(connect).toBeVisible();
  await expect
    .poll(() => walletState(page))
    .toMatchObject({ positionOutpoint: `${txid}:0`, tickTxid });
  await page.reload({ waitUntil: "networkidle" });
  await expect(connect).toBeVisible();
  await expect
    .poll(() => walletState(page))
    .toMatchObject({ positionOutpoint: `${txid}:0`, tickTxid });
});

test("settles event and oracle price markets through Humid with fragmented wallet outputs", async ({
  page,
}, testInfo) => {
  test.setTimeout(600_000);
  page.on("request", (request) =>
    expect(request.url()).not.toContain(":18884"),
  );
  const chain = await rpc<{ chain: string }>("getblockchaininfo");
  expect(chain.chain).toBe("elementsregtest");
  const root = BIP32Factory(ecc).fromSeed(randomBytes(32), networks.regtest);
  const accountNode = root.derivePath("m/84'/1'/0'");
  const key = Buffer.from(accountNode.derive(0).derive(0).privateKey!);
  const pair = ECPairFactory(ecc).fromPrivateKey(key, {
    network: networks.regtest,
  });
  const { address, output } = payments.p2wpkh({
    pubkey: Buffer.from(pair.publicKey),
    network: networks.regtest,
  });
  expect(address).toBeTruthy();
  const walletScript = output!.toString("hex");
  const confidentialAddress = liquidAddress.toConfidential(
    address!,
    Buffer.from(pair.publicKey),
  );
  const library = await zkpFactory();
  const nonzero = (result: Uint8Array | null): Uint8Array => {
    if (!result) throw new Error("Invalid blinding scalar or point");
    return result;
  };
  const zkp = {
    ...library,
    ecc: {
      ...library.ecc,
      privateAdd: (secret: Uint8Array, tweak: Uint8Array) =>
        nonzero(library.ecc.privateAdd(secret, tweak)),
      privateSub: (secret: Uint8Array, tweak: Uint8Array) =>
        nonzero(library.ecc.privateSub(secret, tweak)),
      pointFromScalar: (scalar: Uint8Array, compressed?: boolean) =>
        nonzero(library.ecc.pointFromScalar(scalar, compressed)),
    },
  };
  const unblinder = new confidential.Confidential(zkp);
  const expression = `elwpkh([${Buffer.from(root.fingerprint).toString("hex")}/84h/1h/0h]${accountNode.neutered().toBase58()}/0/*)`;
  const { pegged_asset: policyAsset } = await rpc<{ pegged_asset: string }>(
    "getsidechaininfo",
  );
  const chainId = "bip122:humid-regtest-test";
  const policyAssetId = `${chainId}/elip144:${policyAsset}`;
  const accountIdentifier = "humid-test-account";
  const methods = [
    "getWalletDescriptor",
    "getUTXOs",
    "signMessage",
    "signPset",
  ];
  const approvals: Array<{ method: string; indexes?: number[] }> = [];
  let approved = false;
  let rejectNextSignature = true;
  await page.exposeBinding(
    "humidTestRequest",
    async (
      _source,
      args: {
        method: string;
        params?: {
          scope?: string;
          request?: {
            method: string;
            params: {
              assetId?: string;
              message?: string;
              pset?: string;
              signInputs?: Array<{ index: number; address: string }>;
              broadcast?: boolean;
            };
          };
        };
      },
    ) => {
      if (args.method === "wallet_addChain") {
        expect(args.params).toMatchObject({
          settings: { network: "regtest", policyAsset },
        });
        return { chainId };
      }
      if (args.method === "wallet_createSession") {
        approved = true;
        return {};
      }
      if (args.method === "wallet_revokeSession") {
        approved = false;
        return {};
      }
      if (args.method === "wallet_getSession")
        return {
          sessionScopes: approved
            ? { [chainId]: { methods, accounts: [accountIdentifier] } }
            : {},
        };
      expect(approved).toBe(true);
      expect(args.params?.scope).toBe(chainId);
      const request = args.params!.request!;
      if (request.method === "getWalletDescriptor")
        return {
          chainId,
          accountIdentifier,
          policyAssetId,
          descriptors: [
            {
              descriptorType: "publicWalletDescriptor",
              format: "bip380-split-branches",
              branchLayout: "split",
              branchDescriptors: [
                {
                  branch: "external",
                  change: 0,
                  descriptor: `${expression}#${descriptorChecksum(expression)}`,
                },
              ],
            },
          ],
        };
      if (request.method === "getUTXOs") {
        expect(request.params.assetId).toBe(policyAssetId);
        const outputs = await new ElementsRpcClient({
          url: rpcUrl,
          username: rpcUser,
          password: rpcPassword,
        }).getScriptUtxos(walletScript);
        return {
          chainId,
          accountIdentifier,
          policyAssetId,
          utxos: await Promise.all(
            outputs.map(async (utxo) => {
              const transaction = Transaction.fromHex(
                await rpc<string>("getrawtransaction", [utxo.txid]),
              );
              const previous = transaction.outs[utxo.vout];
              const blinded = previous.nonce.length > 1;
              const secrets = blinded
                ? unblinder.unblindOutputWithKey(previous, key)
                : undefined;
              return {
                txid: utxo.txid,
                vout: utxo.vout,
                address: confidentialAddress,
                amount: secrets?.value ?? String(utxo.amountSats),
                assetId: `${chainId}/elip144:${secrets ? Buffer.from(secrets.asset).reverse().toString("hex") : utxo.asset}`,
                confidential: blinded,
                scriptPubKey: walletScript,
                spendable: true,
                txOut: "",
              };
            }),
          ),
        };
      }
      if (request.method === "signMessage") {
        approvals.push({ method: request.method });
        const message = Buffer.from(request.params.message!, "utf8");
        const length =
          message.length < 253
            ? Buffer.of(message.length)
            : Buffer.of(253, message.length & 255, message.length >> 8);
        const digest = createHash("sha256")
          .update(
            createHash("sha256")
              .update(
                Buffer.concat([
                  Buffer.from("\x18Bitcoin Signed Message:\n"),
                  length,
                  message,
                ]),
              )
              .digest(),
          )
          .digest();
        const signed = ecc.signRecoverable(digest, key);
        return {
          address,
          protocol: "ecdsa",
          signatureEncoding: "hex-recoverable-ecdsa-65",
          signature: Buffer.concat([
            Buffer.from(signed.signature),
            Buffer.of(signed.recoveryId),
          ]).toString("hex"),
        };
      }
      if (request.method === "signPset") {
        expect(typeof request.params.broadcast).toBe("boolean");
        if (rejectNextSignature) {
          rejectNextSignature = false;
          throw new Error("Humid approval rejected");
        }
        const pset = Pset.fromBase64(request.params.pset!);
        const inputs = request.params.signInputs!;
        approvals.push({
          method: request.method,
          indexes: inputs.map((input) => input.index),
        });
        for (const input of inputs) {
          expect([address, confidentialAddress]).toContain(input.address);
          const index = input.index;
          if (!pset.inputs[index].witnessUtxo) {
            const txid = Buffer.from(pset.inputs[index].previousTxid)
              .reverse()
              .toString("hex");
            const previous = Transaction.fromHex(
              await rpc<string>("getrawtransaction", [txid]),
            );
            new Updater(pset).addInWitnessUtxo(
              index,
              previous.outs[pset.inputs[index].previousTxIndex],
            );
          }
          if (pset.inputs[index].sighashType === undefined)
            new Updater(pset).addInSighashType(index, 1);
        }
        if (pset.needsBlinding()) {
          const generator = new ZKPGenerator(
            zkp,
            ZKPGenerator.WithBlindingKeysOfInputs(inputs.map(() => key)),
          );
          const owned = generator.unblindInputs(
            pset,
            inputs.map((input) => input.index),
          );
          new Blinder(pset, owned, new ZKPValidator(zkp), generator).blindLast({
            outputBlindingArgs: generator.blindOutputs(
              pset,
              Pset.ECCKeysGenerator(ecc),
            ),
          });
        }
        for (const { index } of inputs) {
          new Signer(pset).addSignature(
            index,
            {
              partialSig: {
                pubkey: Buffer.from(pair.publicKey),
                signature: script.signature.encode(
                  Buffer.from(pair.sign(pset.getInputPreimage(index, 1))),
                  1,
                ),
              },
            },
            Pset.ECDSASigValidator(ecc),
          );
        }
        if (!request.params.broadcast) return { pset: pset.toBase64() };

        new Finalizer(pset).finalize();
        const broadcast = await fetch(
          `${process.env.TEST_CHAIN_BACKEND_URL ?? "http://127.0.0.1:3100/api/chain"}/tx`,
          {
            method: "POST",
            body: Extractor.extract(pset).toHex(),
          },
        );
        const txid = (await broadcast.text()).trim();
        expect(broadcast.ok, txid).toBe(true);
        expect(txid).toMatch(/^[0-9a-f]{64}$/i);
        return { pset: pset.toBase64(), txid };
      }
      throw new Error(`Unexpected Humid request ${request.method}`);
    },
  );
  await page.addInitScript(() => {
    const bridge = window as unknown as {
      humidTestRequest: (args: unknown) => Promise<unknown>;
      humid: unknown;
    };
    bridge.humid = {
      request: (args: unknown) => bridge.humidTestRequest(args),
      on: () => () => {},
    };
  });
  await rpc("sendtoaddress", [address, 0.0018], true);
  await mine();

  const unique = Date.now();
  const titles = [
    `Will the first checkpoint complete? ${unique}`,
    `Will the second checkpoint complete? ${unique}`,
  ];
  const deadline = localDate(Date.now() + 60 * 60 * 1000);
  await page.goto("/");
  await page.getByRole("button", { name: "Demo", exact: true }).click();
  await page
    .getByLabel("Login", { exact: true })
    .fill(process.env.TEST_ADMIN_LOGIN ?? "admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.TEST_ADMIN_PASSWORD ?? "prediction-demo");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Market desk", exact: true }),
  ).toBeVisible();
  for (const title of titles) {
    const eventForm = page.locator(".admin-create:not(.price-desk)");
    await eventForm.getByLabel("Question", { exact: true }).fill(title);
    await eventForm.getByLabel("Deadline", { exact: true }).fill(deadline);
    await page
      .getByRole("button", { name: "Publish prediction", exact: true })
      .click();
    await expect(
      page.locator(".resolution-row").filter({ hasText: title }),
    ).toBeVisible();
  }

  await page
    .getByRole("button", { name: "Back to Markets", exact: true })
    .click();
  await page
    .getByRole("region", { name: "Wallet summary" })
    .getByRole("button", { name: "Connect Humid", exact: true })
    .click();
  await expect(page.getByLabel("Public RPC", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("RPC user", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("RPC password", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Private key", { exact: true })).toHaveCount(0);
  await expect(
    page
      .getByRole("region", { name: "Wallet summary" })
      .getByRole("button", { name: "Connect Humid", exact: true }),
  ).toHaveCount(0);
  const settlements: string[] = [];

  for (const title of titles) {
    await page.locator(".market-row").filter({ hasText: title }).click();
    await page
      .getByLabel("Stake, LBTC", { exact: true })
      .fill(settlements.length ? "0.002" : "0.001");
    const previousOutpoint = (await walletState(page)).positionOutpoint ?? "";
    await page
      .getByRole("button", { name: "Participate", exact: true })
      .click();
    if (settlements.length === 0) {
      await expect(page.getByRole("alert")).toContainText(
        "Humid approval rejected",
      );
      expect((await walletState(page)).positionOutpoint ?? "").toBe(
        previousOutpoint,
      );
      await page
        .getByRole("button", { name: "Participate", exact: true })
        .click();
    }
    await expect
      .poll(async () => (await walletState(page)).positionOutpoint ?? "")
      .not.toBe(previousOutpoint);
    const funded = await walletState(page);
    const fundingTxid = funded.positionOutpoint.split(":")[0];
    if (settlements.length) {
      const transaction = await rpc<{
        vin: Array<{ txid: string; vout: number }>;
      }>("getrawtransaction", [fundingTxid, true]);
      expect(transaction.vin).toHaveLength(3);
      const holderInputs = transaction.vin.slice(0, -1);
      expect(holderInputs.every((input) => input.txid === settlements[0])).toBe(
        true,
      );
      expect(holderInputs.map((input) => input.vout).sort()).toEqual([0, 2]);
    }
    await mine();
    await expect(
      page.locator(".stage.done").filter({ hasText: "Position funded" }),
    ).toBeVisible();

    await page
      .getByRole("button", { name: "Market desk", exact: true })
      .click();
    const row = page.locator(".resolution-row").filter({ hasText: title });
    await row.getByRole("textbox").fill(localDate(Date.now() - 10_000));
    await row.getByRole("button", { name: "Resolve Yes", exact: true }).click();
    await expect(row.locator(".signed")).toBeVisible();
    await page
      .getByRole("button", { name: "Back to Markets", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Request winning Tick", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Sign and redeem", exact: true }),
    ).toBeVisible({ timeout: 120_000 });
    const tick = await walletState(page);
    expect(tick.tickTxid).toBeTruthy();
    await mine();
    await page
      .getByRole("button", { name: "Sign and redeem", exact: true })
      .click();
    await expect
      .poll(async () => (await walletState(page)).redemptionTxid)
      .not.toBe("");
    const { redemptionTxid } = await walletState(page);
    const redemption = await rpc<{
      vout: Array<{
        scriptPubKey: { hex: string };
        valuecommitment?: string;
        assetcommitment?: string;
      }>;
    }>("getrawtransaction", [redemptionTxid, true]);
    expect(redemption.vout[1].scriptPubKey.hex).toBe("6a0400000001");
    for (const index of [0, 2]) {
      expect(redemption.vout[index].valuecommitment).toMatch(
        /^0[89][0-9a-f]{64}$/,
      );
      expect(redemption.vout[index].assetcommitment).toMatch(
        /^0[ab][0-9a-f]{64}$/,
      );
    }
    expect(redemption.vout[1].valuecommitment).toBeUndefined();
    await mine();
    await expect(page.locator(".win-block strong")).toHaveText(
      "Position redeemed",
    );
    expect(await rpc("gettxout", [fundingTxid, 0])).toBeNull();
    settlements.push(redemptionTxid);
  }

  expect(new Set(settlements).size).toBe(2);
  expect(
    approvals.filter((request) => request.method === "signMessage"),
  ).toHaveLength(2);
  expect(
    approvals
      .filter((request) => request.method === "signPset")
      .map((request) => request.indexes),
  ).toEqual([[0], [2], [0, 1], [2]]);
  const publicState = await page.evaluate(
    (key) => JSON.parse(localStorage.getItem(key) ?? "{}"),
    stateKey,
  );
  expect(publicState.privateKey).toBeUndefined();
  expect(publicState.rpcUrl).toBeUndefined();
  expect(publicState.rpcUsername).toBeUndefined();
  expect(publicState.rpcPassword).toBeUndefined();
  expect(publicState.wallet.publicKey).toBe(
    Buffer.from(pair.publicKey).toString("hex"),
  );
  await expect(page.locator(".settlement-row")).toHaveCount(2);
  await page.reload();
  await expect(page.locator(".settlement-row")).toHaveCount(2);
  await expect(page.locator(".win-block strong")).toHaveText(
    "Position redeemed",
  );
  await page
    .getByRole("searchbox", { name: "Search markets" })
    .fill(String(unique));
  await expect(page.locator(".market-row")).toHaveCount(2);
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: testInfo.outputPath(`settled-${width}.png`),
      fullPage: true,
    });
  }
  await page
    .getByRole("region", { name: "Wallet summary" })
    .getByRole("button")
    .click();
  await page
    .getByRole("button", { name: "Disconnect Humid", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Connect Humid", exact: true }).first(),
  ).toBeVisible();
  expect(approved).toBe(false);
  await page.reload();
  await expect(
    page
      .getByRole("region", { name: "Wallet summary" })
      .getByRole("button", { name: "Connect Humid", exact: true }),
  ).toBeVisible();

  await page.setViewportSize({ width: 1440, height: 1000 });
  const coordinator =
    process.env.TEST_COORDINATOR_API ?? "http://127.0.0.1:9100";
  const rateResponse = await fetch(`${coordinator}/price-feeds/0`);
  expect(rateResponse.ok).toBe(true);
  const rate = (await rateResponse.json()) as {
    main: { feed: { price: number; decimals: number } };
  };
  const winningStrike = Math.floor(
    (rate.main.feed.price / 10 ** rate.main.feed.decimals) * 0.9,
  ).toString();
  const priceTitle = `Will LBTC/USD touch the winning strike? ${unique}`;
  const expiryTitle = `Will LBTC/USD touch an unreachable strike? ${unique}`;
  await page.getByRole("button", { name: "Demo", exact: true }).click();
  const priceDesk = page.getByRole("region", {
    name: "Price market publishing",
  });
  await priceDesk.getByRole("button", { name: "Connect house Humid" }).click();
  await expect(
    priceDesk.getByRole("button", { name: "Reconnect house" }),
  ).toBeVisible();
  const publishPrice = async (
    title: string,
    strike: string,
    deadline: number,
    grace: number,
  ) => {
    await priceDesk.getByLabel("Question", { exact: true }).fill(title);
    await priceDesk.getByLabel("Strike", { exact: true }).fill(strike);
    await priceDesk
      .getByLabel("Opens", { exact: true })
      .fill(localDate(Date.now() - 60_000));
    await priceDesk
      .getByLabel("Deadline", { exact: true })
      .fill(localDate(deadline));
    await priceDesk.getByLabel("Claim grace, seconds").fill(String(grace));
    await priceDesk
      .getByRole("button", { name: "Publish price market" })
      .click();
    const row = page.locator(".resolution-row").filter({ hasText: title });
    await expect(row).toBeVisible();
    await expect(row.getByRole("button", { name: "Resolve Yes" })).toHaveCount(
      0,
    );
  };
  const reconnectHolder = async () => {
    await page
      .getByRole("button", { name: "Back to Markets", exact: true })
      .click();
    await page
      .getByRole("region", { name: "Wallet summary" })
      .getByRole("button", { name: "Connect Humid", exact: true })
      .click();
    await expect(
      page
        .getByRole("region", { name: "Wallet summary" })
        .getByRole("button", { name: "Connect Humid", exact: true }),
    ).toHaveCount(0);
  };
  const publicPriceState = () =>
    page.evaluate(
      (key) => JSON.parse(localStorage.getItem(key) ?? "{}"),
      stateKey,
    );
  const finalizeOracleRequest = async (hash: string) => {
    await mine();
    await expect
      .poll(
        async () => {
          const response = await fetch(`${coordinator}/users/requests/${hash}`);
          const status = (await response.json()) as {
            status: string;
            payload?: string;
          };
          if (status.status === "failed")
            throw new Error(status.payload ?? "Oracle request failed");
          if (status.status === "processing" || status.status === "included")
            await mine();
          return status.status;
        },
        { timeout: 120_000, intervals: [1000] },
      )
      .toBe("executed");
  };

  await publishPrice(priceTitle, winningStrike, Date.now() + 3600_000, 600);
  await reconnectHolder();
  await page
    .getByRole("searchbox", { name: "Search markets" })
    .fill(String(unique));
  await page.locator(".market-row").filter({ hasText: priceTitle }).click();
  await page.getByLabel("Stake, LBTC", { exact: true }).fill("0.0005");
  const previous = (await publicPriceState()).positionOutpoint;
  await page.getByRole("button", { name: "Participate", exact: true }).click();
  await expect
    .poll(async () => (await publicPriceState()).positionOutpoint)
    .not.toBe(previous);
  const pricePosition = (await publicPriceState()).positionOutpoint;
  await mine();
  await expect(
    page.getByRole("button", { name: "Request price proof" }),
  ).toBeEnabled();
  await page.getByRole("button", { name: "Request price proof" }).click();
  await expect
    .poll(async () => (await publicPriceState()).priceRequestHash ?? "")
    .not.toBe("");
  await finalizeOracleRequest((await publicPriceState()).priceRequestHash);
  await expect(
    page.getByRole("button", { name: "Sign and claim" }),
  ).toBeEnabled();
  const proof = (await publicPriceState()).priceClaim;
  expect(proof.voucher.amount_sats).toBe(1);
  expect(proof.tick.asset).toBe(
    (await publicPriceState()).account.tick_asset_id,
  );
  expect(proof.tick.amount_sats).toBeGreaterThan(0);
  await page.getByRole("button", { name: "Sign and claim" }).click();
  await expect
    .poll(async () => (await publicPriceState()).redemptionTxid)
    .not.toBe("");
  const claimed = await publicPriceState();
  const claimTransaction = await rpc<{
    vin: Array<{ txid: string; vout: number }>;
    vout: Array<{
      value: number;
      asset: string;
      scriptPubKey: { hex: string };
    }>;
  }>("getrawtransaction", [claimed.redemptionTxid, true]);
  expect(claimTransaction.vin[1]).toMatchObject({
    txid: proof.voucher.txid,
    vout: proof.voucher.vout,
  });
  expect(claimTransaction.vout[1]).toMatchObject({
    value: 0.00000001,
    asset: proof.voucher.asset,
    scriptPubKey: { hex: "6a0400000001" },
  });
  expect(claimTransaction.vin[2]).toMatchObject({
    txid: proof.tick.txid,
    vout: proof.tick.vout,
  });
  expect(claimTransaction.vout[2]).toMatchObject({
    value: proof.tick.amount_sats / 100_000_000,
    asset: proof.tick.asset,
    scriptPubKey: { hex: "6a0400000002" },
  });
  await mine();
  await expect(page.locator(".win-block strong")).toHaveText(
    "Position redeemed",
  );
  expect(await rpc("gettxout", [pricePosition.split(":")[0], 0])).toBeNull();

  await page.getByRole("button", { name: "Demo", exact: true }).click();
  await priceDesk.getByRole("button", { name: "Connect house Humid" }).click();
  const expiry = Date.now() + 60_000;
  await publishPrice(expiryTitle, "1000000000", expiry, 1);
  await page
    .getByRole("button", { name: "Back to Markets", exact: true })
    .click();
  await page.locator(".market-row").filter({ hasText: expiryTitle }).click();
  const prior = (await publicPriceState()).positionOutpoint;
  await page.getByRole("button", { name: "Participate", exact: true }).click();
  await expect
    .poll(async () => (await publicPriceState()).positionOutpoint)
    .not.toBe(prior);
  const expiryPosition = (await publicPriceState()).positionOutpoint;
  await mine();
  await expect(
    page.getByRole("button", { name: "Request price proof" }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Demo", exact: true }).click();
  await priceDesk.getByRole("button", { name: "Connect house Humid" }).click();
  await expect(
    priceDesk.getByRole("button", { name: "Reconnect house" }),
  ).toBeVisible();
  const sweepDesk = page.getByRole("region", { name: "House sweep" });
  await sweepDesk
    .getByRole("combobox", { name: "Market", exact: true })
    .selectOption({ label: expiryTitle });
  await expect(sweepDesk.getByLabel("Position outpoint")).toHaveValue(
    expiryPosition,
  );
  await expect(
    sweepDesk.getByRole("button", { name: "Request expiry Tick" }),
  ).toBeEnabled({ timeout: 75_000 });
  await sweepDesk.getByRole("button", { name: "Request expiry Tick" }).click();
  const houseState = () =>
    page.evaluate(() =>
      JSON.parse(localStorage.getItem("signal-market:house-sweep:v1") ?? "{}"),
    );
  await expect
    .poll(async () => (await houseState()).feeOutpoint ?? "")
    .not.toBe("");
  await mine();
  await expect
    .poll(async () => (await houseState()).requestHash ?? "")
    .not.toBe("");
  await finalizeOracleRequest((await houseState()).requestHash);
  await expect(
    sweepDesk.getByRole("button", { name: "Sign house sweep" }),
  ).toBeEnabled();
  await sweepDesk.getByRole("button", { name: "Sign house sweep" }).click();
  await expect.poll(async () => (await houseState()).txid ?? "").not.toBe("");
  const swept = await houseState();
  const sweepTransaction = await rpc<{
    vout: Array<{ scriptPubKey: { hex: string } }>;
  }>("getrawtransaction", [swept.txid, true]);
  expect(sweepTransaction.vout[0].scriptPubKey.hex).toBe(walletScript);
  expect(sweepTransaction.vout[1].scriptPubKey.hex).toBe("6a0400000001");
  await mine();
  expect(await rpc("gettxout", [expiryPosition.split(":")[0], 0])).toBeNull();
  await page
    .getByRole("button", { name: "Back to Markets", exact: true })
    .click();
  await expect(page.locator(".win-block strong")).toHaveText(
    "Position swept to house",
  );
});
