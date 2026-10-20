import { randomBytes } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium, expect, test, type Page } from "@playwright/test";

const server =
  process.env.TEST_CHAIN_BACKEND_URL ?? "http://127.0.0.1:3100/api/chain";
const coordinator = process.env.TEST_COORDINATOR_API ?? "http://127.0.0.1:9100";
const stateKey = "signal-market:user-state:v3";

async function rpc<Result>(
  method: string,
  params: unknown[] = [],
  wallet = false,
): Promise<Result> {
  const url = process.env.TEST_ELEMENTS_RPC ?? "http://127.0.0.1:18884";
  const user = process.env.TEST_RPC_USER ?? "high-storm";
  const password = process.env.TEST_RPC_PASSWORD ?? "high-storm";
  const response = await fetch(
    `${url}${wallet ? `/wallet/${process.env.TEST_FUNDING_WALLET ?? "bootstrap"}` : ""}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`,
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

async function mine() {
  const address = await rpc<string>("getnewaddress", ["", "bech32"], true);
  await rpc("generatetoaddress", [1, address]);
  const height = await rpc<number>("getblockcount");
  await expect
    .poll(async () =>
      Number(await (await fetch(`${server}/blocks/tip/height`)).text()),
    )
    .toBeGreaterThanOrEqual(height);
}

function localDate(timestamp: number): string {
  const date = new Date(timestamp);
  const part = (value: number) => value.toString().padStart(2, "0");
  return `${date.getFullYear()}-${part(date.getMonth() + 1)}-${part(date.getDate())}T${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

async function finishOracle(hash: string) {
  await mine();
  await expect
    .poll(
      async () => {
        const status = (await (
          await fetch(`${coordinator}/users/requests/${hash}`)
        ).json()) as { status: string; payload?: string };
        if (status.status === "failed")
          throw new Error(status.payload ?? "Oracle request failed");
        if (status.status === "processing" || status.status === "included")
          await mine();
        return status.status;
      },
      { timeout: 120_000, intervals: [1000] },
    )
    .toBe("executed");
}

async function publicState(page: Page) {
  return page.evaluate((key) => {
    const state = JSON.parse(localStorage.getItem(key) ?? "{}");
    return { ...state, ...state.positions?.[state.selected] };
  }, stateKey);
}

test.use({ screenshot: "off", trace: "off", video: "off" });

test("claims and sweeps price markets with the actual Humid extension", async () => {
  const extension = process.env.TEST_REAL_HUMID_EXTENSION;
  test.skip(
    !extension,
    "Set TEST_REAL_HUMID_EXTENSION to the built Humid extension directory",
  );
  test.setTimeout(600_000);
  const profile = await mkdtemp(join(tmpdir(), "humid-real-flow-"));
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: false,
    viewport: { width: 1280, height: 800 },
    args: [
      `--disable-extensions-except=${extension}`,
      `--load-extension=${extension}`,
      "--window-size=1280,900",
      "--window-position=0,0",
    ],
  });
  const approvalErrors: string[] = [];
  try {
    const worker =
      context.serviceWorkers()[0] ??
      (await context.waitForEvent("serviceworker"));
    const extensionId = new URL(worker.url()).host;
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/src/popup.html`);
    await popup
      .getByRole("link", { name: "Create wallet", exact: true })
      .click();
    const words = await popup
      .locator(".grid > div > span:last-child")
      .allTextContents();
    expect(words.length).toBeGreaterThanOrEqual(12);
    await popup
      .getByRole("button", { name: "I saved it", exact: true })
      .click();
    await popup
      .getByRole("button", { name: "Continue", exact: true })
      .waitFor();
    for (const label of await popup.locator("label").all()) {
      const position = Number(
        (await label.textContent())?.match(/Word (\d+)/)?.[1],
      );
      await label.locator("input").fill(words[position - 1]);
    }
    words.fill("");
    await popup.getByRole("button", { name: "Continue", exact: true }).click();
    const password = randomBytes(32).toString("base64url");
    await popup.getByLabel("Password", { exact: true }).fill(password);
    await popup.getByLabel("Confirm password", { exact: true }).fill(password);
    await popup
      .getByRole("button", { name: "Create wallet", exact: true })
      .click();
    await expect(popup).toHaveURL(/#\/app/, { timeout: 30_000 });
    await popup.close();
    const app = await context.newPage();
    app.on("request", (request) =>
      expect(request.url()).not.toContain(":18884"),
    );
    context.on("page", (notification) => {
      void (async () => {
        await notification.waitForURL((url) => url.host === extensionId);
        if (!notification.url().includes("/src/notification.html")) return;
        for (let step = 0; step < 8 && !notification.isClosed(); step += 1) {
          const approve = notification
            .getByRole("button", {
              name: /^(Approve|Connect|Add network|Confirm|Allow|Sign message|Sign transaction|Sign and broadcast)$/i,
            })
            .last();
          await approve.waitFor({ timeout: 15_000 });
          console.log("Humid approval:", await approve.textContent());
          await approve.click();
          await notification
            .waitForEvent("close", { timeout: 2000 })
            .catch(() => {});
        }
      })().catch((error: Error) => {
        if (!notification.isClosed()) approvalErrors.push(error.message);
      });
    });
    await app.goto(process.env.VITE_TEST_URL ?? "http://127.0.0.1:5173");
    await app
      .getByRole("region", { name: "Wallet summary" })
      .getByRole("button", { name: "Connect Humid", exact: true })
      .click();
    try {
      await expect(
        app
          .getByRole("region", { name: "Wallet summary" })
          .getByRole("button", { name: "Connect Humid", exact: true }),
      ).toHaveCount(0, { timeout: 60_000 });
    } catch (error) {
      console.log(
        "Connection notices:",
        await app.locator(".notice").allTextContents(),
      );
      console.log("Approval errors:", approvalErrors);
      throw error;
    }
    const wallet = (await publicState(app)).wallet;
    expect(wallet.address).toMatch(/^ert1/);
    expect(approvalErrors).toEqual([]);
    console.log(
      JSON.stringify({
        extensionId,
        walletAddress: wallet.address,
        walletScript: wallet.scriptPubKey,
      }),
    );
    expect((await rpc<{ chain: string }>("getblockchaininfo")).chain).toBe(
      "elementsregtest",
    );
    const receive = await context.newPage();
    await receive.goto(`chrome-extension://${extensionId}/src/popup.html#/app`);
    await receive.getByRole("button", { name: "Liquid", exact: true }).click();
    await receive
      .getByRole("menuitemradio", {
        name: "HighStorm Elements Regtest",
        exact: true,
      })
      .click();
    await receive.getByRole("link", { name: "Receive", exact: true }).click();
    await receive
      .getByRole("tab", { name: "Unconfidential", exact: true })
      .click();
    await expect(
      receive.getByText(wallet.address, { exact: true }),
    ).toBeVisible();
    await receive
      .getByRole("tab", { name: "Confidential", exact: true })
      .click();
    const address = receive
      .locator("p")
      .filter({ hasText: /^el1[0-9a-z]+$/ })
      .first();
    await expect(address).toBeVisible();
    const confidentialAddress = (await address.textContent())!.trim();
    console.log("Confidential funding address:", confidentialAddress);
    await rpc("sendtoaddress", [confidentialAddress, 0.0018], true);
    await mine();
    await receive.getByRole("link", { name: "Back", exact: true }).click();
    await receive
      .getByRole("button", { name: "Refresh balances", exact: true })
      .click();
    let reportedUtxos: Array<{
      amount: string;
      confidential: boolean;
      spendable: boolean;
      txid: string;
      vout: number;
    }> = [];
    await expect
      .poll(
        async () => {
          reportedUtxos = await app.evaluate(async (wallet) => {
            const result = await window.humid!.request<{
              utxos: Array<{
                amount: string;
                confidential: boolean;
                spendable: boolean;
                txid: string;
                vout: number;
              }>;
            }>({
              method: "wallet_invokeMethod",
              params: {
                scope: wallet.chainId,
                request: {
                  method: "getUTXOs",
                  params: {
                    assetId: `${wallet.chainId}/elip144:${wallet.policyAssetId}`,
                  },
                },
              },
            });
            return result.utxos.map(
              ({ amount, confidential, spendable, txid, vout }) => ({
                amount,
                confidential,
                spendable,
                txid,
                vout,
              }),
            );
          }, wallet);
          if (reportedUtxos.length)
            console.log("Public funding UTXOs:", JSON.stringify(reportedUtxos));
          return reportedUtxos
            .filter((utxo) => utxo.confidential && utxo.spendable)
            .reduce((sum, utxo) => sum + BigInt(utxo.amount), 0n)
            .toString();
        },
        { timeout: 90_000, intervals: [5000] },
      )
      .toBe("180000");

    await app.getByRole("button", { name: "Demo", exact: true }).click();
    await app
      .getByLabel("Login", { exact: true })
      .fill(process.env.TEST_ADMIN_LOGIN ?? "admin");
    await app
      .getByLabel("Password", { exact: true })
      .fill(process.env.TEST_ADMIN_PASSWORD ?? "prediction-demo");
    await app.getByRole("button", { name: "Sign in", exact: true }).click();
    const desk = app.getByRole("region", { name: "Price market publishing" });
    const connectHouse = async () => {
      await desk
        .getByRole("button", { name: "Connect house Humid", exact: true })
        .click();
      await expect(
        desk.getByRole("button", { name: "Reconnect house", exact: true }),
      ).toBeVisible();
    };
    await connectHouse();
    const rate = (await (
      await fetch(`${coordinator}/price-feeds/0`)
    ).json()) as { main: { feed: { price: number; decimals: number } } };
    const strike = Math.floor(
      (rate.main.feed.price / 10 ** rate.main.feed.decimals) * 0.9,
    ).toString();
    const unique = Date.now();
    const winner = `Humid real price claim ${unique}`;
    const loser = `Humid real house sweep ${unique}`;
    const publish = async (
      title: string,
      strike: string,
      deadline: number,
      grace: number,
    ) => {
      await desk.getByLabel("Question", { exact: true }).fill(title);
      await desk.getByLabel("Strike", { exact: true }).fill(strike);
      await desk
        .getByLabel("Opens", { exact: true })
        .fill(localDate(Date.now() - 60_000));
      await desk
        .getByLabel("Deadline", { exact: true })
        .fill(localDate(deadline));
      await desk.getByLabel("Claim grace, seconds").fill(String(grace));
      await desk
        .getByRole("button", { name: "Publish price market", exact: true })
        .click();
      await expect(
        app.getByText("Price market published.", { exact: true }),
      ).toBeVisible();
    };
    const lock = async (title: string) => {
      await app
        .getByRole("button", { name: "Back to Markets", exact: true })
        .click();
      await app
        .getByRole("searchbox", { name: "Search markets" })
        .fill(String(unique));
      await app.locator(".market-row").filter({ hasText: title }).click();
      await app.getByLabel("Stake, LBTC", { exact: true }).fill("0.0005");
      const previous = (await publicState(app)).positionOutpoint;
      await app
        .getByRole("button", { name: "Participate", exact: true })
        .click();
      await expect
        .poll(async () => (await publicState(app)).positionOutpoint)
        .not.toBe(previous);
      await mine();
      return (await publicState(app)).positionOutpoint as string;
    };
    await publish(winner, strike, Date.now() + 3600_000, 600);
    const claimPosition = await lock(winner);
    await expect(
      app.getByRole("button", { name: "Request price proof", exact: true }),
    ).toBeEnabled();
    await app
      .getByRole("button", { name: "Request price proof", exact: true })
      .click();
    await expect
      .poll(async () => (await publicState(app)).priceRequestHash ?? "")
      .not.toBe("");
    await finishOracle((await publicState(app)).priceRequestHash);
    await expect(
      app.getByRole("button", { name: "Sign and claim", exact: true }),
    ).toBeEnabled();
    const proof = (await publicState(app)).priceClaim;
    await app
      .getByRole("button", { name: "Sign and claim", exact: true })
      .click();
    await expect
      .poll(async () => (await publicState(app)).redemptionTxid ?? "")
      .not.toBe("");
    const claimTxid = (await publicState(app)).redemptionTxid;
    await mine();
    await expect(app.locator(".win-block strong")).toHaveText(
      "Position redeemed",
    );
    const claim = await (await fetch(`${server}/tx/${claimTxid}`)).json();
    expect(claim.vout[1]).toMatchObject({
      value: 1,
      asset: proof.voucher.asset,
      scriptpubkey: "6a0400000001",
    });
    const [claimFunding, claimIndex] = claimPosition.split(":");
    expect(
      await rpc("gettxout", [claimFunding, Number(claimIndex)]),
    ).toBeNull();

    await app.getByRole("button", { name: "Demo", exact: true }).click();
    await connectHouse();
    await publish(loser, "1000000000", Date.now() + 60_000, 1);
    const sweepPosition = await lock(loser);
    await app.getByRole("button", { name: "Demo", exact: true }).click();
    await connectHouse();
    const sweepDesk = app.getByRole("region", { name: "House sweep" });
    await sweepDesk
      .getByRole("combobox", { name: "Market", exact: true })
      .selectOption({ label: loser });
    await expect(sweepDesk.getByLabel("Position outpoint")).toHaveValue(
      sweepPosition,
    );
    await expect(
      sweepDesk.getByRole("button", {
        name: "Request expiry Tick",
        exact: true,
      }),
    ).toBeEnabled({ timeout: 75_000 });
    await sweepDesk
      .getByRole("button", { name: "Request expiry Tick", exact: true })
      .click();
    const houseState = () =>
      app.evaluate(() =>
        JSON.parse(
          localStorage.getItem("signal-market:house-sweep:v1") ?? "{}",
        ),
      );
    await expect
      .poll(async () => (await houseState()).feeOutpoint ?? "")
      .not.toBe("");
    await mine();
    await expect
      .poll(async () => (await houseState()).requestHash ?? "")
      .not.toBe("");
    await finishOracle((await houseState()).requestHash);
    await expect(
      sweepDesk.getByRole("button", { name: "Sign house sweep", exact: true }),
    ).toBeEnabled();
    await sweepDesk
      .getByRole("button", { name: "Sign house sweep", exact: true })
      .click();
    await expect.poll(async () => (await houseState()).txid ?? "").not.toBe("");
    const sweepTxid = (await houseState()).txid;
    await mine();
    const sweep = await (await fetch(`${server}/tx/${sweepTxid}`)).json();
    expect(sweep.vout[0]).toMatchObject({
      value: 50000,
      scriptpubkey: wallet.scriptPubKey,
    });
    expect(sweep.vout[1].scriptpubkey).toBe("6a0400000001");
    const [sweepFunding, sweepIndex] = sweepPosition.split(":");
    expect(
      await rpc("gettxout", [sweepFunding, Number(sweepIndex)]),
    ).toBeNull();
    await app
      .getByRole("button", { name: "Back to Markets", exact: true })
      .click();
    await expect(app.locator(".win-block strong")).toHaveText(
      "Position swept to house",
    );
    expect(approvalErrors).toEqual([]);
    console.log(
      JSON.stringify({
        signer: "actual Humid extension / LWK",
        claimTxid,
        sweepTxid,
        stakeSats: 50000,
      }),
    );
  } finally {
    await context.close();
  }
});
