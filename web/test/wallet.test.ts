import { describe, expect, test } from "bun:test";
import {
  address,
  Creator,
  CreatorInput,
  CreatorOutput,
  networks,
  ElementsValue,
  PsetInput,
  PsetOutput,
  payments,
  Pset,
  Transaction,
} from "liquidjs-lib";
import {
  addWalletInputDerivation,
  createFundingPset,
  escrowOwnershipMessage,
  getPayoutBlindingKey,
  EsploraClient,
  selectFundingUtxos,
  verifyMatchedEscrow,
  hydrateFundingPset,
} from "../src/wallet";

async function withChainResponses(
  responses: Record<string, Response>,
  run: (client: EsploraClient) => Promise<void>,
) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input, options) => {
    expect(options?.credentials).toBe("omit");
    const response = responses[String(input)];
    if (!response) throw new Error(`Unexpected chain request: ${input}`);
    return response.clone();
  }) as typeof fetch;
  try {
    await run(new EsploraClient("http://chain.test/api/"));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe("public chain lookups", () => {
  const txid = "01".repeat(32);
  const base = "http://chain.test/api";

  test("reads explicit vouchers and detects house sweeps without RPC", async () => {
    const spender = "02".repeat(32);
    await withChainResponses(
      {
        [`${base}/tx/${txid}/status`]: Response.json({ confirmed: true }),
        [`${base}/tx/${txid}/outspend/1`]: Response.json({ spent: false }),
        [`${base}/tx/${txid}`]: Response.json({
          vout: [
            {},
            {
              value: 1,
              asset: "33".repeat(32),
              scriptpubkey: "5120" + "44".repeat(32),
            },
          ],
        }),
        [`${base}/tx/${txid}/outspend/0`]: Response.json({
          spent: true,
          txid: spender,
        }),
        [`${base}/tx/${spender}`]: Response.json({
          vout: [{ scriptpubkey: "0014" + "55".repeat(20) }],
        }),
      },
      async (client) => {
        expect((await client.getExplicitUtxo(txid, 1)).amountSats).toBe(1);
        expect(await client.getSpendingTransaction(txid, 0)).toEqual({
          txid: spender,
          payoutScript: "0014" + "55".repeat(20),
        });
        await expect(client.getExplicitUtxo(txid, 0)).rejects.toThrow(
          "confirmed and unspent",
        );
      },
    );
  });

  test("validates genesis without RPC credentials", async () => {
    await withChainResponses(
      { [`${base}/block-height/0`]: new Response("ab".repeat(32)) },
      async (client) => {
        await client.validateGenesis("ab".repeat(32));
        await expect(client.validateGenesis("cd".repeat(32))).rejects.toThrow(
          "does not match",
        );
      },
    );
    expect(() => new EsploraClient("http://user:password@chain.test")).toThrow(
      "public HTTP",
    );
  });

  test("tracks confirmed, pending and unknown transactions", async () => {
    await withChainResponses(
      {
        [`${base}/tx/${txid}/status`]: Response.json({
          confirmed: true,
          block_height: 100,
        }),
        [`${base}/blocks/tip/height`]: Response.json(102),
      },
      async (client) =>
        expect(await client.getTransactionConfirmations(txid)).toBe(3),
    );
    for (const response of [
      Response.json({ confirmed: false }),
      new Response("", { status: 404 }),
    ]) {
      await withChainResponses(
        { [`${base}/tx/${txid}/status`]: response },
        async (client) => {
          expect(await client.getTransactionConfirmations(txid)).toBe(0);
          expect(await client.isConfirmedUnspent(txid, 0)).toBe(false);
        },
      );
    }
  });

  test("excludes spent outputs and surfaces index failures", async () => {
    for (const spent of [false, true]) {
      await withChainResponses(
        {
          [`${base}/tx/${txid}/status`]: Response.json({ confirmed: true }),
          [`${base}/tx/${txid}/outspend/2`]: Response.json({ spent }),
        },
        async (client) =>
          expect(await client.isConfirmedUnspent(txid, 2)).toBe(!spent),
      );
    }
    await withChainResponses(
      { [`${base}/tx/${txid}/status`]: new Response("", { status: 503 }) },
      async (client) => {
        await expect(client.getTransactionConfirmations(txid)).rejects.toThrow(
          "503",
        );
      },
    );
  });
});

describe("prediction redemption", () => {
  test("gets only a public blinding key from the wallet's explicit fee reserve", () => {
    const publicKey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex",
    );
    const payment = payments.p2wpkh({
      pubkey: publicKey,
      network: networks.regtest,
    });
    const wallet = {
      scriptPubKey: payment.output!.toString("hex"),
      policyAssetId: "ab".repeat(32),
    };
    const fee = { txid: "01".repeat(32), vout: 2 };
    const reserve = {
      ...fee,
      address: address.toConfidential(payment.address!, publicKey),
      amount: "2000",
      assetId: wallet.policyAssetId,
      confidential: false,
      scriptPubKey: wallet.scriptPubKey,
      spendable: true,
      txOut: "output",
    };
    expect(getPayoutBlindingKey([reserve], fee, wallet)).toBe(
      publicKey.toString("hex"),
    );
    for (const override of [
      { spendable: false },
      { assetId: "cd".repeat(32) },
      { vout: 1 },
    ]) {
      expect(() =>
        getPayoutBlindingKey([{ ...reserve, ...override }], fee, wallet),
      ).toThrow("not available");
    }
    const other = payments.p2wpkh({
      hash: Buffer.alloc(20, 0x77),
      network: networks.regtest,
    });
    expect(() =>
      getPayoutBlindingKey(
        [
          {
            ...reserve,
            address: address.toConfidential(other.address!, publicKey),
          },
        ],
        fee,
        wallet,
      ),
    ).toThrow("does not match");
  });

  test("preserves the wallet derivation without an extra root index", () => {
    const pset = createFundingPset(
      [0, 1, 2].map((vout) => ({ txid: "01".repeat(32), vout })),
      [new CreatorOutput("ab".repeat(32), 1000, Buffer.alloc(0))],
    );
    const wallet = {
      publicKey:
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      masterFingerprint: "12345678",
      derivationPath: "m/84'/1'/0'/0/0",
    };
    addWalletInputDerivation(pset, 2, wallet);
    const parsed = Pset.fromBase64(pset.toBase64());
    expect(parsed.inputs[0].bip32Derivation).toBeUndefined();
    expect(parsed.inputs[1].bip32Derivation).toBeUndefined();
    expect(parsed.inputs[2].bip32Derivation).toEqual([
      {
        pubkey: Buffer.from(wallet.publicKey, "hex"),
        masterFingerprint: Buffer.from(wallet.masterFingerprint, "hex"),
        path: "84'/1'/0'/0/0",
      },
    ]);
    expect(wallet.derivationPath).toBe("m/84'/1'/0'/0/0");
  });
});

const utxo = (
  txid: string,
  vout: number,
  amountSats: number,
  asset = "lbtc",
) => ({
  txid,
  vout,
  amountSats,
  asset,
  scriptPubKey: "0014",
});

describe("prediction funding", () => {
  test("escrow ownership message matches the server format", () => {
    // Keep in sync with `ownership_message_format_is_stable` in server/src/escrow.rs.
    expect(
      escrowOwnershipMessage("ab".repeat(32), 100000, "0014" + "55".repeat(20).toUpperCase(), [
        { txid: "11".repeat(32), vout: 0 },
        { txid: "22".repeat(32), vout: 3 },
      ]),
    ).toBe(
      `Prediction escrow funding\nprediction: ${"ab".repeat(32)}\nstake_sats: 100000\npayout: 0014${"55".repeat(20)}\ninputs: ${"11".repeat(32)}:0,${"22".repeat(32)}:3`,
    );
  });

  test("hydrates holder witness UTXOs and range proofs before mixed-wallet signing", async () => {
    const transaction = new Transaction();
    transaction.addInput(Buffer.alloc(32, 1), 0);
    transaction.addOutput(
      Buffer.from("0014" + "55".repeat(20), "hex"),
      ElementsValue.fromNumber(1000000).bytes,
      Buffer.concat([Buffer.from([1]), Buffer.alloc(32, 0xab)]),
      Buffer.from([0]),
      Buffer.from("range-proof"),
      Buffer.from("asset-proof"),
    );
    const txid = transaction.getId();
    const input = {
      txid,
      vout: 0,
      scriptPubKey: transaction.outs[0].script.toString("hex"),
    };
    const pset = createFundingPset(
      [input],
      [new CreatorOutput("ab".repeat(32), 1000, Buffer.alloc(0))],
    );
    await withChainResponses(
      {
        [`http://chain.test/api/tx/${txid}/hex`]: new Response(
          transaction.toHex(),
        ),
      },
      async (chain) => {
        await hydrateFundingPset(pset, [input], chain);
        const parsed = Pset.fromBase64(pset.toBase64());
        expect(parsed.inputs[0].witnessUtxo?.script).toEqual(
          transaction.outs[0].script,
        );
        expect(parsed.inputs[0].utxoRangeProof).toEqual(
          transaction.outs[0].rangeProof,
        );
        await expect(
          hydrateFundingPset(pset, [{ ...input, scriptPubKey: "51" }], chain),
        ).rejects.toThrow("selected Humid input");
      },
    );
    await withChainResponses(
      {
        [`http://chain.test/api/tx/${"02".repeat(32)}/hex`]: new Response(
          transaction.toHex(),
        ),
      },
      async (chain) => {
        await expect(
          chain.getFundingTransaction("02".repeat(32)),
        ).rejects.toThrow("transaction ID");
      },
    );
  });

  test("accepts only a fully host-funded match without increasing the holder contribution", () => {
    const original = createFundingPset(
      [{ txid: "01".repeat(32), vout: 0 }],
      [
        new CreatorOutput("ab".repeat(32), 100000, Buffer.alloc(34, 1)),
        new CreatorOutput("ab".repeat(32), 10000, Buffer.alloc(22, 2)),
        new CreatorOutput("ab".repeat(32), 2000, Buffer.alloc(22, 3)),
        new CreatorOutput("ab".repeat(32), 1000, Buffer.alloc(0)),
      ],
    );
    const matched = Pset.fromBase64(original.toBase64());
    matched.outputs[0].value = 200000;
    const host = new PsetInput(Buffer.alloc(32, 2), 0);
    host.sighashType = 1;
    host.witnessUtxo = {
      script: Buffer.alloc(22, 4),
      asset: Buffer.concat([Buffer.from([1]), original.outputs[0].asset!]),
      value: ElementsValue.fromNumber(1000000).bytes,
      nonce: Buffer.from([0]),
    };
    matched.addInput(host);
    matched.addOutput(
      new PsetOutput(900000, original.outputs[0].asset, Buffer.alloc(22, 4)),
    );
    expect(() =>
      verifyMatchedEscrow(
        original,
        Pset.fromBase64(matched.toBase64()),
        100000,
      ),
    ).not.toThrow();
    for (const index of [0, 1, 2, 3, 4]) {
      const invalid = Pset.fromBase64(matched.toBase64());
      invalid.outputs[index].value += 1;
      expect(() => verifyMatchedEscrow(original, invalid, 100000)).toThrow();
    }
    const exact = Pset.fromBase64(matched.toBase64());
    exact.outputs.pop();
    exact.globals.outputCount -= 1;
    exact.inputs.at(-1)!.witnessUtxo!.value =
      ElementsValue.fromNumber(100000).bytes;
    expect(() =>
      verifyMatchedEscrow(original, Pset.fromBase64(exact.toBase64()), 100000),
    ).not.toThrow();
    for (const amount of [99999, 100001]) {
      const invalid = Pset.fromBase64(exact.toBase64());
      invalid.inputs.at(-1)!.witnessUtxo!.value =
        ElementsValue.fromNumber(amount).bytes;
      expect(() => verifyMatchedEscrow(original, invalid, 100000)).toThrow();
    }
    const invalid = Pset.fromBase64(matched.toBase64());
    invalid.inputs[0].previousTxIndex = 1;
    expect(() => verifyMatchedEscrow(original, invalid, 100000)).toThrow(
      "holder funding inputs",
    );
  });

  test("declares SIGHASH_ALL on every funding input for LWK and LiquidJS finalization", () => {
    const pset = createFundingPset(
      [
        { txid: "01".repeat(32), vout: 0 },
        { txid: "02".repeat(32), vout: 1 },
      ],
      [new CreatorOutput("ab".repeat(32), 1000, Buffer.alloc(0))],
    );
    const parsed = Pset.fromBase64(pset.toBase64());
    expect(parsed.inputs.map((input) => input.sighashType)).toEqual([1, 1]);
  });

  test("omits a zero timestamp locktime that LWK rejects", () => {
    const pset = Creator.newPset({
      inputs: [new CreatorInput("01".repeat(32), 0)],
      outputs: [new CreatorOutput("ab".repeat(32), 1000, Buffer.alloc(0))],
    });
    expect(
      Pset.fromBase64(pset.toBase64()).inputs[0].requiredTimeLocktime,
    ).toBeUndefined();
  });

  test("preserves a real timestamp locktime", () => {
    const pset = Creator.newPset({
      inputs: [new CreatorInput("01".repeat(32), 0)],
      outputs: [new CreatorOutput("ab".repeat(32), 1000, Buffer.alloc(0))],
    });
    pset.inputs[0].requiredTimeLocktime = 1_790_000_000;
    expect(
      Pset.fromBase64(pset.toBase64()).inputs[0].requiredTimeLocktime,
    ).toBe(1_790_000_000);
  });

  test("uses a sufficient output rather than the first small redemption payout", () => {
    const inputs = [
      utxo("redemption", 0, 100_000),
      utxo("redemption", 2, 800_000),
    ];
    expect(selectFundingUtxos(inputs, "lbtc", 112_001)).toEqual([inputs[1]]);
  });

  test("combines payout and change to fund the next prediction", () => {
    const inputs = [
      utxo("redemption", 0, 100_000),
      utxo("redemption", 2, 80_000),
    ];
    expect(selectFundingUtxos(inputs, "lbtc", 112_001)).toEqual(inputs);
  });

  test("prefers confidential funding over a larger explicit payout", () => {
    const confidential = {
      ...utxo("confidential", 0, 200_000),
      confidential: true,
    };
    const explicit = { ...utxo("payout", 0, 800_000), confidential: false };
    expect(
      selectFundingUtxos([explicit, confidential], "lbtc", 112_001),
    ).toEqual([confidential]);
  });

  test("keeps a confidential input when explicit funds are also needed", () => {
    const confidential = {
      ...utxo("confidential", 0, 50_000),
      confidential: true,
    };
    const explicit = { ...utxo("payout", 0, 100_000), confidential: false };
    expect(
      selectFundingUtxos([explicit, confidential], "lbtc", 112_001),
    ).toEqual([confidential, explicit]);
  });

  test("never treats a Tick or another asset as LBTC", () => {
    expect(() =>
      selectFundingUtxos(
        [utxo("tick", 0, 1_790_000_000, "tick")],
        "lbtc",
        112_001,
      ),
    ).toThrow("Insufficient");
  });

  test("does not count the same outpoint twice", () => {
    const input = utxo("payout", 0, 100_000);
    expect(() => selectFundingUtxos([input, input], "lbtc", 112_001)).toThrow(
      "Insufficient",
    );
  });

  test("rejects an invalid or insufficient stake budget", () => {
    expect(() => selectFundingUtxos([], "lbtc", Number.NaN)).toThrow(
      "valid stake",
    );
    expect(() =>
      selectFundingUtxos([utxo("funding", 0, 10_000)], "lbtc", 112_001),
    ).toThrow("Insufficient");
  });
});
