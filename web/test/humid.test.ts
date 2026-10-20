import { afterEach, expect, test } from "bun:test";
import BIP32Factory from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import { networks } from "liquidjs-lib";
import {
  connectHumid,
  HumidNotDetectedError,
  deriveHumidWallet,
  descriptorChecksum,
  getHumidUtxos,
  signHumidMessage,
  sameHumidWallet,
  signHumidPset,
  signAndBroadcastHumidPset,
  validateHumidSession,
  type WalletDescriptor,
} from "../src/humid";

const root = BIP32Factory(ecc).fromSeed(Buffer.alloc(32, 7), networks.regtest);
const account = root.derivePath("m/84'/1'/0'");
const expression = `elwpkh([${Buffer.from(root.fingerprint).toString("hex")}/84h/1h/0h]${account.neutered().toBase58()}/0/*)`;
const policyAsset = "ab".repeat(32);
const descriptor: WalletDescriptor = {
  chainId: "regtest",
  accountIdentifier: "account",
  policyAssetId: `regtest/elip144:${policyAsset}`,
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
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
test("Humid installation is required only when the provider is not detected", async () => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { setTimeout },
  });
  await expect(connectHumid(policyAsset)).rejects.toBeInstanceOf(
    HumidNotDetectedError,
  );
});

test("Humid signs a joint escrow without broadcasting or signing host inputs", async () => {
  const wallet = deriveHumidWallet(descriptor);
  let signing: unknown;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: {
          method: string;
          params?: { request: { params: unknown } };
        }) => {
          if (request.method === "wallet_getSession")
            return {
              sessionScopes: {
                regtest: {
                  accounts: ["account"],
                  methods: [
                    "getWalletDescriptor",
                    "getUTXOs",
                    "signMessage",
                    "signPset",
                  ],
                },
              },
            };
          signing = request.params?.request.params;
          return { pset: "partially-signed" };
        },
      },
    },
  });
  expect(
    await signHumidPset(wallet, "joint-escrow", [
      { address: wallet.address, index: 0 },
    ]),
  ).toBe("partially-signed");
  expect(signing).toEqual({
    pset: "joint-escrow",
    broadcast: false,
    signInputs: [{ address: wallet.address, index: 0, sighashTypes: [1] }],
  });
});

const originalLocalStorage = Object.getOwnPropertyDescriptor(
  globalThis,
  "localStorage",
);
afterEach(() => {
  if (originalWindow)
    Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
  if (originalLocalStorage)
    Object.defineProperty(globalThis, "localStorage", originalLocalStorage);
  else Reflect.deleteProperty(globalThis, "localStorage");
});

test("Humid backend migration preserves only the same wallet and policy asset", () => {
  const wallet = deriveHumidWallet(descriptor);
  const migrated = {
    ...wallet,
    chainId: "new-chain",
    accountIdentifier: "new-scope",
  };
  expect(sameHumidWallet(wallet, migrated)).toBe(true);
  for (const field of [
    "publicKey",
    "scriptPubKey",
    "policyAssetId",
    "masterFingerprint",
    "derivationPath",
  ] as const) {
    expect(sameHumidWallet(wallet, { ...migrated, [field]: "different" })).toBe(
      false,
    );
  }
});

test("Humid identity is derived from a public descriptor only", () => {
  const wallet = deriveHumidWallet(descriptor);
  expect(wallet.policyAssetId).toBe(policyAsset);
  expect(wallet.publicKey).toBe(
    Buffer.from(account.derive(0).derive(0).publicKey).toString("hex"),
  );
  expect(wallet.address.startsWith("ert1")).toBe(true);
  expect(() =>
    deriveHumidWallet({
      ...descriptor,
      descriptors: [
        {
          ...descriptor.descriptors[0],
          branchDescriptors: [
            {
              branch: "external",
              change: 0,
              descriptor: `${expression}#invalid`,
            },
          ],
        },
      ],
    }),
  ).toThrow("checksum");
});

test("Humid uses built-in Liquid testnet without adding chains or changing cached networks", async () => {
  const chainId = "bip122:a771da8e52ee6ad581ed1e9a99825e5b";
  const testnetDescriptor: WalletDescriptor = {
    ...descriptor,
    chainId,
    policyAssetId: `${chainId}/elip144:${networks.testnet.assetHash}`,
  };
  const storage = new Map([
    ["storm-humid-regtest-chain", "existing-regtest"],
    ["storm-humid-regtest-backend", "http://127.0.0.1:3001"],
    ["storm-humid-testnet-chain", "previous-custom-testnet"],
    ["storm-humid-testnet-backend", "http://127.0.0.1:3100/api/chain"],
  ]);
  const requests: unknown[] = [];
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
    },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: { method: string }) => {
          requests.push(request);
          if (request.method === "wallet_addChain")
            throw new Error("Testnet must not add a chain");
          if (request.method === "wallet_createSession") return {};
          if (request.method === "wallet_getSession")
            return {
              sessionScopes: {
                [chainId]: {
                  accounts: [descriptor.accountIdentifier],
                  methods: [
                    "getWalletDescriptor",
                    "getUTXOs",
                    "signMessage",
                    "signPset",
                  ],
                },
              },
            };
          return testnetDescriptor;
        },
      },
    },
  });

  const backend = "http://127.0.0.1:3100/api/chain";
  const wallet = await connectHumid(networks.testnet.assetHash, backend);
  expect(requests[0]).toMatchObject({
    method: "wallet_createSession",
    params: {
      optionalScopes: {
        [chainId]: {
          methods: [
            "getWalletDescriptor",
            "getUTXOs",
            "signMessage",
            "signPset",
          ],
          notifications: ["bip122_walletDescriptorChanged"],
        },
      },
    },
  });
  expect(wallet.address.startsWith("tex1")).toBe(true);
  expect(wallet.scriptPubKey).toBe(deriveHumidWallet(descriptor).scriptPubKey);
  expect(storage.get("storm-humid-regtest-chain")).toBe("existing-regtest");
  expect(wallet.chainId).toBe(chainId);
  expect(storage.get("storm-humid-testnet-chain")).toBe(
    "previous-custom-testnet",
  );
  expect(await validateHumidSession(wallet, backend)).toBe(true);
  expect(
    await validateHumidSession(
      { ...wallet, chainId: "previous-custom-testnet" },
      backend,
    ),
  ).toBe(false);
  await connectHumid(networks.testnet.assetHash, backend);
  testnetDescriptor.policyAssetId = `${chainId}/elip144:${policyAsset}`;
  await expect(
    connectHumid(networks.testnet.assetHash, backend),
  ).rejects.toThrow("LBTC asset does not match");
  expect(
    requests.filter(
      (request) => (request as { method: string }).method === "wallet_addChain",
    ),
  ).toHaveLength(0);
});

test.each([5100, 4001])(
  "Humid does not add testnet after session error %i",
  async (code) => {
    const requests: string[] = [];
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: { getItem: () => null },
    });
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        humid: {
          request: async (request: { method: string }) => {
            requests.push(request.method);
            throw Object.assign(new Error("Session unavailable"), { code });
          },
        },
      },
    });

    await expect(
      connectHumid(networks.testnet.assetHash),
    ).rejects.toMatchObject({ code });
    expect(requests).toEqual(["wallet_createSession"]);
  },
);

test("Humid connects with chain-scoped assets and requests policy UTXOs in ELIP-144 format", async () => {
  const requests: unknown[] = [];
  let responseDescriptor = descriptor;
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: () => "regtest",
      removeItem: () => {},
      setItem: () => {},
    },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: {
          method: string;
          params?: { request: { method: string } };
        }) => {
          requests.push(request);
          if (request.method === "wallet_addChain")
            return { chainId: "regtest" };
          if (request.method === "wallet_createSession") return {};
          if (request.method === "wallet_getSession")
            return {
              sessionScopes: {
                regtest: {
                  accounts: ["account"],
                  methods: [
                    "getWalletDescriptor",
                    "getUTXOs",
                    "signMessage",
                    "signPset",
                  ],
                },
              },
            };
          if (request.params?.request.method === "getWalletDescriptor")
            return responseDescriptor;
          return {
            chainId: "regtest",
            accountIdentifier: "account",
            policyAssetId: descriptor.policyAssetId,
            utxos: [
              {
                address: "wallet",
                amount: "1000",
                assetId: descriptor.policyAssetId,
                confidential: false,
                scriptPubKey: "0014",
                spendable: true,
                txid: "cd".repeat(32),
                txOut: "output",
                vout: 0,
              },
              {
                address: "wallet",
                amount: "1000",
                assetId: `regtest/elip144:${"ef".repeat(32)}`,
                confidential: false,
                scriptPubKey: "0014",
                spendable: true,
                txid: "cd".repeat(32),
                txOut: "output",
                vout: 1,
              },
            ],
          };
        },
      },
    },
  });
  const wallet = await connectHumid(policyAsset);
  expect(wallet.policyAssetId).toBe(policyAsset);
  const utxos = await getHumidUtxos(wallet);
  expect(utxos).toHaveLength(1);
  expect(utxos[0].assetId).toBe(policyAsset);
  expect(requests.at(-1)).toEqual({
    method: "wallet_invokeMethod",
    params: {
      scope: "regtest",
      request: {
        method: "getUTXOs",
        params: { assetId: descriptor.policyAssetId },
      },
    },
  });
  responseDescriptor = {
    ...descriptor,
    policyAssetId: `regtest/elip144:${"ef".repeat(32)}`,
  };
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "LBTC asset does not match",
  );
  responseDescriptor = {
    ...descriptor,
    policyAssetId: `other-chain/elip144:${policyAsset}`,
  };
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "invalid asset identifier",
  );
  responseDescriptor = { ...descriptor, chainId: "other-chain" };
  await expect(connectHumid(policyAsset)).rejects.toThrow("different chain");
});

test("Humid replaces a cached default-asset chain only with approval and verifies the new asset", async () => {
  let storedChain: string | null = "old-regtest";
  let storedBackend: string | null = null;
  let wrongNewAsset = false;
  let rejectAddition = false;
  const requests: Array<{ method: string; params?: { scope?: string } }> = [];
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) =>
        key === "storm-humid-regtest-chain" ? storedChain : storedBackend,
      removeItem: () => {
        storedChain = null;
      },
      setItem: (key: string, value: string) => {
        if (key === "storm-humid-regtest-chain") storedChain = value;
        else storedBackend = value;
      },
    },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: {
          method: string;
          params?: { scope?: string };
        }) => {
          requests.push(request);
          if (request.method === "wallet_addChain") {
            expect(request).toMatchObject({
              params: { settings: { network: "regtest", policyAsset } },
            });
            if (rejectAddition)
              throw Object.assign(
                new Error("User rejected the add-chain request."),
                { code: 4001 },
              );
            return { chainId: "regtest" };
          }
          if (request.method === "wallet_createSession") return {};
          if (request.method === "wallet_getSession")
            return {
              sessionScopes: {
                regtest: {
                  accounts: [descriptor.accountIdentifier],
                  methods: [
                    "getWalletDescriptor",
                    "getUTXOs",
                    "signMessage",
                    "signPset",
                  ],
                },
              },
            };
          if (request.params?.scope === "old-regtest")
            return {
              ...descriptor,
              chainId: "old-regtest",
              policyAssetId: `old-regtest/elip144:${"ef".repeat(32)}`,
            };
          return wrongNewAsset
            ? {
                ...descriptor,
                policyAssetId: `regtest/elip144:${"ef".repeat(32)}`,
              }
            : descriptor;
        },
      },
    },
  });
  expect((await connectHumid(policyAsset)).policyAssetId).toBe(policyAsset);
  expect(storedChain).toBe("regtest");
  expect(requests.map((request) => request.method)).toEqual([
    "wallet_createSession",
    "wallet_invokeMethod",
    "wallet_addChain",
    "wallet_createSession",
    "wallet_invokeMethod",
    "wallet_getSession",
  ]);
  expect(requests[1].params?.scope).toBe("old-regtest");
  expect(requests[4].params?.scope).toBe("regtest");
  requests.length = 0;
  const relay = "http://127.0.0.1:3100/api/chain";
  await connectHumid(policyAsset, relay);
  expect(requests[0]).toMatchObject({
    method: "wallet_addChain",
    params: { settings: { backend: { url: relay } } },
  });
  expect(storedBackend).toBe(relay);
  requests.length = 0;
  await connectHumid(policyAsset, relay);
  expect(requests.some((request) => request.method === "wallet_addChain")).toBe(
    false,
  );
  requests.length = 0;
  storedChain = null;
  wrongNewAsset = true;
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "LBTC asset does not match",
  );
  expect(requests.map((request) => request.method)).toEqual([
    "wallet_addChain",
    "wallet_createSession",
    "wallet_invokeMethod",
  ]);
  requests.length = 0;
  storedChain = "old-regtest";
  rejectAddition = true;
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "User rejected the add-chain request.",
  );
  expect(requests.map((request) => request.method)).toEqual([
    "wallet_createSession",
    "wallet_invokeMethod",
    "wallet_addChain",
  ]);
  expect(storedChain).toBeNull();
});

test("Humid prompts to restore a deleted cached chain before retrying connection", async () => {
  let storedChain: string | null = "deleted-regtest";
  let chainExists = false;
  const requests: Array<{
    method: string;
    params?: { optionalScopes?: Record<string, unknown> };
  }> = [];
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: () => storedChain,
      removeItem: (key: string) => {
        expect(key).toBe("storm-humid-regtest-chain");
        storedChain = null;
      },
      setItem: (key: string, value: string) => {
        if (key === "storm-humid-regtest-backend") return;
        expect(key).toBe("storm-humid-regtest-chain");
        storedChain = value;
      },
    },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: {
          method: string;
          params?: { optionalScopes?: Record<string, unknown> };
        }) => {
          requests.push(request);
          if (request.method === "wallet_createSession") {
            if (!chainExists)
              throw Object.assign(
                new Error("None of the requested chains are supported."),
                { code: 5100 },
              );
            return {};
          }
          if (request.method === "wallet_addChain") {
            expect(storedChain).toBeNull();
            expect(request).toMatchObject({
              params: { settings: { network: "regtest", policyAsset } },
            });
            chainExists = true;
            return { chainId: "regtest" };
          }
          if (request.method === "wallet_getSession")
            return {
              sessionScopes: {
                regtest: {
                  accounts: ["account"],
                  methods: [
                    "getWalletDescriptor",
                    "getUTXOs",
                    "signMessage",
                    "signPset",
                  ],
                },
              },
            };
          return descriptor;
        },
      },
    },
  });
  expect((await connectHumid(policyAsset)).chainId).toBe("regtest");
  expect(storedChain).toBe("regtest");
  expect(requests.slice(0, 3).map((request) => request.method)).toEqual([
    "wallet_createSession",
    "wallet_addChain",
    "wallet_createSession",
  ]);
  expect(Object.keys(requests[0].params!.optionalScopes!)).toEqual([
    "deleted-regtest",
  ]);
  expect(Object.keys(requests[2].params!.optionalScopes!)).toEqual(["regtest"]);
});

test("Humid does not retry rejected approvals or repeatedly restore unsupported chains", async () => {
  const methods: string[] = [];
  let failure = Object.assign(
    new Error("User rejected the connection request."),
    { code: 4001 },
  );
  let rejectAddition = false;
  let cleared = false;
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: () => "deleted-regtest",
      removeItem: () => {
        cleared = true;
      },
      setItem: () => {},
    },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: { method: string }) => {
          methods.push(request.method);
          if (request.method === "wallet_addChain") {
            if (rejectAddition)
              throw Object.assign(
                new Error("User rejected the add-chain request."),
                { code: 4001 },
              );
            return { chainId: "regtest" };
          }
          throw failure;
        },
      },
    },
  });
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "User rejected the connection request.",
  );
  expect(methods).toEqual(["wallet_createSession"]);
  expect(cleared).toBe(false);
  methods.length = 0;
  failure = Object.assign(
    new Error("None of the requested chains are supported."),
    { code: 5100 },
  );
  rejectAddition = true;
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "User rejected the add-chain request.",
  );
  expect(methods).toEqual(["wallet_createSession", "wallet_addChain"]);
  expect(cleared).toBe(true);
  methods.length = 0;
  rejectAddition = false;
  await expect(connectHumid(policyAsset)).rejects.toThrow(
    "None of the requested chains are supported.",
  );
  expect(methods).toEqual([
    "wallet_createSession",
    "wallet_addChain",
    "wallet_createSession",
  ]);
});

test("Humid approves signing and broadcasting only selected PSET inputs", async () => {
  const requests: unknown[] = [];
  const relay = "http://127.0.0.1:3100/api/chain";
  const storage = new Map<string, string>([
    ["storm-humid-regtest-chain", "regtest"],
    ["storm-humid-regtest-backend", "http://127.0.0.1:3001"],
  ]);
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: (key: string) => storage.get(key) ?? null },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async (request: {
          method: string;
          params?: { request: { method: string } };
        }) => {
          requests.push(request);
          if (request.method === "wallet_getSession")
            return {
              sessionScopes: {
                regtest: {
                  accounts: ["account"],
                  methods: [
                    "getWalletDescriptor",
                    "getUTXOs",
                    "signMessage",
                    "signPset",
                  ],
                },
              },
            };
          if (request.params?.request.method === "signMessage")
            return {
              address: deriveHumidWallet(descriptor).address,
              protocol: "ecdsa",
              signatureEncoding: "hex-recoverable-ecdsa-65",
              signature: "ab".repeat(65),
            };
          return { pset: "signed", txid: "ab".repeat(32) };
        },
      },
    },
  });
  const wallet = deriveHumidWallet(descriptor);
  expect(await validateHumidSession(wallet, relay)).toBe(false);
  await expect(
    signAndBroadcastHumidPset(wallet, "unsigned", [], relay),
  ).rejects.toThrow("Reconnect Humid");
  expect(requests).toHaveLength(0);
  storage.set("storm-humid-regtest-backend", relay);
  storage.set("storm-humid-regtest-chain", "different-chain");
  expect(await validateHumidSession(wallet, relay)).toBe(false);
  await expect(
    signAndBroadcastHumidPset(wallet, "unsigned", [], relay),
  ).rejects.toThrow("Reconnect Humid");
  expect(requests).toHaveLength(0);
  storage.set("storm-humid-regtest-chain", wallet.chainId);
  expect(await signHumidMessage(wallet, "oracle request")).toBe(
    "ab".repeat(65),
  );
  expect(
    await signAndBroadcastHumidPset(
      wallet,
      "unsigned",
      [{ address: wallet.address, index: 2 }],
      relay,
    ),
  ).toBe("ab".repeat(32));
  expect(requests[3]).toEqual({
    method: "wallet_invokeMethod",
    params: {
      scope: "regtest",
      request: {
        method: "signPset",
        params: {
          pset: "unsigned",
          broadcast: true,
          signInputs: [
            { address: wallet.address, index: 2, sighashTypes: [1] },
          ],
        },
      },
    },
  });
});

test("Humid refuses signing after the account changes", async () => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      humid: {
        request: async () => ({
          sessionScopes: { regtest: { accounts: ["other"], methods: [] } },
        }),
      },
    },
  });
  await expect(
    signAndBroadcastHumidPset(deriveHumidWallet(descriptor), "unsigned", [
      { address: "wallet", index: 2 },
    ]),
  ).rejects.toThrow("Reconnect Humid");
});
