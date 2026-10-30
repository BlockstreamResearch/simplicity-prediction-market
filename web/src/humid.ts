import * as ecc from "@bitcoinerlab/secp256k1";
import BIP32Factory from "bip32";
import { Buffer } from "buffer";
import { networks, payments } from "liquidjs-lib";

const bip32 = BIP32Factory(ecc);
const METHODS = ["getWalletDescriptor", "getUTXOs", "signMessage", "signPset"];
const LIQUID_TESTNET_CHAIN_ID = "bip122:a771da8e52ee6ad581ed1e9a99825e5b";
const defaultBackend =
  import.meta.env?.VITE_HUMID_REGTEST_BACKEND_URL ?? "http://127.0.0.1:3001";
const NOTIFICATIONS = ["bip122_walletDescriptorChanged"];
const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

export type HumidProvider = {
  request<Result>(args: { method: string; params?: unknown }): Promise<Result>;
  on?: (args: {
    event: string;
    listener: (payload: unknown) => void;
  }) => () => void;
};
declare global {
  interface Window {
    humid?: HumidProvider;
  }
}

export type HumidWallet = {
  chainId: string;
  accountIdentifier: string;
  policyAssetId: string;
  address: string;
  scriptPubKey: string;
  publicKey: string;
  masterFingerprint: string;
  derivationPath: string;
};
export function sameHumidWallet(
  previous: HumidWallet,
  next: HumidWallet,
): boolean {
  return (
    previous.publicKey === next.publicKey &&
    previous.scriptPubKey === next.scriptPubKey &&
    previous.policyAssetId === next.policyAssetId &&
    previous.masterFingerprint === next.masterFingerprint &&
    previous.derivationPath === next.derivationPath
  );
}

export type HumidUtxo = {
  address: string;
  amount: string;
  assetId: string;
  confidential: boolean;
  scriptPubKey: string;
  spendable: boolean;
  txid: string;
  txOut: string;
  vout: number;
};
export type WalletDescriptor = {
  chainId: string;
  accountIdentifier: string;
  policyAssetId: string;
  descriptors: Array<{
    descriptorType: string;
    format: string;
    branchLayout: string;
    branchDescriptors?: Array<{
      branch: string;
      change: number;
      descriptor: string;
    }>;
  }>;
};

export class HumidNotDetectedError extends Error {
  constructor() {
    super("Humid was not detected in this browser");
    this.name = "HumidNotDetectedError";
  }
}

async function provider(): Promise<HumidProvider> {
  const started = Date.now();
  while (!window.humid && Date.now() - started < 3_000)
    await new Promise((resolve) => window.setTimeout(resolve, 50));
  if (!window.humid) throw new HumidNotDetectedError();
  return window.humid;
}
async function invoke<Result>(
  wallet: Pick<HumidWallet, "chainId">,
  method: string,
  params: unknown,
): Promise<Result> {
  return (await provider()).request<Result>({
    method: "wallet_invokeMethod",
    params: { scope: wallet.chainId, request: { method, params } },
  });
}

function rawAssetId(assetId: string, chainId: string): string {
  const prefix = `${chainId}/elip144:`;
  const raw = assetId.startsWith(prefix)
    ? assetId.slice(prefix.length)
    : assetId;
  if (!/^[0-9a-f]{64}$/i.test(raw))
    throw new Error(
      "Humid returned an invalid asset identifier for the selected chain",
    );
  return raw.toLowerCase();
}

function walletNetwork(policyAssetId: string) {
  return policyAssetId.toLowerCase() === networks.testnet.assetHash
    ? networks.testnet
    : networks.regtest;
}

export async function connectHumid(
  policyAssetId: string,
  backendUrl = walletNetwork(policyAssetId) === networks.testnet
    ? "https://blockstream.info/liquidtestnet/api"
    : defaultBackend,
): Promise<HumidWallet> {
  const connection = await provider();
  const network = walletNetwork(policyAssetId);
  const builtInTestnet = network === networks.testnet;
  const chainKey = `storm-humid-${network.name}-chain`;
  const backendKey = `storm-humid-${network.name}-backend`;
  let addedChain = false;
  const addChain = async (): Promise<string> => {
    const result = await connection.request<{ chainId: string }>({
      method: "wallet_addChain",
      params: {
        name: "HighStorm Elements Regtest",
        settings: {
          network: network.name,
          policyAsset: policyAssetId.toLowerCase(),
          backend: {
            url: backendUrl,
          },
        },
      },
    });
    localStorage.setItem(chainKey, result.chainId);
    localStorage.setItem(backendKey, backendUrl);
    addedChain = true;
    return result.chainId;
  };
  const cachedChain = localStorage.getItem(chainKey);
  const backendChanged =
    backendUrl !== defaultBackend &&
    localStorage.getItem(backendKey) !== backendUrl;
  let chainId = builtInTestnet
    ? LIQUID_TESTNET_CHAIN_ID
    : cachedChain && !backendChanged
      ? cachedChain
      : await addChain();
  const createSession = () =>
    connection.request({
      method: "wallet_createSession",
      params: {
        optionalScopes: {
          [chainId]: { methods: METHODS, notifications: NOTIFICATIONS },
        },
      },
    });
  try {
    await createSession();
  } catch (error) {
    if (
      builtInTestnet ||
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== 5100
    )
      throw error;
    localStorage.removeItem(chainKey);
    chainId = await addChain();
    await createSession();
  }
  const readDescriptor = async (): Promise<WalletDescriptor> => {
    const result = await invoke<WalletDescriptor>(
      { chainId },
      "getWalletDescriptor",
      {
        descriptorType: "publicWalletDescriptor",
        descriptorFormat: [{ format: "bip380-split-branches" }],
      },
    );
    if (result.chainId !== chainId)
      throw new Error(
        "Humid returned a wallet for a different chain. Reconnect Humid",
      );
    return result;
  };
  let result = await readDescriptor();
  if (
    rawAssetId(result.policyAssetId, chainId) !== policyAssetId.toLowerCase() &&
    !addedChain &&
    !builtInTestnet
  ) {
    localStorage.removeItem(chainKey);
    chainId = await addChain();
    await createSession();
    result = await readDescriptor();
  }
  if (
    rawAssetId(result.policyAssetId, chainId) !== policyAssetId.toLowerCase()
  ) {
    throw new Error(
      "Humid's LBTC asset does not match the selected chain. Check Humid's backend",
    );
  }
  const wallet = deriveHumidWallet(result);
  if (!(await validateHumidSession(wallet)))
    throw new Error("Approve the requested Humid wallet permissions");
  return wallet;
}

export function deriveHumidWallet(result: WalletDescriptor): HumidWallet {
  const entries = result.descriptors.filter(
    (entry) =>
      entry.descriptorType === "publicWalletDescriptor" &&
      entry.format === "bip380-split-branches" &&
      entry.branchLayout === "split",
  );
  const external =
    entries.length === 1
      ? entries[0].branchDescriptors?.filter(
          (branch) => branch.branch === "external" && branch.change === 0,
        )
      : [];
  if (external?.length !== 1)
    throw new Error("Humid returned an unsupported wallet descriptor");
  const descriptor = external[0].descriptor;
  const separator = descriptor.lastIndexOf("#");
  const expression = descriptor.slice(0, separator);
  if (
    separator < 0 ||
    descriptorChecksum(expression) !== descriptor.slice(separator + 1)
  )
    throw new Error("Invalid Humid descriptor checksum");
  const match =
    /^elwpkh\(\[([0-9a-f]{8})\/84[h']\/1[h']\/0[h']\](tpub[1-9A-HJ-NP-Za-km-z]+)\/0\/\*\)$/i.exec(
      expression,
    );
  if (!match) throw new Error("Humid must use a native SegWit Liquid wallet");
  const policyAssetId = rawAssetId(result.policyAssetId, result.chainId);
  const network = walletNetwork(policyAssetId);
  const node = bip32.fromBase58(match[2], network).derive(0).derive(0);
  const payment = payments.p2wpkh({
    pubkey: Buffer.from(node.publicKey),
    network,
  });
  if (!payment.address || !payment.output)
    throw new Error("Could not derive the Humid wallet address");
  return {
    chainId: result.chainId,
    accountIdentifier: result.accountIdentifier,
    policyAssetId,
    address: payment.address,
    scriptPubKey: payment.output.toString("hex"),
    publicKey: Buffer.from(node.publicKey).toString("hex"),
    masterFingerprint: match[1],
    derivationPath: "m/84'/1'/0'/0/0",
  };
}

export async function validateHumidSession(
  wallet: HumidWallet,
  backendUrl?: string,
): Promise<boolean> {
  try {
    const network = walletNetwork(wallet.policyAssetId);
    if (
      network === networks.testnet &&
      wallet.chainId !== LIQUID_TESTNET_CHAIN_ID
    )
      return false;
    if (
      backendUrl &&
      network !== networks.testnet &&
      (localStorage.getItem(`storm-humid-${network.name}-chain`) !==
        wallet.chainId ||
        localStorage.getItem(`storm-humid-${network.name}-backend`) !==
          backendUrl)
    )
      return false;
    const session = await (
      await provider()
    ).request<{
      sessionScopes: Record<string, { accounts?: string[]; methods: string[] }>;
    }>({ method: "wallet_getSession" });
    const scope = session.sessionScopes[wallet.chainId];
    return Boolean(
      scope?.accounts?.includes(wallet.accountIdentifier) &&
      METHODS.every((method) => scope.methods.includes(method)),
    );
  } catch {
    return false;
  }
}

export function subscribeToHumidChanges(listener: () => void): () => void {
  let disposed = false;
  let unsubscribers: Array<() => void> = [];
  void provider()
    .then((connection) => {
      if (!disposed)
        unsubscribers = [
          "accountsChanged",
          "chainChanged",
          ...NOTIFICATIONS,
          "wallet_sessionChanged",
        ].flatMap((event) => connection.on?.({ event, listener }) ?? []);
    })
    .catch(listener);
  return () => {
    disposed = true;
    unsubscribers.forEach((unsubscribe) => unsubscribe());
  };
}

export async function revokeHumidSession(): Promise<void> {
  await window.humid?.request({ method: "wallet_revokeSession" });
}

export async function getHumidUtxos(wallet: HumidWallet): Promise<HumidUtxo[]> {
  const result = await invoke<{
    chainId: string;
    accountIdentifier: string;
    policyAssetId: string;
    utxos: HumidUtxo[];
  }>(wallet, "getUTXOs", {
    assetId: `${wallet.chainId}/elip144:${wallet.policyAssetId}`,
  });
  if (
    result.chainId !== wallet.chainId ||
    result.accountIdentifier !== wallet.accountIdentifier ||
    rawAssetId(result.policyAssetId, wallet.chainId) !== wallet.policyAssetId
  )
    throw new Error("Humid account changed. Reconnect your wallet");
  return result.utxos
    .map((utxo) => ({
      ...utxo,
      assetId: rawAssetId(utxo.assetId, wallet.chainId),
    }))
    .filter(
      (utxo) =>
        utxo.spendable &&
        utxo.assetId === wallet.policyAssetId &&
        /^\d+$/.test(utxo.amount) &&
        Number.isSafeInteger(Number(utxo.amount)) &&
        Number(utxo.amount) > 0,
    );
}

export async function signHumidMessage(
  wallet: HumidWallet,
  message: string,
  address = wallet.address,
): Promise<string> {
  if (!(await validateHumidSession(wallet)))
    throw new Error("Reconnect Humid before signing");
  const result = await invoke<{
    address: string;
    protocol: string;
    signatureEncoding: string;
    signature: string;
  }>(wallet, "signMessage", {
    address,
    protocol: "ecdsa",
    message,
  });
  if (
    result.address !== address ||
    result.protocol !== "ecdsa" ||
    result.signatureEncoding !== "hex-recoverable-ecdsa-65" ||
    !/^[0-9a-f]{130}$/i.test(result.signature)
  )
    throw new Error("Humid returned an unsupported message signature");
  return result.signature.toLowerCase();
}

async function signPset(
  wallet: HumidWallet,
  pset: string,
  signInputs: Array<{ address: string; index: number }>,
  broadcast: boolean,
  backendUrl?: string,
): Promise<{ pset: string; txid?: string }> {
  if (!(await validateHumidSession(wallet, backendUrl)))
    throw new Error("Reconnect Humid before signing");
  const result = await invoke<{ pset: string; txid?: string }>(
    wallet,
    "signPset",
    {
      pset,
      broadcast,
      signInputs: signInputs.map((input) => ({ ...input, sighashTypes: [1] })),
    },
  );
  if (!result.pset || (broadcast && !/^[0-9a-f]{64}$/i.test(result.txid ?? "")))
    throw new Error("Humid did not return a broadcast transaction ID");
  return result;
}

export async function signHumidPset(
  wallet: HumidWallet,
  pset: string,
  signInputs: Array<{ address: string; index: number }>,
  backendUrl?: string,
): Promise<string> {
  return (await signPset(wallet, pset, signInputs, false, backendUrl)).pset;
}

export async function signAndBroadcastHumidPset(
  wallet: HumidWallet,
  pset: string,
  signInputs: Array<{ address: string; index: number }>,
  backendUrl?: string,
): Promise<string> {
  return (
    await signPset(wallet, pset, signInputs, true, backendUrl)
  ).txid!.toLowerCase();
}

export function descriptorChecksum(descriptor: string): string {
  let checksum = 1n;
  let classes = 0n;
  let classCount = 0;
  const polymod = (value: bigint) => {
    const top = checksum >> 35n;
    checksum = ((checksum & 0x7ffffffffn) << 5n) ^ value;
    const generators = [
      0xf5dee51989n,
      0xa9fdca3312n,
      0x1bab10e32dn,
      0x3706b1677an,
      0x644d626ffdn,
    ];
    for (let index = 0; index < generators.length; index += 1)
      if (((top >> BigInt(index)) & 1n) !== 0n) checksum ^= generators[index];
  };
  for (const character of descriptor) {
    const position = INPUT_CHARSET.indexOf(character);
    if (position < 0) return "";
    polymod(BigInt(position & 31));
    classes = classes * 3n + BigInt(position >> 5);
    if (++classCount === 3) {
      polymod(classes);
      classes = 0n;
      classCount = 0;
    }
  }
  if (classCount > 0) polymod(classes);
  for (let index = 0; index < 8; index += 1) polymod(0n);
  checksum ^= 1n;
  return Array.from(
    { length: 8 },
    (_, index) =>
      CHECKSUM_CHARSET[Number((checksum >> BigInt(5 * (7 - index))) & 31n)],
  ).join("");
}
