# Signal Market

An Elements prediction demo with admin-resolved events and oracle-settled price-touch markets, supporting local regtest and official Liquid testnet oracle accounts. New price claims combine signed price data with network-issued Oracle Verifier and Tick UTXOs; expired positions also use a Tick.

## Run

### Liquid Testnet

The local server config uses `https://api.oracle-0.dev.blockstream.com` and official Liquid testnet Esplora. The API root returns 404; `/price-feeds`, `/price-feeds/{id}` and `/users/account/{owner}` are the relevant routes.

```toml
data_file = "data/predictions-liquidtestnet.json"
policy_asset_id = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"
genesis_block_hash = "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1"
oracle_url = "https://api.oracle-0.dev.blockstream.com"

[chain_backend]
esplora_url = "https://blockstream.info/liquidtestnet/api"
rpc_url = ""
rpc_username = ""
rpc_password = ""

[escrow]
private_key_file = "data/escrow-private-key.hex"
max_stake_sats = 1000000
```

With these values in `server/config.toml`, start `cargo run -p prediction-demo-server`, then `cd web && bun run dev`. No local oracle stack is needed for feed previews, Humid connections or publishing markets. The app connects to Humid's built-in Liquid Testnet chain (`bip122:a771da8e52ee6ad581ed1e9a99825e5b`) without adding a network or replacing its backend, derives `tex1` addresses and requires testnet LBTC rather than regtest funds. The frontend obtains the oracle URL and network from `/api/config`.

The local escrow wallet enables host matching on testnet without an Elements node wallet. Its separate private key is generated on first startup in the ignored `data` directory. Log in to **Market desk** and use **Escrow reserves** to copy its public funding address and refresh its confirmed balance. Send testnet LBTC to that unconfidential `tex1` address; a reserve output must be confirmed and at least equal to the requested stake. A blank `rpc_url` uses Esplora for ordinary transactions, including opening escrow. Tick/Verifier-burning settlements still require general RPC credentials for an Elements node on Liquid testnet, but never wallet RPC or its private keys. Never use the local regtest RPC for testnet. Existing regtest market files, wallet caches and saved positions are preserved; testnet uses separate storage.

### Local Regtest

Prerequisites: Bun, Rust 1.97.1, Simplex 0.0.12, the Price Oracle development environment, and the local Humid extension with mixed-input PSET signing support.

`server/config.example.toml` retains the local regtest chain, oracle and matched escrow configuration. Use those values in `server/config.toml`, with `listen_address = "127.0.0.1:3100"` for the web app's default server URL, before following these steps.

```sh
cd ../price-oracle/high-storm
./devenv.sh up

cd ../../prediction-demo
cargo run -p prediction-demo-server

cd web
bun install
bun run dev
```

Open `http://127.0.0.1:5173`. The example admin credentials are `admin` / `prediction-demo`.

Humid is the holder's wallet and signer. Connect Humid in the Markets workspace and approve access to its public wallet descriptor, UTXOs, message signing, and PSET signing. New escrow openings use non-broadcast signing: the server checks the transaction, signs only the host contribution with its backend reserve wallet, and broadcasts the joint transaction. Claims still use Humid signing and broadcast. The website never requests, generates, or stores wallet private keys or node RPC credentials. A rejected approval does not broadcast a transaction or consume an oracle fee. Account, chain, and session changes require reconnecting; an active position requires its original Humid wallet.

Humid uses the same custom regtest chain as the oracle dashboard, through the demo's Esplora-compatible `/api/chain` backend. It forwards public reads to Esplora and broadcasts signed transactions using server-held RPC credentials. The relay permits an explicit, tagged burn of the active network's Tick (up to a 32-bit timestamp) or Verifier (exactly one unit), or their uniquely tagged pair at inputs 1 (Verifier) and 2 (Tick). It rejects duplicate tags/assets, other assets and policy-asset burns. This is needed because the ordinary Esplora broadcaster rejects voucher burns with `maxburnamount=0`. Configure upstream URLs and credentials under `[chain_backend]` in the server config; defaults match the bundled local services. Switching from a cached direct-Esplora backend requires Humid approval, not a new wallet. The market board includes search, status filters, a balance summary, and recent settlements. Market desk handles publishing and signed event resolutions. Predictions refresh automatically.

The SDK obtains the active Tick asset and a script-authorized Tick covenant bound to Humid's external `/0/0` wallet script. Funding prefers live, confirmed confidential policy-asset outputs and combines them when necessary, including payouts from earlier predictions. Explicit inputs remain a fallback. Humid prepares and signs the funding PSET. Confidential funding inputs retain confidential change and an explicit settlement fee reserve. The prediction stake, oracle fee, Tick asset and burn, and transaction fee remain explicit.

## Matched Escrow

New positions lock twice the holder's stake: half from Humid and half from the host reserve wallet. A 100,000-sat stake therefore creates a 200,000-sat position and a winning claim pays 200,000 sats, before fees. The holder still pays oracle and transaction fees. Existing funded positions keep their original payout amounts; they are not retroactively matched. For price markets, the house sweep receives the full escrow after deadline plus grace under the existing timeout rules.

For local signing, set `[escrow]` with `private_key_file = "data/escrow-private-key.hex"` and `max_stake_sats = 1000000`, without a `wallet` entry. Paths are relative to the server's working directory. The backend creates a random 32-byte key when the file is absent, with owner-only permissions on Unix, or loads an existing hex key. It rejects the admin resolution key and never exposes the reserve key through the API or browser. Back up this file securely: losing or deleting a funded key loses access to its reserves. Do not commit it, hardcode it in source, or share it with the frontend. This is a development hot wallet, not production custody.

In **Market desk → Escrow reserves**, copy the stable unconfidential funding address and refresh the confirmed, available and reserved balances. `GET /api/admin/escrow` requires the admin session. Only confirmed, explicit LBTC outputs are available; confidential deposits and other assets are not spendable in this mode. Each proposal reserves one output at least equal to its stake for up to ten minutes, so split reserves across several outputs for concurrent openings. Positive change returns to the same backend address; an exact match has no host-change output. Reserved balance represents pending participation, not spent funds. The backend verifies Esplora's genesis, raw reserve and holder prevouts, and actual holder signatures, then signs its own input locally with `SIGHASH_ALL`. Neither matching nor opening escrow calls node wallet RPC. The reserve wallet is separate from both the admin signing key and the house Humid wallet that receives sweeps.

The legacy node-wallet mode remains available for local regtest: use `wallet = "prediction-host"` instead of `private_key_file`, with the same stake limit. That named wallet must be loaded on the configured Elements regtest node and contain confirmed, explicit policy-asset outputs at least equal to the requested stake. These two wallet modes are mutually exclusive.

`POST /api/predictions/{id}/escrow` prepares a ten-minute funding proposal; `/escrow/commit` verifies the Humid-signed PSET and co-signs it. Both sides check that the holder inputs and fees remain unchanged, the position contains exactly 2x the stake, and host change equals the host input minus one stake. The browser never signs the host input. Failed or rejected participation calls `DELETE /api/predictions/{id}/escrow/{funding_id}` to release the proposal immediately; cancellation requires its unguessable proposal ID and moves no funds. If the browser closes or cancellation cannot reach the server, the proposal expires within ten minutes. Restarting the server also clears pending proposals and requires preparing a new one.

The off-chain oracle request uses Humid's ECDSA `signMessage` approval. The coordinator verifies its signature against a domain-separated message binding the account key, compressed signing key, request kinds/payloads, and fee outpoints. Existing Schnorr clients remain supported. A position remains active until redemption confirms. Oracle requests retain their request hash so a timeout can be resumed without submitting the fee UTXO again.

Redemption uses Tick script authorization: input 2 spends the Humid fee reserve and authorizes input 1's tagged Tick burn. New positions use a versioned covenant that verifies confidential payout commitments preserve the stake's asset and amount. The backend blinds the payout and returned fee change using the public blinding key from Humid's reserve address, creates commitment-opening proofs, and then finalizes the prediction and Tick witnesses. Humid approves, signs only input 2, finalizes, and broadcasts through `signPset`. No separate Schnorr signer is used by the website, and wallet blinding private keys never leave Humid. The explicit stake still makes the payout amount inferable; this is not amount privacy for the prediction itself.

Existing positions keep the original explicit-payout covenant and redemption path. The server identifies the version from the position's script rather than trusting a client flag. Confidential redemption requires script-authorized Ticks; the legacy signature-authorized flow remains available for legacy positions.

Public wallet/position state uses `signal-market:user-state:v3`. Legacy demo state under `v2` is neither loaded nor deleted; old locally keyed positions are not migrated into the Humid wallet.

`devenv.sh up` preserves existing chain data. Use `create` only when intentionally resetting the oracle deployment. Wallet UTXOs come from Humid. Public Esplora reads verify confirmed/unspent outputs and track transaction confirmations; the demo checks Esplora's genesis against `/api/config` before connecting. There are no browser-side Elements RPC requests or RPC settings. Existing `v3` positions are preserved, and obsolete RPC fields are omitted when their public state is next persisted.

The server's `policy_asset_id` and `genesis_block_hash` must match the target Elements chain because both values are part of the Simplicity transaction environment. The regtest example matches the Price Oracle development environment created above; the Liquid testnet values are listed separately.

## Validate

```sh
cargo test -p prediction-demo-server
cargo test -p prediction-demo-contracts --lib --test price_market
cd contracts && simplex test
cd ../web && bun run test && bun run lint && bun run build
bunx playwright test e2e/price-ui.spec.ts
cd ../../price-oracle/web/sdk && bun run check
```

The offline contract unit tests execute the confidential covenant with several blinding factors and reject mismatched payout assets, amounts and opening proofs. Price tests execute both position and voucher covenants, covering inclusive window/strike boundaries, wrong feeds/signatures/Verifier keys/assets/amounts, payouts and burn tags, plus strict post-grace expiry and overflow rejection. Server tests verify immutable publication, persistence, real prevouts, sweep authentication, blocked admin resolution, both event covenant versions and relay limits. Wallet tests cover confidential-first funding, fragmented payouts, asset filtering, duplicate outpoints, insufficient funds and script-matched public blinding keys. Fixture browser tests verify resumption without another fee, fee-input-only signing, historical claims after grace and desktop/mobile controls without the chain. `simplex test` runs legacy chain-backed tests; use offline tests without advancing an existing deployment.

## Price Markets

In **Market desk**, connect the house Humid wallet and publish a price market with a feed, exact decimal strike, direction, opens/deadline, and claim grace (default 600 seconds). Publication pins the feed scale, house payout script and active Tick/Verifier/Storm Eye asset IDs. The house script comes from the connected wallet, not an arbitrary configuration default. Admin resolution is disabled for price markets. Existing event records and confidential event redemption remain compatible.

In **Markets**, connect the holder, select the market and lock a Yes position. Once its confirmed live quote meets the strike during the window, request a price proof. Humid signs one ECDSA oracle batch containing `signed-price-data` and `tick-utxo`, with script authorization tied to the holder's wallet. Only an `executed` issuance is accepted. The browser verifies the exact 32-byte price payload, BIP-340 signature and Tick time, and shows the signer, Verifier/Tick outpoints, Tick timestamp and extended price validity under **Oracle proof**.

**Sign and claim** sends the position, Verifier, Tick and wallet reserve to the server. The new covenant verifies the price signature, feed, scale, observation window and strike, checks that the amount-one network Verifier commits to that signer as its Taproot internal key, and requires `received_at <= Tick time < valid_until + 3300`. The signed price bytes are not modified; the contract extends their expiry by exactly 55 minutes and rejects addition overflow. The feed's normal five-minute validity therefore yields a one-hour Tick window from observation. The server verifies all confirmed/unspent chain prevouts, finalizes the position and both voucher inputs, and returns a PSET for Humid to sign only fee input 3. Output 1 burns the Verifier with `OP_RETURN <u32_be(1)>`; output 2 burns the Tick with `OP_RETURN <u32_be(2)>`. The price payout is explicit and preserves the full locked escrow, including the host match for new positions. Existing funded positions are recognized by their original script and retain their original amounts and legacy Verifier-only claim and fee input 2; saved legacy proofs do not require a Tick.

After deadline plus grace, the house can select the market under **Expired price positions**, supply the holder's public payout script and position outpoint, request an expiry Tick, then sign the house sweep. The covenant requires a Tick strictly later than the cutoff and pays the full stake to the published house script. The sweep API is admin-authenticated and Humid must use that house wallet.

The grace period delays sweeps; it does **not** invalidate historical Yes proofs. For new positions, an observation inside the market window remains claimable with an unspent Verifier and a Tick inside the extended validity interval. A bundled Tick proves validity at its recorded issuance time, not at eventual redemption; no browser wall clock or current block timestamp is substituted for it. Legacy positions retain the original observation-only time rule. After grace, a claim and sweep can compete for the position. A sweep is a timeout mechanism, not cryptographic proof that the price never touched. The house could sweep an unclaimed winning position. Verifiers/Ticks expire at roughly 60 blocks, so settle promptly and avoid rapid regtest mining around outstanding proofs.

Oracle requests spend 10,000 sats even when the issued price misses the strike/window. A miss can be retried during the window with a newly funded request; timeouts retain the request hash and resume without submitting the same fee again. Browser state contains only public wallet/position/proof data. House sweep state uses `signal-market:house-sweep:v1`.

The API's optional `oracle_url` defaults to `http://127.0.0.1:9100`; `/api/config` provides the configured URL to the web app, with `VITE_COORDINATOR_API` only as a fallback for older servers. `GET /api/prices` and `/api/prices/{id}` proxy previews. The contract imports the actual oracle SimplicityHL SDK through a Simplex path dependency; run `cd contracts && simplex build` after oracle contract changes. Both projects must retain their sibling layout.

### Live Event And Price Regression

With the oracle stack, prediction server, and Vite running:

```sh
cd web
bunx playwright install chromium
bun run test:e2e
```

The browser regression creates two distinct event predictions, funds and resolves each through the UI, obtains a Tick, redeems and confirms each payout, then checks persistence and desktop/mobile layout. It also publishes a price market below the current feed and claims with real Verifier and Tick vouchers, checking both tagged burns, then sweeps an unreachable-strike market with a post-expiry Tick. It funds a disposable wallet with 0.0018 regtest LBTC, forcing fragmented event funding. It verifies tagged voucher burns, spent positions, rejected approval, disconnect/reload behavior, and absence of private keys in app state. Tests append their own markets to the running server's data.

The regression injects a Humid-compatible provider backed by an isolated Node test signer, never passing its spending or blinding key into the page. It unblinds its confidential UTXOs, blinds funding and asserts confidential payout/change with an explicit Tick burn. It uses the live oracle, prediction API, and Elements chain; it does not exercise the installed extension's approval screens or LWK blinding implementation. Humid's mixed-input signing behavior has separate focused tests. Manually approve transactions in the rebuilt extension to verify the real wallet UI. Do not run the live regression against a deployment whose existing positions must not be advanced toward Tick expiry.

Optional environment overrides: `VITE_TEST_URL`, `TEST_COORDINATOR_API` (default `http://127.0.0.1:9100`), `TEST_ELEMENTS_RPC`, `TEST_RPC_USER`, `TEST_RPC_PASSWORD`, `TEST_FUNDING_WALLET` (default `bootstrap`), `TEST_ADMIN_LOGIN`, `TEST_ADMIN_PASSWORD`, `TEST_ESPLORA_URL` (default `http://127.0.0.1:3001`), and `TEST_CHAIN_BACKEND_URL` (default `http://127.0.0.1:3100/api/chain`). Fixture RPC credentials stay in the Node test process. The test waits for Esplora indexing after mining, broadcasts through the same restricted relay as Humid, and asserts that the browser never requests the node RPC port. The test refuses to fund any chain other than `elementsregtest`; defaults match the bundled local services.

Offline contract/API/SDK/web tests and deterministic price browser scenarios pass. The extended live price claim/sweep regression still requires validation with the Docker/oracle stack and real Humid approval screens.
