import { useEffect, useState } from 'react'
import { Check, Clock3, Copy, LoaderCircle, Plus, Radio, RefreshCw, ShieldCheck, WalletCards } from 'lucide-react'
import { Pset } from 'liquidjs-lib'
import { PriceOracleClient, createWalletTickRequest, deriveAccount, parseExecutedTick, walletRequestSigningMessage, type PriceFeedInfo, type PriceFeedRate } from '@price-oracle/sdk'
import { connectHumid, HumidNotDetectedError, signHumidMessage, signAndBroadcastHumidPset, validateHumidSession, type HumidWallet } from './humid'
import HumidInstallDialog from './HumidInstallDialog'
import { addWalletInputDerivation, EsploraClient } from './wallet'
import { displayPrice, fundOracleRequest, loadOracleVerification, scaledPrice, verifyMarketAssets, waitForOutput, type ExplicitUtxo, type PriceMarket } from './price-market'
import type { ServerConfig } from './App'

type Market = { id: string; title: string; deadline: number; price: PriceMarket }
type ReserveStatus = { configured: boolean; funding_address: string | null; balance_sats: number; available_sats: number; reserved_sats: number; utxo_count: number; max_stake_sats: number }
type SweepState = { marketId: string; positionOutpoint: string; payoutScript: string; feeOutpoint: string; reserve: ExplicitUtxo | null; requestHash: string; tick: ExplicitUtxo | null; txid: string }
const KEY = 'signal-market:house-sweep:v1'
const emptySweep: SweepState = { marketId: '', positionOutpoint: '', payoutScript: '', feeOutpoint: '', reserve: null, requestHash: '', tick: null, txid: '' }

async function fetchReserves(serverApi: string, token: string, signal?: AbortSignal): Promise<ReserveStatus> {
  const response = await fetch(`${serverApi}/api/admin/escrow`, { headers: { authorization: `Bearer ${token}` }, signal })
  const result = await response.json() as ReserveStatus & { error?: string }
  if (!response.ok) throw new Error(result.error ?? 'Escrow reserves unavailable')
  return result
}

export default function PriceDesk({ token, predictions, refresh, serverApi, coordinatorApi, chainBackend, config }: {
  token: string; predictions: Market[]; refresh: () => Promise<void>; serverApi: string; coordinatorApi: string; chainBackend: string; config: ServerConfig
}) {
  const stateKey = config.network === 'liquidtestnet' ? `${KEY}:${config.genesis_block_hash}` : KEY
  const userStateKey = config.network === 'liquidtestnet' ? `signal-market:user-state:v3:${config.genesis_block_hash}` : 'signal-market:user-state:v3'
  const [wallet, setWallet] = useState<HumidWallet | null>(null)
  const [feeds, setFeeds] = useState<PriceFeedInfo[]>([])
  const [feedId, setFeedId] = useState(0)
  const [priceQuote, setPriceQuote] = useState<{ feedId: number; rate: PriceFeedRate | null } | null>(null)
  const [title, setTitle] = useState('')
  const [strike, setStrike] = useState('')
  const [above, setAbove] = useState(true)
  const [opensAt, setOpensAt] = useState('')
  const [deadline, setDeadline] = useState('')
  const [grace, setGrace] = useState(600)
  const [busy, setBusy] = useState('')
  const [notice, setNotice] = useState('')
  const [humidInstall, setHumidInstall] = useState<{ trigger: Element | null } | null>(null)
  const [reserves, setReserves] = useState<ReserveStatus | null>(null)
  const [reservesBusy, setReservesBusy] = useState(true)
  const [reservesError, setReservesError] = useState('')
  const [addressCopied, setAddressCopied] = useState(false)
  const [now, setNow] = useState(() => Date.now() / 1000)
  const [sweep, setSweep] = useState<SweepState>(() => {
    try { return { ...emptySweep, ...JSON.parse(localStorage.getItem(stateKey) ?? '{}') } as SweepState }
    catch { return emptySweep }
  })
  const feed = feeds.find((item) => item.id === feedId)
  const livePrice = priceQuote?.feedId === feedId ? priceQuote.rate : null
  const priceLoading = Boolean(feed && priceQuote?.feedId !== feed.id)
  const currentPrice = feed && livePrice?.main.feed.feed_id === feed.id && livePrice.main.feed.valid_until > now
    ? displayPrice(BigInt(livePrice.main.feed.price), feed.decimals) : null
  const market = predictions.find((item) => item.id === sweep.marketId)
  const expired = Boolean(market?.price && now > market.deadline + market.price.claim_grace)

  useEffect(() => { localStorage.setItem(stateKey, JSON.stringify(sweep)) }, [sweep, stateKey])
  useEffect(() => {
    const controller = new AbortController()
    void fetchReserves(serverApi, token, controller.signal).then((reserves) => {
      setReserves(reserves)
    }).catch((error: unknown) => {
      if (!controller.signal.aborted) setReservesError(error instanceof Error ? error.message : 'Escrow reserves unavailable')
    }).finally(() => { if (!controller.signal.aborted) setReservesBusy(false) })
    return () => controller.abort()
  }, [serverApi, token])
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => window.clearInterval(interval)
  }, [])
  useEffect(() => {
    let cancelled = false
    void fetch(`${serverApi}/api/prices`).then(async (response) => {
      if (!response.ok) throw new Error('Oracle feeds unavailable')
      const feeds = await response.json() as PriceFeedInfo[]
      if (!cancelled) { setFeeds(feeds); setFeedId(feeds[0]?.id ?? 0) }
    }).catch(() => { if (!cancelled) setNotice('Oracle feeds unavailable') })
    return () => { cancelled = true }
  }, [serverApi])

  useEffect(() => {
    let cancelled = false
    if (!feed) return

    const update = async () => {
      try {
        const response = await fetch(`${serverApi}/api/prices/${feed.id}`)
        if (!response.ok) throw new Error('Oracle price unavailable')
        const rate = await response.json() as PriceFeedRate
        if (!cancelled) setPriceQuote({ feedId: feed.id, rate: rate.main.feed.feed_id === feed.id && rate.main.feed.decimals === feed.decimals ? rate : null })
      } catch { if (!cancelled) setPriceQuote({ feedId: feed.id, rate: null }) }
    }

    void update()
    const interval = window.setInterval(update, 5000)
    return () => { cancelled = true; window.clearInterval(interval) }
  }, [feed, serverApi])

  async function api<Result>(path: string, body: unknown): Promise<Result> {
    const response = await fetch(`${serverApi}${path}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) })
    const result = await response.json() as Result & { error?: string }
    if (!response.ok) throw new Error(result.error ?? 'Market request failed')
    return result
  }

  async function refreshReserves() {
    setReservesBusy(true); setReservesError('')
    try { setReserves(await fetchReserves(serverApi, token)) }
    catch (error) { setReservesError(error instanceof Error ? error.message : 'Escrow reserves unavailable') }
    finally { setReservesBusy(false) }
  }

  async function copyFundingAddress() {
    if (!reserves?.funding_address) return
    try { await navigator.clipboard.writeText(reserves.funding_address); setAddressCopied(true) }
    catch { setReservesError('Funding address could not be copied') }
  }

  async function connect() {
    const trigger = humidInstall?.trigger ?? document.activeElement
    setBusy('connect'); setNotice('')
    try {
      const response = await fetch(`${serverApi}/api/config`)
      if (!response.ok) throw new Error('Market configuration unavailable')
      const config = await response.json() as ServerConfig
      await new EsploraClient(chainBackend).validateGenesis(config.genesis_block_hash)
      setWallet(await connectHumid(config.policy_asset_id, chainBackend))
    } catch (error) {
      if (error instanceof HumidNotDetectedError) setHumidInstall({ trigger })
      else setNotice(error instanceof Error ? error.message : 'Connection failed')
    }
    finally { setBusy('') }
  }

  async function activeWallet(): Promise<HumidWallet> {
    if (!wallet || !await validateHumidSession(wallet, chainBackend)) throw new Error('Reconnect the house Humid wallet')
    return wallet
  }

  async function publish(event: React.FormEvent) {
    event.preventDefault(); setBusy('publish'); setNotice('')
    try {
      const wallet = await activeWallet()
      if (!feed) throw new Error('Select an available oracle feed')
      await api('/api/admin/predictions', { title, deadline: Math.floor(new Date(deadline).getTime() / 1000), price: {
        feed_id: feed.id, strike: scaledPrice(strike, feed.decimals), above, opens_at: Math.floor(new Date(opensAt).getTime() / 1000),
        claim_grace: grace, house_script_pubkey: wallet.scriptPubKey,
      } })
      await refresh(); setTitle(''); setNotice('Price market published.')
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Publication failed') }
    finally { setBusy('') }
  }

  function chooseMarket(id: string) {
    let positionOutpoint = ''
    let payoutScript = ''
    try {
      const state = JSON.parse(localStorage.getItem(userStateKey) ?? '{}') as { walletScript?: string; positions?: Record<string, { positionOutpoint?: string }> }
      const position = state.positions?.[id]
      if (position) { positionOutpoint = position.positionOutpoint ?? ''; payoutScript = state.walletScript ?? '' }
    } catch {}
    setSweep({ ...emptySweep, marketId: id, positionOutpoint, payoutScript })
  }

  async function requestTick() {
    setBusy('tick'); setNotice('')
    try {
      const wallet = await activeWallet()
      if (!market?.price || !expired || wallet.scriptPubKey !== market.price.house_script_pubkey) throw new Error('Sweep requires the published house wallet and an expired claim-priority period')
      const client = new PriceOracleClient(coordinatorApi)
      const chain = new EsploraClient(chainBackend)
      const verification = await loadOracleVerification(serverApi, wallet, config.network)
      verifyMarketAssets(market.price, verification)
      let requestHash = sweep.requestHash
      if (!requestHash) {
        let feeOutpoint = sweep.feeOutpoint
        if (!feeOutpoint) {
          const account = await client.getAccount(wallet.publicKey.slice(2), verification)
          const funding = await fundOracleRequest(wallet, account, chainBackend)
          feeOutpoint = funding.feeOutpoint
          setSweep((state) => ({ ...state, feeOutpoint, reserve: funding.reserve }))
        }
        const [txid, index] = feeOutpoint.split(':')
        await waitForOutput(chain, txid, Number(index))
        const request = createWalletTickRequest(wallet.publicKey, [feeOutpoint], wallet.scriptPubKey)
        request.header.signature = await signHumidMessage(wallet, walletRequestSigningMessage(request))
        requestHash = (await client.submitTickRequest(request)).request_hash
        setSweep((state) => ({ ...state, requestHash, feeOutpoint: '' }))
      }
      for (let attempt = 0; attempt < 120; attempt += 1) {
        const status = await client.getTickRequest(requestHash)
        if (status.status === 'failed') { setSweep((state) => ({ ...state, requestHash: '' })); throw new Error(status.payload ?? 'Tick request failed') }
        const executed = status.status === 'executed' ? parseExecutedTick(status) : null
        const result = executed?.results.find((item) => item.kind === 'tick-utxo')
        if (executed && result) {
          const tick = await waitForOutput(chain, executed.txid, result.vout)
          if (tick.asset !== verification.tickAssetId || tick.script_pubkey !== deriveAccount(verification).tick_script_pubkey || tick.amount_sats <= market.deadline + market.price.claim_grace) throw new Error('Tick does not prove expiry')
          setSweep((state) => ({ ...state, tick })); setNotice('Expiry Tick ready.'); return
        }
        await new Promise((resolve) => window.setTimeout(resolve, 1000))
      }
      throw new Error('Tick is pending. Check again to resume without another fee.')
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Tick request failed') }
    finally { setBusy('') }
  }

  async function sweepPosition() {
    setBusy('sweep'); setNotice('')
    try {
      const wallet = await activeWallet()
      if (!market?.price || !sweep.tick || !sweep.reserve || wallet.scriptPubKey !== market.price.house_script_pubkey) throw new Error('House sweep is not ready')
      if (!/^[0-9a-f]{64}:\d+$/i.test(sweep.positionOutpoint)) throw new Error('Enter a position txid:vout')
      const chain = new EsploraClient(chainBackend)
      const [txid, index] = sweep.positionOutpoint.split(':')
      const position = await waitForOutput(chain, txid, Number(index))
      if (!await chain.isConfirmedUnspent(sweep.tick.txid, sweep.tick.vout)) {
        setSweep((state) => ({ ...state, tick: null, requestHash: '' }))
        throw new Error('Expiry Tick is spent or expired; request another Tick')
      }
      const prepared = await api<{ pset: string }>(`/api/predictions/${market.id}/sweep`, { position, voucher: sweep.tick, fee: sweep.reserve, payout_script_pubkey: sweep.payoutScript, auth_script_pubkey: wallet.scriptPubKey })
      const pset = Pset.fromBase64(prepared.pset)
      addWalletInputDerivation(pset, 2, wallet)
      const result = await signAndBroadcastHumidPset(wallet, pset.toBase64(), [{ address: wallet.address, index: 2 }], chainBackend)
      setSweep((state) => ({ ...state, txid: result })); setNotice(`House sweep broadcast: ${result}`)
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Sweep failed') }
    finally { setBusy('') }
  }

  return <>
    {humidInstall && <HumidInstallDialog returnFocus={humidInstall.trigger} onClose={() => setHumidInstall(null)} onRetry={() => { setHumidInstall(null); void connect() }} />}
    <section className="escrow-reserves" aria-label="Escrow reserves">
      <div className="section-heading"><div><span className="eyebrow">Backend wallet</span><h2>Escrow reserves</h2></div><button type="button" className="icon-button" title="Refresh escrow reserves" onClick={refreshReserves} disabled={reservesBusy}>{reservesBusy ? <LoaderCircle className="spin" size={17} /> : <RefreshCw size={17} />}</button></div>
      {reserves?.configured && reserves.funding_address ? <>
        <div className="escrow-address"><div><span>Unconfidential LBTC address</span><code>{reserves.funding_address}</code></div><button type="button" className="icon-button" title="Copy funding address" onClick={copyFundingAddress}>{addressCopied ? <Check size={17} /> : <Copy size={17} />}</button></div>
        <dl className="reserve-balances">
          <div><dt>Confirmed balance</dt><dd>{reserves.balance_sats.toLocaleString()} <small>sats</small></dd></div>
          <div><dt>Available</dt><dd>{reserves.available_sats.toLocaleString()} <small>sats</small></dd></div>
          <div><dt>Reserved</dt><dd>{reserves.reserved_sats.toLocaleString()} <small>sats</small></dd></div>
          <div><dt>Match limit</dt><dd>{reserves.max_stake_sats.toLocaleString()} <small>sats</small></dd></div>
        </dl>
        <span className="reserve-state">{reserves.available_sats === 0 ? (reserves.reserved_sats > 0 ? 'Reserved for pending participation' : 'Awaiting confirmed reserves') : `${reserves.utxo_count} confirmed reserve output${reserves.utxo_count === 1 ? '' : 's'}`}</span>
        {addressCopied && <span className="reserve-state" role="status">Funding address copied.</span>}
      </> : <span className="reserve-state">{reservesBusy ? 'Loading reserves...' : reserves ? 'Local escrow wallet not configured' : 'Reserves unavailable'}</span>}
      {reservesError && <div className="reserve-error" role="alert">{reservesError}</div>}
    </section>
    <section className="admin-create price-desk" aria-label="Price market publishing">
      <div className="section-heading"><div><span className="eyebrow">Oracle settlement</span><h2>Publish a price market</h2></div><button type="button" className="secondary compact" onClick={connect} disabled={Boolean(busy)}><WalletCards size={16} />{wallet ? 'Reconnect house' : 'Connect house Humid'}</button></div>
      <form onSubmit={publish}>
        <label>Question<input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={240} required /></label>
        <div className="feed-field">
          <label>Feed<select value={feedId} onChange={(event) => setFeedId(Number(event.target.value))}>{feeds.map((feed) => <option value={feed.id} key={feed.id}>{feed.symbol}</option>)}</select></label>
          {feed && <div className="quote-line feed-price" role="status" aria-label="Current feed price"><span>Current price</span><strong>{priceLoading ? 'Loading...' : currentPrice ?? 'Unavailable'}</strong></div>}
        </div>
        <label>Strike<input inputMode="decimal" value={strike} onChange={(event) => setStrike(event.target.value)} required /></label>
        <div className="direction-control"><span>Direction</span><div className="market-tabs" role="group" aria-label="Strike direction"><button type="button" aria-pressed={above} className={above ? 'active' : ''} onClick={() => setAbove(true)}>At or above</button><button type="button" aria-pressed={!above} className={!above ? 'active' : ''} onClick={() => setAbove(false)}>At or below</button></div></div>
        <label>Opens<input type="datetime-local" value={opensAt} onChange={(event) => setOpensAt(event.target.value)} required /></label>
        <label>Deadline<input type="datetime-local" value={deadline} onChange={(event) => setDeadline(event.target.value)} required /></label>
        <label>Claim grace, seconds<input type="number" min={1} max={3600} value={grace} onChange={(event) => setGrace(Number(event.target.value))} required /></label>
        <button className="primary" disabled={Boolean(busy) || !wallet || !feed}><Plus size={17} />Publish price market</button>
      </form>
      {wallet && <div className="account-block"><span>House destination</span><code>{wallet.scriptPubKey}</code></div>}
    </section>
    <section className="price-sweep" aria-label="House sweep">
      <div className="section-heading"><h2>Expired price positions</h2><Clock3 size={17} /></div>
      <div className="sweep-fields">
        <label>Market<select value={sweep.marketId} disabled={Boolean(busy)} onChange={(event) => chooseMarket(event.target.value)}><option value="">Select market</option>{predictions.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label>
        <label>Position outpoint<input value={sweep.positionOutpoint} disabled={Boolean(busy)} onChange={(event) => setSweep({ ...sweep, positionOutpoint: event.target.value })} placeholder="txid:vout" /></label>
        <label>Holder payout script<input value={sweep.payoutScript} disabled={Boolean(busy)} onChange={(event) => setSweep({ ...sweep, payoutScript: event.target.value })} /></label>
      </div>
      <div className="sweep-actions">
        {!sweep.tick && <button className="secondary" onClick={requestTick} disabled={Boolean(busy) || !wallet || !expired || !sweep.positionOutpoint || !sweep.payoutScript}>{busy === 'tick' ? <LoaderCircle className="spin" size={17} /> : <Radio size={17} />}{sweep.requestHash ? 'Check expiry request' : 'Request expiry Tick'}</button>}
        {sweep.tick && !sweep.txid && <button className="primary" onClick={sweepPosition} disabled={Boolean(busy) || !wallet}>{busy === 'sweep' ? <LoaderCircle className="spin" size={17} /> : <ShieldCheck size={17} />}Sign house sweep</button>}
      </div>
      {sweep.txid && <div className="account-block"><span>Sweep transaction</span><code>{sweep.txid}</code></div>}
    </section>
    {notice && <div className="price-desk-notice" role="status">{notice}</div>}
  </>
}