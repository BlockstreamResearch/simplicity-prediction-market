import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  ArrowRight, Check, ChevronLeft, Clock3, LoaderCircle, LogIn, Radio,
  RefreshCw, Search, Settings2, ShieldCheck, SquareArrowOutUpRight, Trophy, WalletCards, X, LogOut,
} from 'lucide-react'
import { Buffer } from 'buffer'
import {
  address, CreatorOutput, Pset,
} from 'liquidjs-lib'
import {
  PriceOracleClient,
  createWalletSignedPriceRequest, decodePriceData, parseExecutedSignedPrice,
  parseExecutedTick, walletRequestSigningMessage, type OracleAccount,
  type OracleUtxo, type PriceFeedInfo, type PriceFeedRate,
} from '@price-oracle/sdk'
import './App.css'
import { addWalletInputDerivation, createFundingPset, EsploraClient, hydrateFundingPset, selectFundingUtxos, verifyMatchedEscrow } from './wallet'
import { connectHumid, getHumidUtxos, HumidNotDetectedError, revokeHumidSession, sameHumidWallet, signHumidMessage, signHumidPset, signAndBroadcastHumidPset,
  subscribeToHumidChanges, validateHumidSession, type HumidWallet, type HumidUtxo } from './humid'
import { displayPrice, fundOracleRequest, loadOracleVerification, meetsMarket, meetsPriceTick, PRICE_VALIDITY_EXTENSION_SECONDS, verifyIssuedPriceOutputs, verifyMarketAssets, waitForOutput, type PriceClaim, type PriceMarket } from './price-market'
import PriceDesk from './PriceDesk'
import HumidInstallDialog from './HumidInstallDialog'

const SATS = 100_000_000
const TRANSACTION_FEE = 1_000
const ORACLE_FEE = 10_000

type Prediction = {
  id: string
  title: string
  deadline: number
  created_at: number
  price: PriceMarket
}
type Contract = { script_pubkey: string }
type ExplicitUtxo = { txid: string; vout: number; script_pubkey: string; amount_sats: number; asset: string; stake_sats?: number }
export type ServerConfig = {
  policy_asset_id: string
  genesis_block_hash: string
  network: 'elementsregtest' | 'liquidtestnet'
  oracle_url: string
  matched_escrow_enabled: boolean
}
type Notice = { kind: 'error' | 'success'; message: string }
type StageState = 'idle' | 'pending' | 'done'
type Settlement = { predictionId: string; title: string; amountSats: number; txid: string }
type Position = {
  feeOutpoint: string
  positionOutpoint: string
  positionUtxo: ExplicitUtxo | null
  positionConfirmations: number
  redemptionFeeUtxo: ExplicitUtxo | null
  redemptionTxid: string
  redemptionConfirmations: number
  priceRequestHash: string
  priceClaim: PriceClaim | null
  priceSwept: boolean
}
type PersistedUserState = {
  wallet: HumidWallet | null
  account: OracleAccount | null
  walletScript: string
  walletUtxos: OracleUtxo[]
  selected: string | null
  stake: string
  positions: Record<string, Position>
  settlements: Settlement[]
}

const emptyPosition: Position = {
  feeOutpoint: '', positionOutpoint: '', positionUtxo: null, positionConfirmations: 0, redemptionFeeUtxo: null,
  redemptionTxid: '', redemptionConfirmations: 0,
  priceRequestHash: '', priceClaim: null, priceSwept: false,
}

const serverApi = import.meta.env.VITE_SERVER_API ?? 'http://127.0.0.1:3100'
const chainBackend = `${serverApi}/api/chain`
const chain = new EsploraClient(chainBackend)
const USER_STATE_KEY = 'signal-market:user-state:v3'
const MODE_KEY = 'signal-market:mode'

function loadUserState(key: string): Partial<PersistedUserState> {
  try {
    return JSON.parse(localStorage.getItem(key) ?? '{}') as Partial<PersistedUserState>
  } catch {
    return {}
  }
}

function formatTime(timestamp: number) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(timestamp * 1000)
}

function shortHex(value: string, size = 7) {
  return `${value.slice(0, size)}...${value.slice(-size)}`
}

function isActive(position: Position) {
  return Boolean(position.positionOutpoint && (!position.redemptionTxid || position.redemptionConfirmations < 1))
}

type StatusTone = 'open' | 'neutral' | 'accent' | 'success' | 'danger'

function marketStatus(market: Prediction, position: Position | undefined, now: number): { label: string; tone: StatusTone } {
  if (position?.redemptionTxid) {
    if (position.priceSwept) return { label: 'Swept', tone: 'danger' }
    return position.redemptionConfirmations < 1 ? { label: 'Claiming', tone: 'neutral' } : { label: 'Claimed', tone: 'success' }
  }
  const funded = Boolean(position?.positionOutpoint)
  if (position?.priceClaim) return { label: 'Claimable', tone: 'accent' }
  if (now < market.price.opens_at) return { label: 'Scheduled', tone: 'neutral' }
  if (now <= market.deadline) return { label: 'Open', tone: 'open' }
  if (funded && now <= market.deadline + market.price.claim_grace) return { label: 'Claim window', tone: 'accent' }
  return { label: 'Expired', tone: 'danger' }
}

function useAutoDismiss(notice: Notice | null, setNotice: (notice: Notice | null) => void) {
  useEffect(() => {
    if (!notice) return
    const timeout = window.setTimeout(() => setNotice(null), notice.kind === 'error' ? 10_000 : 5_000)
    return () => window.clearTimeout(timeout)
  }, [notice, setNotice])
}

async function json<Result>(path: string, init?: RequestInit): Promise<Result> {
  const response = await fetch(`${serverApi}${path}`, init)
  const body = (await response.json()) as Result | { error: string }
  if (!response.ok) {
    const error = body as { error?: string }
    throw new Error(error.error ?? `HTTP ${response.status}`)
  }
  return body as Result
}

function UserView({ predictions, refresh, config, walletSlot }: { predictions: Prediction[]; refresh: () => Promise<void>; config: ServerConfig; walletSlot: HTMLElement | null }) {
  const coordinatorApi = config.oracle_url
  const stateKey = config.network === 'liquidtestnet' ? `${USER_STATE_KEY}:${config.genesis_block_hash}` : USER_STATE_KEY
  const matchedEscrowEnabled = config.matched_escrow_enabled
  const [initialState] = useState(() => loadUserState(stateKey))
  const [wallet, setWallet] = useState<HumidWallet | null>(initialState.wallet ?? null)
  const [connected, setConnected] = useState(false)
  const [account, setAccount] = useState<OracleAccount | null>(initialState.account ?? null)
  const [walletScript, setWalletScript] = useState(initialState.walletScript ?? '')
  const [walletUtxos, setWalletUtxos] = useState<OracleUtxo[]>(initialState.walletUtxos ?? [])
  const [selected, setSelected] = useState<string | null>(initialState.selected ?? predictions[0]?.id ?? null)
  const [stake, setStake] = useState(initialState.stake ?? '0.001')
  const [positions, setPositions] = useState<Record<string, Position>>(initialState.positions ?? {})
  const [livePrice, setLivePrice] = useState<PriceFeedRate | null>(null)
  const [feedSymbols, setFeedSymbols] = useState<Record<number, string>>({})
  const [settlements, setSettlements] = useState<Settlement[]>(initialState.settlements ?? [])
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<'all' | 'open' | 'closed'>('all')
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [humidInstall, setHumidInstall] = useState<{ trigger: Element | null } | null>(null)
  const [now, setNow] = useState(() => Date.now() / 1000)
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  useAutoDismiss(notice, setNotice)
  const prediction = predictions.find(({ id }) => id === selected)
  const position = prediction ? positions[prediction.id] : undefined
  const {
    feeOutpoint, positionOutpoint, positionUtxo, positionConfirmations, redemptionFeeUtxo,
    redemptionTxid, redemptionConfirmations, priceRequestHash, priceClaim, priceSwept,
  } = position ?? emptyPosition
  const priceTerms = prediction?.price
  const liveQualifies = Boolean(priceTerms && livePrice && livePrice.main.feed.valid_until > now
    && now >= priceTerms.opens_at && now <= prediction!.deadline
    && livePrice.main.feed.received_at >= priceTerms.opens_at && livePrice.main.feed.received_at <= prediction!.deadline
    && (priceTerms.above ? BigInt(livePrice.main.feed.price) >= BigInt(priceTerms.strike) : BigInt(livePrice.main.feed.price) <= BigInt(priceTerms.strike)))
  const isFundedPrediction = Boolean(position?.positionOutpoint)
  const positionActive = Boolean(position && isActive(position))
  const activePositions = Object.values(positions).filter(isActive)
  const marketOpen = prediction && now >= prediction.price.opens_at && prediction.deadline > now
  const ticketStatus = prediction ? marketStatus(prediction, position, now) : { label: '', tone: 'neutral' as StatusTone }
  const won = Boolean(isFundedPrediction && (priceClaim || redemptionTxid) && !priceSwept)
  const visiblePredictions = predictions.filter((item) => (
    item.title.toLowerCase().includes(search.toLowerCase())
      && (filter === 'all' || (filter === 'closed' ? item.deadline <= now : now >= item.price.opens_at && item.deadline > now))
  ))
  const balance = walletUtxos.reduce((sum, item) => sum + item.amountSats, 0)
  const positionStage: StageState = !isFundedPrediction || !positionOutpoint
    ? 'idle'
    : positionConfirmations >= 1 ? 'done' : 'pending'
  const ticketStake = isFundedPrediction && positionUtxo
    ? positionUtxo.stake_sats ?? positionUtxo.amount_sats : Math.round(Number(stake) * SATS)
  const ticketPayout = isFundedPrediction && positionUtxo ? positionUtxo.amount_sats : ticketStake * 2

  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now() / 1000), 1_000)
    return () => window.clearInterval(interval)
  }, [])

  useEffect(() => {
    let cancelled = false
    void json<PriceFeedInfo[]>('/api/prices').then((feeds) => {
      if (!cancelled) setFeedSymbols(Object.fromEntries(feeds.map((feed) => [feed.id, feed.symbol])))
    }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    let cancelled = false
    const update = async () => {
      if (!priceTerms) { setLivePrice(null); return }
      try {
        const rate = await json<PriceFeedRate>(`/api/prices/${priceTerms.feed_id}`)
        if (!cancelled) setLivePrice(rate)
      } catch { if (!cancelled) setLivePrice(null) }
    }
    void update()
    const interval = window.setInterval(update, 5000)
    return () => { cancelled = true; window.clearInterval(interval) }
  }, [priceTerms])

  useEffect(() => {
    const state: PersistedUserState = {
      wallet, account, walletScript, walletUtxos, selected, stake, positions, settlements,
    }
    localStorage.setItem(stateKey, JSON.stringify({ ...initialState, ...state }))
  }, [stateKey, initialState, wallet, account, walletScript, walletUtxos, selected, stake, positions, settlements])

  useEffect(() => {
    if (!wallet) return
    let cancelled = false
    const restore = async () => {
      if (!await validateHumidSession(wallet, chainBackend)) {
        if (!cancelled) setConnected(false)
        return
      }
      await chain.validateGenesis(config.genesis_block_hash)
      const verification = await loadOracleVerification(serverApi, wallet, config.network)
      const verified = await new PriceOracleClient(coordinatorApi).getAccount(wallet.publicKey.slice(2), verification)
      if (!cancelled) { setAccount(verified); setWalletScript(wallet.scriptPubKey); setConnected(true) }
    }
    void restore().catch((error: unknown) => {
      if (!cancelled) { setConnected(false); setNotice({ kind: 'error', message: error instanceof Error ? error.message : 'Account verification failed' }) }
    })
    const unsubscribe = subscribeToHumidChanges(() => { if (!cancelled) setConnected(false) })
    return () => { cancelled = true; unsubscribe() }
  }, [wallet, config.genesis_block_hash, config.network, coordinatorApi])

  useEffect(() => {
    const pending = Object.entries(positions).filter(([, item]) => (
      item.redemptionTxid ? item.redemptionConfirmations < 1 : item.positionUtxo && item.positionConfirmations < 1
    ))
    if (pending.length === 0) return
    let cancelled = false
    const refreshConfirmations = async () => {
      for (const [id, item] of pending) {
        try {
          const confirmations = await chain.getTransactionConfirmations(item.redemptionTxid || item.positionUtxo!.txid)
          if (cancelled) return
          if (item.redemptionTxid) {
            updatePosition(id, { redemptionConfirmations: confirmations })
            if (confirmations >= 1 && wallet && connected) setWalletUtxos(toOracleUtxos(await getHumidUtxos(wallet)))
          } else updatePosition(id, { positionConfirmations: confirmations })
        } catch {
          if (!cancelled && !item.redemptionTxid) updatePosition(id, { positionConfirmations: 0 })
        }
      }
    }
    void refreshConfirmations()
    const interval = window.setInterval(refreshConfirmations, 3_000)

    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [positions, wallet, connected])

  useEffect(() => {
    const unspent = Object.entries(positions).flatMap(([id, item]) => {
      const market = predictions.find((candidate) => candidate.id === id)
      return market?.price && item.positionUtxo && !item.redemptionTxid
        ? [{ id, utxo: item.positionUtxo, houseScript: market.price.house_script_pubkey }] : []
    })
    if (unspent.length === 0) return
    let cancelled = false
    const update = async () => {
      for (const { id, utxo, houseScript } of unspent) {
        try {
          const spend = await chain.getSpendingTransaction(utxo.txid, utxo.vout)
          if (spend && !cancelled) {
            updatePosition(id, { priceSwept: spend.payoutScript === houseScript, redemptionTxid: spend.txid, redemptionConfirmations: 0 })
          }
        } catch { /* Retry public indexing on the next refresh. */ }
      }
    }
    void update()
    const interval = window.setInterval(update, 3000)
    return () => { cancelled = true; window.clearInterval(interval) }
  }, [predictions, positions])

  function updatePosition(id: string, patch: Partial<Position>) {
    setPositions((previous) => {
      const current = previous[id] ?? emptyPosition
      const keys = Object.keys(patch) as (keyof Position)[]
      if (previous[id] && keys.every((key) => Object.is(current[key], patch[key]))) return previous
      return { ...previous, [id]: { ...current, ...patch } }
    })
  }

  function toOracleUtxos(utxos: HumidUtxo[]): (OracleUtxo & Pick<HumidUtxo, 'confidential'>)[] {
    return utxos.map((utxo) => ({ txid: utxo.txid, vout: utxo.vout, scriptPubKey: utxo.scriptPubKey,
      amountSats: Number(utxo.amount), asset: utxo.assetId, confidential: utxo.confidential }))
  }

  async function connect() {
    const trigger = humidInstall?.trigger ?? document.activeElement
    setBusy('connect')
    setNotice(null)
    try {
      await chain.validateGenesis(config.genesis_block_hash)
      const nextWallet = await connectHumid(config.policy_asset_id, chainBackend)
      if (activePositions.length > 0 && wallet && !sameHumidWallet(wallet, nextWallet)) {
        throw new Error('Reconnect the Humid account that owns your active positions')
      }
      const verification = await loadOracleVerification(serverApi, nextWallet, config.network)
      const nextAccount = await new PriceOracleClient(coordinatorApi).getAccount(nextWallet.publicKey.slice(2), verification)
      if (nextAccount.network !== config.network) throw new Error('The oracle network does not match the prediction chain')
      const utxos = toOracleUtxos(await getHumidUtxos(nextWallet))

      setWallet(nextWallet)
      setConnected(true)
      setAccount(nextAccount)
      setWalletScript(nextWallet.scriptPubKey)
      setWalletUtxos(utxos)
      setSettingsOpen(false)
      setNotice({ kind: 'success', message: `Wallet connected with ${utxos.length} spendable UTXO${utxos.length === 1 ? '' : 's'}.` })
    } catch (error) {
      if (error instanceof HumidNotDetectedError) setHumidInstall({ trigger })
      else setNotice({ kind: 'error', message: error instanceof Error ? error.message : 'Connection failed' })
    } finally { setBusy(null) }
  }

  async function disconnect() {
    setBusy('disconnect')
    try { await revokeHumidSession(); setConnected(false); setWalletUtxos([]); setSettingsOpen(false) }
    catch (error) { setNotice({ kind: 'error', message: error instanceof Error ? error.message : 'Disconnect failed' }) }
    finally { setBusy(null) }
  }

  async function lockPosition() {
    if (!prediction || !account || !wallet || !connected || !walletScript || isFundedPrediction || !marketOpen || !matchedEscrowEnabled) return
    setBusy('lock')
    setNotice(null)
    let pendingFundingId: string | null = null
    try {
      const verification = await loadOracleVerification(serverApi, wallet, config.network)
      verifyMarketAssets(prediction.price, verification)
      const account = await new PriceOracleClient(coordinatorApi).getAccount(wallet.publicKey.slice(2), verification)
      const policyAsset = wallet.policyAssetId
      const humidUtxos = await getHumidUtxos(wallet)
      const discovered = toOracleUtxos(humidUtxos)
      const checked = await Promise.all(discovered.map(async (utxo) => (
        await chain.isConfirmedUnspent(utxo.txid, utxo.vout) ? utxo : null
      )))
        const liveUtxos = checked.filter((utxo) => utxo !== null).filter((utxo) => utxo.asset === policyAsset)
      setWalletUtxos(liveUtxos)
      const stakeSats = Math.round(Number(stake) * SATS)
      if (!Number.isSafeInteger(stakeSats) || stakeSats <= 0) throw new Error('Enter a valid stake amount')
      const inputs = selectFundingUtxos(liveUtxos, policyAsset, stakeSats + ORACLE_FEE + 3 * TRANSACTION_FEE + 1)
      const change = inputs.reduce((sum, input) => sum + input.amountSats, 0) - stakeSats - ORACLE_FEE - TRANSACTION_FEE
      const fundingInputs = inputs.map((input) => humidUtxos.find((utxo) => utxo.txid === input.txid && utxo.vout === input.vout)!)
      const confidentialInput = fundingInputs.find((input) => input.confidential)
      const feeReserve = confidentialInput ? 2 * TRANSACTION_FEE : change
      const contractRequest = { payout_script_pubkey: walletScript, owner_public_key: wallet.publicKey.slice(2) }
      const contract = await json<Contract>(`/api/predictions/${prediction.id}/contract`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(contractRequest),
      })
      const outputs = [new CreatorOutput(policyAsset, stakeSats, Buffer.from(contract.script_pubkey, 'hex')),
        new CreatorOutput(policyAsset, ORACLE_FEE, Buffer.from(account.script_pubkey, 'hex')),
        new CreatorOutput(policyAsset, feeReserve, Buffer.from(walletScript, 'hex'))]
      if (confidentialInput) {
        const confidential = address.fromConfidential(confidentialInput.address)
        outputs.push(new CreatorOutput(policyAsset, change - feeReserve,
          address.toOutputScript(confidential.unconfidentialAddress), confidential.blindingKey, 0))
      }
      outputs.push(new CreatorOutput(policyAsset, TRANSACTION_FEE, Buffer.alloc(0)))
      const unsigned = createFundingPset(inputs, outputs)
      await hydrateFundingPset(unsigned, fundingInputs, chain)
      const funding = await json<{ funding_id: string; pset: string; escrow_sats: number }>(`/api/predictions/${prediction.id}/escrow`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pset: unsigned.toBase64(), stake_sats: stakeSats, contract: contractRequest }),
      })
      pendingFundingId = funding.funding_id
      const matched = Pset.fromBase64(funding.pset)
      verifyMatchedEscrow(unsigned, matched, stakeSats)
      if (funding.escrow_sats !== stakeSats * 2) throw new Error('Host did not match the full stake')
      const signed = await signHumidPset(wallet, matched.toBase64(), fundingInputs.map((input, index) => ({ address: input.address, index })), chainBackend)
      const { txid } = await json<{ txid: string }>(`/api/predictions/${prediction.id}/escrow/commit`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ funding_id: funding.funding_id, pset: signed }),
      })
      pendingFundingId = null

      setWalletUtxos(liveUtxos.filter((utxo) => !inputs.some((input) => input.txid === utxo.txid && input.vout === utxo.vout)))
      updatePosition(prediction.id, {
        ...emptyPosition,
        positionOutpoint: `${txid}:0`,
        feeOutpoint: `${txid}:1`,
        positionUtxo: { txid, vout: 0, script_pubkey: contract.script_pubkey, amount_sats: funding.escrow_sats, asset: policyAsset, stake_sats: stakeSats },
        redemptionFeeUtxo: { txid, vout: 2, script_pubkey: walletScript, amount_sats: feeReserve, asset: policyAsset },
      })
      setNotice({ kind: 'success', message: `Yes position locked in ${shortHex(txid)}.` })
    } catch (error) {
      let message = error instanceof Error ? error.message : 'Lock transaction failed'
      if (pendingFundingId) {
        try {
          const response = await fetch(`${serverApi}/api/predictions/${prediction.id}/escrow/${pendingFundingId}`, { method: 'DELETE', signal: AbortSignal.timeout(5000) })
          if (!response.ok) message += ' Host reservation may remain for up to 10 minutes.'
        } catch { message += ' Host reservation may remain for up to 10 minutes.' }
      }
      setNotice({ kind: 'error', message })
    } finally { setBusy(null) }
  }

  async function requestPrice() {
    if (!prediction?.price || !account || !wallet || !connected || !isFundedPrediction || redemptionTxid) return
    setBusy('price')
    setNotice(null)
    try {
      const client = new PriceOracleClient(coordinatorApi)
      const verification = await loadOracleVerification(serverApi, wallet, config.network)
      verifyMarketAssets(prediction.price, verification)
      let requestHash = priceRequestHash
      if (!requestHash) {
        let oracleFee = feeOutpoint
        if (!oracleFee) {
          const funding = await fundOracleRequest(wallet, account, chainBackend)
          oracleFee = funding.feeOutpoint
          updatePosition(prediction.id, { feeOutpoint: oracleFee, redemptionFeeUtxo: funding.reserve })
        }
        const [txid, vout] = oracleFee.split(':')
        await waitForOutput(chain, txid, Number(vout))
        const request = createWalletSignedPriceRequest(wallet.publicKey, [oracleFee], walletScript, prediction.price.feed_id, { withTick: true })
        request.header.signature = await signHumidMessage(wallet, walletRequestSigningMessage(request))
        requestHash = (await client.submitTickRequest(request)).request_hash
        updatePosition(prediction.id, { priceRequestHash: requestHash, feeOutpoint: '' })
      }
      for (let attempt = 0; attempt < 120; attempt += 1) {
        const status = await client.getTickRequest(requestHash)
        if (status.status === 'failed') { updatePosition(prediction.id, { priceRequestHash: '' }); throw new Error(status.payload ?? 'Price request failed') }
        const issued = parseExecutedSignedPrice(status, {
          stormTreeRoot: verification.stormTreeRoot,
          feedId: prediction.price.feed_id,
          decimals: prediction.price.decimals,
          now: BigInt(Math.floor(Date.now() / 1000)),
        })
        if (issued) {
          if (!meetsMarket(issued.signedPrice, prediction.price, prediction.deadline)) {
            updatePosition(prediction.id, { priceRequestHash: '' })
            throw new Error('The issued price missed the strike or window. The oracle fee was spent; another request requires a new fee.')
          }
          const ticks = parseExecutedTick(status)?.results.filter((result) => result.kind === 'tick-utxo') ?? []
          if (ticks.length !== 1 || !Number.isInteger(ticks[0].vout) || ticks[0].vout < 0 || ticks[0].vout > 0xffffffff || ticks[0].vout === issued.verifierVout) {
            throw new Error('Oracle must issue one distinct Tick alongside the Verifier')
          }
          const [voucher, priceTick] = await Promise.all([
            waitForOutput(chain, issued.txid, issued.verifierVout),
            waitForOutput(chain, issued.txid, ticks[0].vout),
          ])
          verifyIssuedPriceOutputs(issued.signedPrice, voucher, priceTick, verification)
          updatePosition(prediction.id, { priceClaim: { voucher, tick: priceTick, signedPrice: issued.signedPrice } })
          setNotice({ kind: 'success', message: 'Signed price verified. The Tick and Verifier are ready to claim.' })
          return
        }
        await new Promise((resolve) => window.setTimeout(resolve, 1000))
      }
      throw new Error('Oracle request is still pending. Check again to resume without another fee.')
    } catch (error) { setNotice({ kind: 'error', message: error instanceof Error ? error.message : 'Price request failed' }) }
    finally { setBusy(null) }
  }

  async function claimPrice() {
    if (!prediction?.price || !priceClaim || !wallet || !connected || !positionUtxo || !redemptionFeeUtxo || !isFundedPrediction || redemptionTxid) return
    setBusy('claim'); setNotice(null)
    try {
      if (!await chain.isConfirmedUnspent(priceClaim.voucher.txid, priceClaim.voucher.vout)) {
        updatePosition(prediction.id, { priceClaim: null, priceRequestHash: '' })
        throw new Error('The Verifier is spent or expired. Request a fresh proof while the market window is open.')
      }
      if (priceClaim.tick && !await chain.isConfirmedUnspent(priceClaim.tick.txid, priceClaim.tick.vout)) {
        updatePosition(prediction.id, { priceClaim: null, priceRequestHash: '' })
        throw new Error('The Tick is spent or expired. Request a fresh proof while the market window is open.')
      }
      if (priceClaim.tick && !meetsPriceTick(priceClaim.signedPrice, priceClaim.tick, prediction.price!.tick_asset_id)) {
        throw new Error('Tick is outside the signed price validity plus 55 minutes')
      }
      const prepared = await json<{ pset: string }>(`/api/predictions/${prediction.id}/claim`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ position: positionUtxo, voucher: priceClaim.voucher, tick: priceClaim.tick, fee: redemptionFeeUtxo,
          payout_script_pubkey: walletScript, auth_script_pubkey: walletScript,
          signed_price: { price_data: priceClaim.signedPrice.price_data, signer: priceClaim.signedPrice.storm_tree_bloom.branch, signature: priceClaim.signedPrice.storm_tree_bloom.signature } }),
      })
      const pset = Pset.fromBase64(prepared.pset)
      const feeIndex = pset.inputs.length - 1
      if (feeIndex !== 2 && feeIndex !== 3) throw new Error('Unexpected price claim input count')
      addWalletInputDerivation(pset, feeIndex, wallet)
      const txid = await signAndBroadcastHumidPset(wallet, pset.toBase64(), [{ address: wallet.address, index: feeIndex }], chainBackend)
      updatePosition(prediction.id, { redemptionTxid: txid, redemptionConfirmations: 0 })
      setSettlements((previous) => [{ predictionId: prediction.id, title: prediction.title, amountSats: positionUtxo.amount_sats, txid }, ...previous])
      setNotice({ kind: 'success', message: `Price claim broadcast in ${shortHex(txid)}.` })
    } catch (error) { setNotice({ kind: 'error', message: error instanceof Error ? error.message : 'Claim failed' }) }
    finally { setBusy(null) }
  }

  return <div className="workspace">
    {humidInstall && <HumidInstallDialog returnFocus={humidInstall.trigger} onClose={() => setHumidInstall(null)} onRetry={() => { setHumidInstall(null); void connect() }} />}
    <section className="portfolio-bar" aria-label="Wallet overview">
      <span className="section-label">Wallet overview</span>
      <div className="portfolio-item"><span>Available balance</span><strong>{connected ? (balance / SATS).toFixed(8) : '--'} <small>LBTC</small></strong></div>
      <div className="portfolio-item"><span>In position</span><strong>{(activePositions.reduce((sum, item) => sum + (item.positionUtxo?.amount_sats ?? 0), 0) / SATS).toFixed(8)} <small>LBTC</small></strong></div>
      <div className="portfolio-item"><span>Settlements</span><strong>{settlements.length.toString().padStart(2, '0')}</strong></div>
    </section>
    {walletSlot && createPortal(connected && wallet
      ? <button className="secondary wallet-toggle" onClick={() => setSettingsOpen(!settingsOpen)} aria-expanded={settingsOpen}><WalletCards size={16} />{`Humid ${shortHex(wallet.address, 5)}`}<Settings2 size={16} /></button>
      : <button className="primary wallet-toggle" onClick={connect} disabled={busy !== null}>{busy === 'connect' ? <LoaderCircle className="spin" size={16} /> : <WalletCards size={16} />}Connect Humid</button>, walletSlot)}
    {settingsOpen && connected && <section className="wallet-panel" aria-label="Wallet settings">
      <div className="section-heading"><div><span className="eyebrow">Connection</span><h2>Wallet settings</h2></div><button className="icon-button" title="Close wallet settings" onClick={() => setSettingsOpen(false)}><X size={18} /></button></div>
      <div className="wallet-fields">
        <button className="primary" onClick={connect} disabled={busy !== null}>{busy === 'connect' ? <LoaderCircle className="spin" size={17} /> : <WalletCards size={17} />}Refresh Humid</button>
        <button className="secondary" onClick={disconnect} disabled={busy !== null}><LogOut size={17} />Disconnect Humid</button>
      </div>
      {account && <div className="account-block"><span>Oracle Account</span><code>{account.address}</code></div>}
    </section>}
    <main className="market-panel">
      <div className="section-heading market-heading"><button className="icon-button" title="Refresh markets" disabled={busy !== null} onClick={() => { void refresh().catch(() => setNotice({ kind: 'error', message: 'Markets could not be refreshed' })) }}><RefreshCw size={20} /></button><h1>Markets</h1></div>
      <div className="market-toolbar"><div className="market-tabs" role="tablist" aria-label="Market status">{(['all', 'open', 'closed'] as const).map((value) => <button key={value} role="tab" aria-selected={filter === value} className={filter === value ? 'active' : ''} onClick={() => setFilter(value)}>{value === 'all' ? 'All markets' : value === 'open' ? 'Open' : 'Closed'}</button>)}</div><label className="search-field"><Search size={16} /><input type="search" aria-label="Search markets" placeholder="Search markets" value={search} onChange={(event) => setSearch(event.target.value)} /></label></div>
      <div className="market-columns"><span>Market</span><span>Outcome</span></div>
      <div className="market-list">
        {visiblePredictions.length === 0 && <div className="empty-state"><Search size={24} /><strong>{search ? 'No matching markets' : 'No markets in this view'}</strong></div>}
        {visiblePredictions.map((item) => <button key={item.id} aria-pressed={selected === item.id} disabled={busy !== null} className={`market-row ${selected === item.id ? 'selected' : ''}`} onClick={() => { setSelected(item.id); setNotice(null) }}><span className={`market-symbol ${(positions[item.id]?.redemptionConfirmations ?? 0) >= 1 ? 'settled' : ''}`}><Radio size={19} /></span><span className="market-copy"><strong>{item.title}</strong><small><Clock3 size={13} />{formatTime(item.deadline)}{positions[item.id] && isActive(positions[item.id]) && <span className="position-tag">Your position</span>}</small></span><span className={`status ${marketStatus(item, positions[item.id], now).tone}`}>{marketStatus(item, positions[item.id], now).label}</span><ArrowRight size={17} /></button>)}
      </div>
      {settlements.length > 0 && <section className="settlement-history"><div className="section-heading"><h2>Recent settlements</h2><Trophy size={17} /></div>{settlements.map((item) => <div className="settlement-row" key={item.txid}><span className="settlement-icon"><Check size={16} /></span><div><strong>{item.title}</strong><small>{shortHex(item.txid, 10)}</small></div><div className="settlement-amount"><strong>+{(item.amountSats / SATS).toFixed(8)} LBTC</strong><small>{positions[item.predictionId]?.redemptionTxid === item.txid && positions[item.predictionId].redemptionConfirmations < 1 ? 'Confirming' : 'Redeemed'}</small></div></div>)}</section>}
    </main>
    <aside className="order-panel">
      <div className="section-heading"><span className="eyebrow">Order ticket</span><ShieldCheck size={17} /></div><h2>{prediction?.title ?? 'Select a market'}</h2>
      {prediction && <p className="deadline"><Clock3 size={15} /> {formatTime(prediction.deadline)}</p>}
      {priceTerms && <section className="price-ticket" aria-label="Price market">
        <div className="quote-line"><span>Oracle feed</span><strong>{feedSymbols[priceTerms.feed_id] ?? `#${priceTerms.feed_id}`}</strong></div>
        <div className="quote-line"><span>Live price</span><strong>{livePrice && livePrice.main.feed.valid_until > now ? displayPrice(BigInt(livePrice.main.feed.price), priceTerms.decimals) : 'Unavailable'}</strong></div>
        <div className="quote-line"><span>Strike</span><strong>{priceTerms.above ? '>=' : '<='} {displayPrice(priceTerms.strike, priceTerms.decimals)}</strong></div>
        {livePrice && <meter aria-label="Live price relative to strike" min={0} max={Number(priceTerms.strike) * 2} low={Number(priceTerms.strike)} high={Number(priceTerms.strike)} optimum={priceTerms.above ? Number(priceTerms.strike) * 2 : 0} value={livePrice.main.feed.price} />}
        <div className="quote-line"><span>Opens</span><strong>{formatTime(priceTerms.opens_at)}</strong></div>
        <div className="quote-line"><span>Claim priority ends</span><strong>{formatTime(prediction!.deadline + priceTerms.claim_grace)}</strong></div>
        <div className="quote-line"><span>{now < priceTerms.opens_at ? 'Opens in' : now <= prediction!.deadline ? 'Window remaining' : 'Priority remaining'}</span><strong>{Math.max(0, Math.ceil((now < priceTerms.opens_at ? priceTerms.opens_at : now <= prediction!.deadline ? prediction!.deadline : prediction!.deadline + priceTerms.claim_grace) - now)).toLocaleString()} s</strong></div>
        <span className={`status ${ticketStatus.tone}`}>{ticketStatus.label === 'Open' && liveQualifies ? 'At strike' : ticketStatus.label}</span>
      </section>}
      {won && <div className="outcome-selection won"><span>Outcome</span><strong><Check size={16} />Won</strong></div>}
      <label>Stake, LBTC<input type="number" min="0.00000001" step="0.0001" disabled={busy !== null || positionActive} value={stake} onChange={(event) => setStake(event.target.value)} /></label>
      {(matchedEscrowEnabled || isFundedPrediction) && <><div className="quote-line"><span>Host match</span><strong>{Number.isSafeInteger(ticketPayout - ticketStake) && ticketStake > 0 ? ((ticketPayout - ticketStake) / SATS).toFixed(8) : '--'} LBTC</strong></div>
      <div className="quote-line"><span>Winning payout</span><strong>{Number.isSafeInteger(ticketPayout) && ticketStake > 0 ? (ticketPayout / SATS).toFixed(8) : '--'} LBTC</strong></div></>}
      {!isFundedPrediction && <button className="primary" onClick={lockPosition} disabled={!marketOpen || !connected || busy !== null || !matchedEscrowEnabled}>{busy === 'lock' ? <LoaderCircle className="spin" size={17} /> : <ShieldCheck size={17} />}{!matchedEscrowEnabled ? 'Host matching unavailable' : !marketOpen ? 'Market closed' : 'Participate'}</button>}
      {!connected && <button className="secondary" onClick={connect} disabled={busy !== null}>{busy === 'connect' ? <LoaderCircle className="spin" size={17} /> : <WalletCards size={17} />}Connect Humid</button>}
      {isFundedPrediction && <><div className="stage-list" aria-label="Position progress">
        <Stage state={positionStage} label="Position funded" value={positionStage === 'pending' ? 'Waiting for funding confirmation' : positionStage === 'done' ? shortHex(positionOutpoint) : ''} />
        <>
          <Stage
            state={priceClaim ? 'done' : busy === 'price' || priceRequestHash ? 'pending' : 'idle'}
            label="Price proof"
            value={priceClaim ? priceClaim.tick ? 'Signed price, Tick and Verifier ready' : 'Signed price and Verifier ready' : priceRequestHash ? busy === 'price' ? 'Waiting for signed price, Tick and Verifier' : 'Request pending; ready to check again' : busy === 'price' ? 'Preparing oracle request' : liveQualifies ? 'Ready to request' : 'Waiting for price to meet the strike'}
          />
          <Stage
            state={redemptionTxid ? redemptionConfirmations >= 1 ? 'done' : 'pending' : busy === 'claim' ? 'pending' : 'idle'}
            label={priceSwept ? 'Position closed' : 'Claim payout'}
            value={redemptionTxid ? redemptionConfirmations >= 1 ? priceSwept ? 'Swept to house' : 'Payout confirmed' : 'Waiting for payout confirmation' : busy === 'claim' ? 'Preparing and signing claim' : priceClaim ? 'Ready to sign in Humid' : ''}
          />
        </>
      </div>
      {priceTerms && positionConfirmations >= 1 && !priceClaim && !redemptionTxid && <button className="secondary" onClick={requestPrice} disabled={busy !== null || !connected || (!priceRequestHash && !liveQualifies)}>{busy === 'price' ? <LoaderCircle className="spin" size={17} /> : <Radio size={17} />}{busy === 'price' ? 'Waiting for Oracle' : priceRequestHash ? 'Check price request' : 'Request price proof'}</button>}
      {priceTerms && priceClaim && <details className="proof-details"><summary>Oracle proof</summary><span>Signer</span><code>{priceClaim.signedPrice.storm_tree_bloom.branch}</code><span>Verifier</span><code>{priceClaim.voucher.txid}:{priceClaim.voucher.vout}</code>{priceClaim.tick && <><span>Tick</span><code>{priceClaim.tick.txid}:{priceClaim.tick.vout}</code><span>Tick time</span><code>{formatTime(priceClaim.tick.amount_sats)}</code><span>Extended price validity</span><code>{formatTime(Number(decodePriceData(priceClaim.signedPrice.price_data).validUntil) + PRICE_VALIDITY_EXTENSION_SECONDS)}</code></>}</details>}
      {priceTerms && priceClaim && !redemptionTxid && <button className="primary" onClick={claimPrice} disabled={busy !== null || !connected}>{busy === 'claim' ? <LoaderCircle className="spin" size={17} /> : <Trophy size={17} />}Sign and claim</button>}
      {redemptionTxid && <div className="win-block">{redemptionConfirmations >= 1 ? <Trophy size={20} /> : <LoaderCircle className="spin" size={20} />}<div><strong>{redemptionConfirmations >= 1 ? priceSwept ? 'Position swept to house' : 'Position redeemed' : 'Settlement confirming'}</strong><span>{shortHex(redemptionTxid)}</span></div></div>}</>}
    </aside>
    {notice && <div className={`notice ${notice.kind}`} role={notice.kind === 'error' ? 'alert' : 'status'}><span>{notice.message}</span><button title="Dismiss notification" onClick={() => setNotice(null)}><X size={16} /></button></div>}
  </div>
}

function Stage({ state, label, value }: { state: StageState; label: string; value: string }) {
  return <div className={`stage ${state}`}><span>{state === 'done' ? <Check size={13} /> : state === 'pending' ? <Clock3 size={11} /> : null}</span><div><strong>{label}</strong>{value && <small>{value}</small>}</div></div>
}

function AdminView({ predictions, refresh, config }: { predictions: Prediction[]; refresh: () => Promise<void>; config: ServerConfig }) {
  const coordinatorApi = config.oracle_url
  const [token, setToken] = useState(sessionStorage.getItem('admin-token') ?? '')
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  useAutoDismiss(notice, setNotice)

  async function authenticate(event: React.FormEvent) {
    event.preventDefault(); setBusy(true)
    try {
      const response = await json<{ token: string }>('/api/admin/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login, password }) })
      sessionStorage.setItem('admin-token', response.token); setToken(response.token)
    } catch (error) { setNotice({ kind: 'error', message: error instanceof Error ? error.message : 'Login failed' }) } finally { setBusy(false) }
  }

  if (!token) return <form className="login-panel" onSubmit={authenticate}><div className="login-icon"><LogIn size={22} /></div><span className="eyebrow">Restricted</span><h2>Operator access</h2><label>Login<input autoComplete="username" value={login} onChange={(event) => setLogin(event.target.value)} /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label><button className="primary" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <LogIn size={16} />}Sign in</button>{notice && <div className={`notice inline ${notice.kind}`}>{notice.message}</div>}</form>

  return <div className="admin-workspace"><div className="admin-heading"><div><span className="eyebrow">Operations</span><h1>Market desk</h1></div><button className="secondary compact" onClick={() => { sessionStorage.removeItem('admin-token'); setToken('') }}><LogOut size={16} />Sign out</button></div><PriceDesk token={token} predictions={predictions} refresh={refresh} serverApi={serverApi} coordinatorApi={coordinatorApi} chainBackend={chainBackend} config={config} />{notice && <div className={`notice ${notice.kind}`} role="status">{notice.message}</div>}</div>
}

function App() {
  const [mode, setMode] = useState<'user' | 'admin'>(() => localStorage.getItem(MODE_KEY) === 'admin' ? 'admin' : 'user')
  const [walletSlot, setWalletSlot] = useState<HTMLElement | null>(null)
  const [predictions, setPredictions] = useState<Prediction[]>([])
  const [config, setConfig] = useState<ServerConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  async function refresh() {
    const [markets, config] = await Promise.all([
      json<Prediction[]>('/api/predictions'), json<ServerConfig>('/api/config'),
    ])
    setConfig(config)
    setPredictions(markets.toSorted((left, right) => right.created_at - left.created_at))
    setLoadError('')
  }
  useEffect(() => {
    void Promise.resolve().then(refresh).catch(() => setLoadError('Market service is unavailable')).finally(() => setLoading(false))
    const interval = window.setInterval(() => { void refresh().catch(() => setLoadError('Market updates are unavailable')) }, 5_000)
    return () => window.clearInterval(interval)
  }, [])

  function selectMode(nextMode: 'user' | 'admin') {
    localStorage.setItem(MODE_KEY, nextMode)
    setMode(nextMode)
  }

  return <div className={`app-shell ${mode}-mode`}><header><div className="brand"><div className="brand-title"><strong>Prediction Market</strong><span className="demo-chip"><button aria-describedby="demo-disclosure" aria-pressed={mode === 'admin'} onClick={() => selectMode('admin')}>Demo</button><p role="tooltip" id="demo-disclosure">This is a demonstration on test networks with test funds, not intended for real assets. Opens the Market desk.</p></span></div><small>Powered by Simplicity Oracle</small></div><div className="header-actions"><a className="about-link" href="https://simplicity-lang.org" target="_blank" rel="noreferrer">About Simplicity<SquareArrowOutUpRight size={16} /></a><section className="header-wallet" aria-label="Wallet summary" ref={setWalletSlot} hidden={mode !== 'user'} /></div></header>{loadError && <div className="service-error" role="alert">{loadError}<button className="icon-button" title="Retry market connection" onClick={() => { void refresh().catch(() => setLoadError('Market service is unavailable')) }}><RefreshCw size={16} /></button></div>}{loading || !config ? <div className="loading"><LoaderCircle className="spin" /> Loading markets</div> : <><div hidden={mode !== 'user'}><UserView key={config.genesis_block_hash} predictions={predictions} refresh={refresh} config={config} walletSlot={walletSlot} /></div>{mode === 'admin' && <><button className="back-link" onClick={() => selectMode('user')}><ChevronLeft size={16} />Back to Markets</button><AdminView key={config.genesis_block_hash} predictions={predictions} refresh={refresh} config={config} /></>}</>}</div>
}

export default App