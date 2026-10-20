import { useEffect, useRef } from 'react'
import { Download, RefreshCw, SquareArrowOutUpRight, WalletCards, X } from 'lucide-react'

export default function HumidInstallDialog({ returnFocus, onClose, onRetry }: { returnFocus: Element | null; onClose: () => void; onRetry: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const dialog = dialogRef.current
    const previousFocus = returnFocus
    dialog?.showModal()

    return () => {
      dialog?.close()
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus()
    }
  }, [returnFocus])

  return <dialog ref={dialogRef} className="humid-install" aria-labelledby="humid-install-title" aria-describedby="humid-install-description"
    onCancel={(event) => { event.preventDefault(); onClose() }}
    onKeyDown={(event) => {
      if (event.key !== 'Tab') return
      const controls = event.currentTarget.querySelectorAll<HTMLElement>('button, a[href]')
      const first = controls[0]
      const last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }}
    onClick={(event) => {
      const bounds = event.currentTarget.getBoundingClientRect()
      if (event.target === event.currentTarget && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) onClose()
    }}>
    <div className="humid-install-heading">
      <span className="humid-install-symbol"><WalletCards size={22} aria-hidden="true" /></span>
      <button className="icon-button" aria-label="Close installation guide" title="Close installation guide" onClick={onClose}><X size={18} /></button>
    </div>
    <h2 id="humid-install-title">Install Humid</h2>
    <p id="humid-install-description">Humid wasn't detected in this browser. Add the Chrome extension to connect your wallet.</p>
    <ol className="humid-install-steps">
      <li><strong>Download and unzip</strong><p>Download Humid 1.1.3 below and extract the ZIP file.</p></li>
      <li><strong>Add it to Chrome</strong><p>Open <a href="chrome://extensions" target="_blank" rel="noopener noreferrer"><code>chrome://extensions</code></a>, turn on <b>Developer mode</b>, then choose <b>Load unpacked</b> and select the extracted extension folder.</p></li>
      <li><strong>Set up your wallet</strong><p>Open Humid and create or restore your wallet. Unlock it, then reload this tab and connect.</p></li>
    </ol>
    <a className="humid-install-release" href="https://github.com/BlockstreamResearch/humid/releases/tag/1.1.3" target="_blank" rel="noopener noreferrer">Release details<SquareArrowOutUpRight size={13} aria-hidden="true" /></a>
    <div className="humid-install-actions">
      <a className="secondary" href="https://github.com/BlockstreamResearch/humid/releases/download/1.1.3/humid-extension-1.1.3.zip" target="_blank" rel="noopener noreferrer"><Download size={16} aria-hidden="true" />Download Humid</a>
      <button className="primary" onClick={onRetry}><RefreshCw size={16} aria-hidden="true" />Try again</button>
    </div>
  </dialog>
}