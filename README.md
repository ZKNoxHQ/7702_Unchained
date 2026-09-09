# 7702 Unchained — Frontend

Sign & broadcast EIP-7702 delegation transactions from your browser with a mnemonic or from a ledger.

Built by [ZKNOX](https://zknox.com).

The **page lives in the [website repo](https://github.com/ZKNoxHQ/website)** as
`unchained.html`, so it shares the site's `styles.css` and `nav.js` instead of
carrying its own copy of the navigation. This repo holds the Ledger app source
(`ledger/`) and the assets; it is cloned into the website as `7702_Unchained/`.

## Quick Start

Serve the website checkout (with this repo cloned inside it as `7702_Unchained/`):

```bash
cd /path/to/website
npx serve .
```

Open [http://localhost:3000/unchained.html](http://localhost:3000/unchained.html) in Chrome.
It must be served over HTTP — `file://` breaks the root-relative `/nav.js`.

## Requirements

- **Chrome** (WebHID support required for Ledger tabs)
- A Ledger Nano S+ with the **7702 Unchained** app sideloaded via [ZKNOX orange](https://zknox.com/sideloader.html), or rebuild from the ledger/ directory in this repo.
- No build step — everything loads from CDN (`esm.sh`)

## Tabs

### Mnemonic

Self-execution mode: BIP-39 mnemonic → `m/44'/60'/0'/0/0` → EOA signs both the EIP-7702 authorization and the outer type-0x04 transaction.

- `tx.nonce = N`, `auth.nonce = N+1`
- Zero dependencies beyond the browser

### Ledger+Relay

Sponsored delegation: the Ledger signs the EIP-7702 authorization (INS `0x08`), a separate relay key signs and broadcasts the outer transaction.

- Relay can be a different account (sponsored gas) or the same EOA
- If relay == EOA, nonce logic adjusts automatically (`auth.nonce = N+1`)

### Ledger Only

Full hardware signing: the Ledger signs both the authorization (INS `0x08`) and the outer transaction hash (INS `0x09`). No private key ever touches the browser.

- State machine enforced on-device: INS `0x09` only works immediately after a successful INS `0x08`
- One-shot: the signing right is revoked after a single use

## Networks

Sepolia, Holesky, Mainnet, or custom RPC.

## Files

```
ledger/         — Ledger app source (the on-device 7702 Unchained app)
zknox-logo.png  — ZKNOX logo

website/
└── unchained.html  — The app itself (HTML + JS, no build)
```

## License

MIT — ZKNOX SAS 2025
