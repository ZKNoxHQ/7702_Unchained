# 7702 Unchained — Frontend

Sign & broadcast EIP-7702 delegation transactions from your browser with a mnemonic or from a ledger.

Built by [ZKNOX](https://zknox.com).

## Quick Start

```bash
npx serve .
```

Open [http://localhost:3000](http://localhost:3000) in Chrome.

## Requirements

- **Chrome** (WebHID support required for Ledger tabs)
- A Ledger Nano S+ with the **7702 Unchained** app sideloaded via [ZKNOX orange](https://zknox.com/zknox-orange/sideloader)
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
index.html      — Self-contained app (HTML + JS, no build)
zknox-logo.png  — ZKNOX logo
```

## License

MIT — ZKNOX SAS 2025
