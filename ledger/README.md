# 7702 Unchained — Ledger App

EIP-7702 delegation signing for Ledger Nano S+.

Built by [ZKNOX](https://zknox.com) on top of the Ledger app-boilerplate.

## Build & Install

```bash
# In the Docker container
make clean && make

# Sideload via ZKNOX orange
# https://zknox.com/zknox-orange/sideloader
```

## Makefile Configuration

```makefile
APPNAME            = "7702 Unchained"
CURVE_APP_LOAD_PARAMS = secp256k1
PATH_APP_LOAD_PARAMS  = "44'/1'" "44'/60'"   # Testnet + Ethereum
```

## APDU Reference

All APDUs use `CLA = 0xE0`.

---

### GET_VERSION — `INS 0x03`

Returns the app version.

```
┌──────┬──────┬──────┬──────┬──────┐
│ CLA  │ INS  │  P1  │  P2  │  Lc  │
│  E0  │  03  │  00  │  00  │  00  │
└──────┴──────┴──────┴──────┴──────┘
```

**Response:**
```
┌──────────┬──────────┬──────────┬──────┐
│ major(1) │ minor(1) │ patch(1) │  SW  │
└──────────┴──────────┴──────────┴──────┘
```

---

### GET_APP_NAME — `INS 0x04`

Returns the application name as ASCII string.

```
┌──────┬──────┬──────┬──────┬──────┐
│ CLA  │ INS  │  P1  │  P2  │  Lc  │
│  E0  │  04  │  00  │  00  │  00  │
└──────┴──────┴──────┴──────┴──────┘
```

**Response:**
```
┌───────────────────┬──────┐
│   app_name (var)  │  SW  │
└───────────────────┴──────┘
```

---

### GET_PUBLIC_KEY — `INS 0x05`

Derives and returns the public key at the given BIP-32 path.

```
┌──────┬──────┬──────┬──────┬──────┬─────────────────────────────────────┐
│ CLA  │ INS  │  P1  │  P2  │  Lc  │               Data                  │
│  E0  │  05  │ 0/1  │  00  │  15  │  path_len(1) │ bip32_path(4×n)     │
└──────┴──────┴──────┴──────┴──────┴─────────────────────────────────────┘
```

- **P1**: `0x00` = no display, `0x01` = display address on device
- **path_len**: number of BIP-32 components (typically `05`)
- **bip32_path**: each component as 4 bytes big-endian, hardened = `0x80000000 | index`

**Example** — `m/44'/60'/0'/0/0`:
```
E0 05 00 00 15 05 8000002C 8000003C 80000000 00000000 00000000
```

**Response:**
```
┌────────────┬──────────────┬───────────────┬─────────────────┬──────┐
│ pk_len (1) │ pubkey (65)  │ chain_len (1) │ chaincode (32)  │  SW  │
└────────────┴──────────────┴───────────────┴─────────────────┴──────┘
```

- **pubkey**: uncompressed secp256k1, `04 || x(32) || y(32)`
- ETH address: `keccak256(pubkey[1:])[12:]`

---

### SIGN_7702_AUTH — `INS 0x08`

Signs an EIP-7702 delegation authorization.

Computes `keccak256(0x05 || rlp([chain_id, contract_address, nonce]))` on-device, displays the parameters for user confirmation, then signs with ECDSA secp256k1.

```
┌──────┬──────┬──────┬──────┬──────┬──────────────────────────────────────────────────┐
│ CLA  │ INS  │  P1  │  P2  │  Lc  │                    Data                           │
│  E0  │  08  │ 0/1  │  00  │  39  │ path_len(1) │ path(4×n) │ chain(8) │ addr(20) │ nonce(8) │
└──────┴──────┴──────┴──────┴──────┴──────────────────────────────────────────────────┘
```

- **P1**: `0x00` = blind sign, `0x01` = display & confirm on device
- **chain_id**: 8 bytes big-endian (e.g. `0x0000000000AA36A7` = Sepolia 11155111)
- **addr**: 20-byte contract address to delegate to
- **nonce**: 8 bytes big-endian, the EOA nonce for this authorization

**Example** — delegate to `0xEBF2...8703` on Sepolia, nonce 87:
```
E0 08 01 00 39
  05 8000002C 8000003C 80000000 00000000 00000000   ← m/44'/60'/0'/0/0
  0000000000AA36A7                                   ← chain_id = 11155111
  EBF2880FC108D61B0279FEC6132AC01FA8D58703           ← contract address
  0000000000000057                                   ← nonce = 87
```

**On-device display:**
```
┌─────────────────────────┐
│  EIP-7702 Delegation    │
│  Chain: 11155111        │
│  To: 0xebf2...8703      │
│  Nonce: 87              │
│  [Approve] [Reject]     │
└─────────────────────────┘
```

**Response:**
```
┌────────┬─────────┬─────────┬──────┐
│  v (1) │  r (32) │  s (32) │  SW  │
└────────┴─────────┴─────────┴──────┘
```

- **v**: `0x00` or `0x01` (yParity)
- **r, s**: ECDSA signature components

**Side effect:** Sets `G_context.state = STATE_APPROVED`, enabling INS `0x09`.

---

### SIGN_TX_HASH — `INS 0x09`

Signs a raw 32-byte hash (the outer type-0x04 transaction hash).

**⚠️ State machine enforced:**

```
                    ┌──────────────┐
                    │  STATE_NONE  │◄──────────────────────┐
                    └──────┬───────┘                       │
                           │ INS 0x08 succeeds             │
                           ▼                               │
                    ┌──────────────────┐                   │
                    │ STATE_APPROVED   │                   │
                    │ req = 7702_AUTH  │                   │
                    └──────┬───────────┘                   │
                           │ INS 0x09                      │
                           ▼                               │
                    ┌──────────────────┐     one-shot      │
                    │ Check path match │─── reset state ───┘
                    │ Sign hash        │
                    │ Return sig       │
                    └──────────────────┘
```

**Guards:**
1. `req_type == CONFIRM_7702_AUTH && state == STATE_APPROVED` → otherwise `0x6982`
2. BIP-32 path must match the path used in INS `0x08` → otherwise `0x6982`
3. State is reset to `STATE_NONE` **before** signing (one-shot)

```
┌──────┬──────┬──────┬──────┬──────┬────────────────────────────────────┐
│ CLA  │ INS  │  P1  │  P2  │  Lc  │               Data                 │
│  E0  │  09  │  00  │  00  │  35  │ path_len(1) │ path(4×n) │ hash(32) │
└──────┴──────┴──────┴──────┴──────┴────────────────────────────────────┘
```

**Example** — sign tx hash `0x4108AD7E...`:
```
E0 09 00 00 35
  05 8000002C 8000003C 80000000 00000000 00000000   ← must match INS 0x08
  4108AD7E97145047B5930FDE1C63A...                   ← 32-byte keccak hash
```

**Response:**
```
┌────────┬─────────┬─────────┬──────┐
│  v (1) │  r (32) │  s (32) │  SW  │
└────────┴─────────┴─────────┴──────┘
```

---

## Status Words

| SW       | Meaning                          |
|----------|----------------------------------|
| `0x9000` | Success                          |
| `0x6982` | Security not satisfied (state machine) |
| `0x6985` | User rejected on device          |
| `0x6A86` | Incorrect P1/P2                  |
| `0x6A87` | Wrong data length                |
| `0x6D00` | INS not supported                |
| `0x6E00` | CLA not supported                |
| `0x6F00` | Internal error (signing failure) |

## Complete Delegation Flow

### Self-execution (Ledger Only tab)

```
 Browser                          Ledger Device
    │                                  │
    │── GET_PUBLIC_KEY (0x05) ────────►│
    │◄── pubkey + chaincode ───────────│
    │                                  │
    │   derive ETH address             │
    │   compute auth nonce = N+1       │
    │                                  │
    │── SIGN_7702_AUTH (0x08) ────────►│
    │         P1=0x01 (display)        │  ┌──────────────────┐
    │                                  │  │ User confirms on │
    │                                  │  │ device screen    │
    │◄── v, r, s ──────────────────────│  └──────────────────┘
    │                                  │  state = APPROVED
    │                                  │
    │   build type-0x04 unsigned tx    │
    │   tx hash = keccak256(04 || rlp) │
    │                                  │
    │── SIGN_TX_HASH (0x09) ──────────►│
    │         same path                │  check state + path
    │◄── v, r, s ──────────────────────│  state = NONE (reset)
    │                                  │
    │   assemble signed tx             │
    │   broadcast via RPC              │
    │                                  │
```

### Sponsored (Ledger+Relay tab)

```
 Browser                          Ledger Device
    │                                  │
    │── GET_PUBLIC_KEY (0x05) ────────►│
    │◄── pubkey ───────────────────────│
    │                                  │
    │── SIGN_7702_AUTH (0x08) ────────►│
    │◄── v, r, s (auth sig) ──────────│
    │                                  │
    │   relay key signs outer tx       │
    │   (no INS 0x09 needed)           │
    │   broadcast via RPC              │
    │                                  │
```

## Source Files

```
src/
├── types.h                      ← command_e enum (0x03–0x09, 0x22)
├── apdu/
│   ├── dispatcher.c             ← APDU routing (switch on INS)
│   └── dispatcher.h
├── handler/
│   ├── sign_7702_auth.c         ← INS 0x08: EIP-7702 auth signing
│   ├── sign_7702_auth.h
│   ├── sign_tx_hash.c           ← INS 0x09: blind hash signing (state machine)
│   ├── sign_tx_hash.h
│   ├── sign_tx.c                ← INS 0x06/0x07: legacy tx signing (boilerplate)
│   └── ...
└── ui/
    ├── display_7702_auth.c      ← NBGL confirmation screen
    └── ...
```

## License

MIT — ZKNOX SAS 2025
