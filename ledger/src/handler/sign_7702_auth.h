#pragma once

#include <stdbool.h>

#include "buffer.h"

/**
 * Handler for SIGN_7702_AUTH command.
 *
 * Signs an EIP-7702 delegation authorization:
 *   hash = keccak256(0x05 || rlp([chain_id, contract_address, nonce]))
 *   sig  = secp256k1_sign(hash, key_at_bip32_path)
 *
 * APDU payload (single chunk, P1=0x00 or 0x01, P2=0x00):
 *   [1]      len(bip32_path)   number of BIP32 components (e.g. 5)
 *   [4*n]    bip32_path        each component as uint32_be
 *   [8]      chain_id          uint64_be (0 = all chains)
 *   [20]     contract_address  raw 20 bytes
 *   [8]      nonce             uint64_be
 *
 * Response (65 bytes):
 *   [1]      v                 recovery id (0 or 1, NOT 27/28)
 *   [32]     r
 *   [32]     s
 *
 * @param[in]  cdata    Buffer with APDU command data.
 * @param[in]  display  Whether to show confirmation UI (P1=0x01).
 *
 * @return zero on success, nonzero on error.
 */
int handler_sign_7702_auth(buffer_t *cdata, bool display);

/**
 * Sign the EIP-7702 authorization hash stored in G_context and send response.
 * Called by the UI after user approval, or directly if P1=0x00 (blind sign).
 *
 * @return zero on success, nonzero on error.
 */
int sign_7702_auth_and_respond(void);
