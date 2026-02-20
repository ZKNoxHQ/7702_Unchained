#pragma once

#include "buffer.h"

/**
 * Sign a 32-byte hash on secp256k1 at the BIP-32 path in the APDU.
 * INS = 0x09
 *
 * SECURITY: Only executes after a successful SIGN_7702_AUTH (INS 0x08).
 *           Path must match. One-shot — state is reset after signing.
 *
 * Data: path_len(1) || path(4*n) || hash(32)
 * Response: v(1) || r(32) || s(32) = 65 bytes
 */
int handler_sign_tx_hash(buffer_t *cdata);
