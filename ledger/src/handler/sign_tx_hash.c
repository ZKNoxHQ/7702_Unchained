/*****************************************************************************
 *   ZKNOX — Sign TX Hash Handler (INS 0x09)
 *
 *   Signs a raw 32-byte hash on secp256k1.
 *
 *   SECURITY: State machine enforced — this handler ONLY executes if
 *   SIGN_7702_AUTH (INS 0x08) was successfully completed immediately before.
 *   The BIP-32 path must match the one used for the 7702 auth.
 *   After signing, the state is reset — one-shot only.
 *
 *   APDU: CLA=E0 INS=09 P1=00 P2=00
 *   Data: path_len(1) || path(4*n) || hash(32)
 *   Response: v(1) || r(32) || s(32) = 65 bytes
 *****************************************************************************/

#include <string.h>

#include "os.h"
#include "cx.h"
#include "buffer.h"
#include "io.h"

#include "sign_tx_hash.h"
#include "globals.h"
#include "constants.h"
#include "types.h"
#include "sw.h"

#ifndef SWO_EXEC_ERROR
#define SWO_EXEC_ERROR 0x6F00
#endif

/* 0x6982 = Security status not satisfied (ISO 7816-4) */
#ifndef SWO_NOT_ALLOWED
#define SWO_NOT_ALLOWED 0x6982
#endif

/* ─────────────── APDU handler ─────────────────────────────────── */

int handler_sign_tx_hash(buffer_t *cdata) {
    /*
     * STATE MACHINE CHECK:
     * Only proceed if SIGN_7702_AUTH was just completed successfully.
     */
    if (G_context.req_type != CONFIRM_7702_AUTH ||
        G_context.state != STATE_APPROVED) {
        PRINTF("SIGN_TX_HASH rejected: no prior SIGN_7702_AUTH approval\n");
        return io_send_sw(SWO_NOT_ALLOWED);
    }

    /* Parse BIP-32 path from APDU */
    uint8_t path_len;
    if (!buffer_read_u8(cdata, &path_len)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    if (path_len < 1 || path_len > MAX_BIP32_PATH) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    uint32_t bip32_path[MAX_BIP32_PATH];
    for (uint8_t i = 0; i < path_len; i++) {
        if (!buffer_read_u32(cdata, &bip32_path[i], BE)) {
            return io_send_sw(SWO_WRONG_DATA_LENGTH);
        }
    }

    /*
     * PATH VERIFICATION:
     * Must match the path used in the preceding SIGN_7702_AUTH call.
     * Prevents signing with a different key than what the user approved.
     */
    if (path_len != G_context.bip32_path_len) {
        PRINTF("SIGN_TX_HASH rejected: path length mismatch\n");
        G_context.state = STATE_NONE;  /* revoke approval */
        return io_send_sw(SWO_NOT_ALLOWED);
    }
    for (uint8_t i = 0; i < path_len; i++) {
        if (bip32_path[i] != G_context.bip32_path[i]) {
            PRINTF("SIGN_TX_HASH rejected: path component %d mismatch\n", i);
            G_context.state = STATE_NONE;  /* revoke approval */
            return io_send_sw(SWO_NOT_ALLOWED);
        }
    }

    /* Read 32-byte hash */
    uint8_t hash[32];
    if (cdata->size - cdata->offset < 32) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    memmove(hash, cdata->ptr + cdata->offset, 32);
    cdata->offset += 32;

    /*
     * ONE-SHOT: Reset state BEFORE signing so that even if the signing
     * succeeds, the handler cannot be called again without a new 0x08.
     */
    G_context.state = STATE_NONE;

    /* ── Sign ── */
    cx_ecfp_private_key_t private_key = {0};
    uint8_t raw_privkey[64] = {0};
    cx_err_t error;

    uint8_t raw_signature[72];
    size_t sig_len = sizeof(raw_signature);
    uint32_t info = 0;

    error = os_derive_bip32_no_throw(CX_CURVE_256K1,
                                     bip32_path,
                                     path_len,
                                     raw_privkey,
                                     NULL);
    if (error != CX_OK) {
        explicit_bzero(raw_privkey, sizeof(raw_privkey));
        return io_send_sw(SWO_EXEC_ERROR);
    }

    error = cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                               raw_privkey,
                                               32,
                                               &private_key);
    explicit_bzero(raw_privkey, sizeof(raw_privkey));
    if (error != CX_OK) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SWO_EXEC_ERROR);
    }

    error = cx_ecdsa_sign_no_throw(&private_key,
                                   CX_RND_RFC6979 | CX_LAST,
                                   CX_SHA256,
                                   hash,
                                   32,
                                   raw_signature,
                                   &sig_len,
                                   &info);

    explicit_bzero(&private_key, sizeof(private_key));
    if (error != CX_OK) {
        return io_send_sw(SWO_EXEC_ERROR);
    }

    /* Parse DER → v(1) + r(32) + s(32) */
    memset(G_io_apdu_buffer, 0, 65);
    G_io_apdu_buffer[0] = (info & CX_ECCINFO_PARITY_ODD) ? 1 : 0;

    size_t offset = 2;  /* skip 30 <total_len> */
    if (raw_signature[offset] != 0x02) {
        return io_send_sw(SWO_EXEC_ERROR);
    }
    offset++;
    size_t r_len = raw_signature[offset++];
    if (r_len == 33 && raw_signature[offset] == 0x00) {
        offset++;
        r_len = 32;
    }
    if (r_len > 32) {
        return io_send_sw(SWO_EXEC_ERROR);
    }
    memmove(G_io_apdu_buffer + 1 + (32 - r_len), raw_signature + offset, r_len);
    offset += r_len;

    if (raw_signature[offset] != 0x02) {
        return io_send_sw(SWO_EXEC_ERROR);
    }
    offset++;
    size_t s_len = raw_signature[offset++];
    if (s_len == 33 && raw_signature[offset] == 0x00) {
        offset++;
        s_len = 32;
    }
    if (s_len > 32) {
        return io_send_sw(SWO_EXEC_ERROR);
    }
    memmove(G_io_apdu_buffer + 33 + (32 - s_len), raw_signature + offset, s_len);

    return io_send_response_pointer(G_io_apdu_buffer, 65, SWO_SUCCESS);
}
