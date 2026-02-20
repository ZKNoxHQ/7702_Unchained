/*****************************************************************************
 *   ZKNOX — EIP-7702 Authorization Signing Handler
 *
 *   Signs: keccak256( 0x05 || rlp([chain_id, contract_address, nonce]) )
 *   on secp256k1 at the BIP-32 path provided in the APDU.
 *
 *   Reference: https://eips.ethereum.org/EIPS/eip-7702
 *****************************************************************************/

#include <string.h>

#include "os.h"
#include "cx.h"
#include "buffer.h"
#include "io.h"

#include "sign_7702_auth.h"
#include "globals.h"
#include "constants.h"
#include "types.h"
#include "sw.h"
#include "ui.h"

// Generic internal/exec error — add to sw.h if not present:
//   #define SWO_EXEC_ERROR 0x6F00
#ifndef SWO_EXEC_ERROR
#define SWO_EXEC_ERROR 0x6F00
#endif

/* ────────────────────────── RLP helpers ────────────────────────── */

static size_t uint64_to_be(uint64_t v, uint8_t *out) {
    if (v == 0) return 0;
    uint8_t tmp[8];
    for (int i = 7; i >= 0; i--) {
        tmp[i] = (uint8_t) (v & 0xFF);
        v >>= 8;
    }
    size_t start = 0;
    while (start < 8 && tmp[start] == 0) start++;
    size_t len = 8 - start;
    memmove(out, tmp + start, len);
    return len;
}

static size_t rlp_encode_bytes(const uint8_t *data, size_t len, uint8_t *out) {
    if (len == 0) {
        out[0] = 0x80;
        return 1;
    }
    if (len == 1 && data[0] <= 0x7f) {
        out[0] = data[0];
        return 1;
    }
    out[0] = (uint8_t) (0x80 + len);
    memmove(out + 1, data, len);
    return 1 + len;
}

static size_t rlp_encode_uint64(uint64_t v, uint8_t *out) {
    if (v == 0) {
        out[0] = 0x80;
        return 1;
    }
    uint8_t be[8];
    size_t be_len = uint64_to_be(v, be);
    return rlp_encode_bytes(be, be_len, out);
}

/* ────────────────────── Hash construction ──────────────────────── */

static int build_7702_auth_hash(uint64_t chain_id,
                                const uint8_t contract_address[20],
                                uint64_t nonce,
                                uint8_t hash_out[32]) {
    uint8_t items[64];
    size_t items_len = 0;

    items_len += rlp_encode_uint64(chain_id, items + items_len);
    items_len += rlp_encode_bytes(contract_address, 20, items + items_len);
    items_len += rlp_encode_uint64(nonce, items + items_len);

    uint8_t payload[128];
    size_t payload_len = 0;
    payload[payload_len++] = 0x05;                            // EIP-7702 magic
    payload[payload_len++] = (uint8_t) (0xc0 + items_len);   // list header
    memmove(payload + payload_len, items, items_len);
    payload_len += items_len;

    cx_sha3_t keccak;
    if (cx_keccak_init_no_throw(&keccak, 256) != CX_OK) {
        return -1;
    }
    if (cx_hash_no_throw((cx_hash_t *) &keccak,
                         CX_LAST,
                         payload,
                         payload_len,
                         hash_out,
                         32) != CX_OK) {
        return -1;
    }
    return 0;
}

/* ──────────────────── Display string formatting ───────────────── */

static char g_chain_id_str[24];
static char g_address_str[43];
static char g_nonce_str[24];

static void format_hex(const uint8_t *data, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    for (size_t i = 0; i < len; i++) {
        out[2 + 2 * i] = hex[(data[i] >> 4) & 0x0f];
        out[2 + 2 * i + 1] = hex[data[i] & 0x0f];
    }
    out[2 + 2 * len] = '\0';
}

static void format_uint64(uint64_t v, char *out) {
    if (v == 0) {
        out[0] = '0';
        out[1] = '\0';
        return;
    }
    char tmp[24];
    int pos = 0;
    while (v > 0) {
        tmp[pos++] = '0' + (char) (v % 10);
        v /= 10;
    }
    for (int i = 0; i < pos; i++) {
        out[i] = tmp[pos - 1 - i];
    }
    out[pos] = '\0';
}

const char *get_7702_chain_id_str(void) {
    return g_chain_id_str;
}
const char *get_7702_address_str(void) {
    return g_address_str;
}
const char *get_7702_nonce_str(void) {
    return g_nonce_str;
}

/* ─────────────────── APDU parsing ─────────────────────────────── */

int handler_sign_7702_auth(buffer_t *cdata, bool display) {
    uint8_t path_len;
    if (!buffer_read_u8(cdata, &path_len)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    if (path_len < 1 || path_len > MAX_BIP32_PATH) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    G_context.bip32_path_len = path_len;
    for (uint8_t i = 0; i < path_len; i++) {
        if (!buffer_read_u32(cdata, &G_context.bip32_path[i], BE)) {
            return io_send_sw(SWO_WRONG_DATA_LENGTH);
        }
    }

    uint64_t chain_id = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b;
        if (!buffer_read_u8(cdata, &b)) {
            return io_send_sw(SWO_WRONG_DATA_LENGTH);
        }
        chain_id = (chain_id << 8) | b;
    }

    uint8_t contract_address[20];
    if (cdata->size - cdata->offset < 20) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    memmove(contract_address, cdata->ptr + cdata->offset, 20);
    cdata->offset += 20;

    uint64_t nonce = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b;
        if (!buffer_read_u8(cdata, &b)) {
            return io_send_sw(SWO_WRONG_DATA_LENGTH);
        }
        nonce = (nonce << 8) | b;
    }

    uint8_t auth_hash[32];
    if (build_7702_auth_hash(chain_id, contract_address, nonce, auth_hash) != 0) {
        return io_send_sw(SWO_EXEC_ERROR);
    }

    G_context.req_type = CONFIRM_7702_AUTH;
    G_context.state = STATE_NONE;
    G_context.auth_7702_info.chain_id = chain_id;
    memmove(G_context.auth_7702_info.contract_address, contract_address, 20);
    G_context.auth_7702_info.nonce = nonce;
    memmove(G_context.auth_7702_info.hash, auth_hash, 32);

    format_uint64(chain_id, g_chain_id_str);
    format_hex(contract_address, 20, g_address_str);
    format_uint64(nonce, g_nonce_str);

    PRINTF("7702_AUTH: chain=%s addr=%s nonce=%s\n", g_chain_id_str, g_address_str, g_nonce_str);

    if (display) {
        return ui_display_7702_auth();
    }

    return sign_7702_auth_and_respond();
}

/* ─────────────── Signing (called after UI approval) ───────────── */

int sign_7702_auth_and_respond(void) {
    cx_ecfp_private_key_t private_key = {0};
    // SDK requires 64-byte buffer (privkey 32 + chaincode 32)
    uint8_t raw_privkey[64] = {0};
    cx_err_t error = CX_OK;

    uint8_t raw_signature[72];
    size_t sig_len = sizeof(raw_signature);
    uint32_t info = 0;

    error = os_derive_bip32_no_throw(CX_CURVE_256K1,
                                     G_context.bip32_path,
                                     G_context.bip32_path_len,
                                     raw_privkey,
                                     NULL);
    if (error != CX_OK) {
        explicit_bzero(raw_privkey, sizeof(raw_privkey));
        return io_send_sw(SWO_EXEC_ERROR);
    }

    // Init from first 32 bytes (the actual private key)
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
                                   G_context.auth_7702_info.hash,
                                   32,
                                   raw_signature,
                                   &sig_len,
                                   &info);

    explicit_bzero(&private_key, sizeof(private_key));
    if (error != CX_OK) {
        return io_send_sw(SWO_EXEC_ERROR);
    }

    // Parse DER → (v, r, s) into G_io_apdu_buffer
    memset(G_io_apdu_buffer, 0, 65);
    G_io_apdu_buffer[0] = (info & CX_ECCINFO_PARITY_ODD) ? 1 : 0;

    size_t offset = 2;
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

    // Mark state as approved — allows SIGN_TX_HASH (INS 0x09) to proceed once
    G_context.state = STATE_APPROVED;

    return io_send_response_pointer(G_io_apdu_buffer, 65, SWO_SUCCESS);
}
