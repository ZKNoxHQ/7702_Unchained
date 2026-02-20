/*****************************************************************************
 *   ZKNOX — EIP-7702 Authorization UI Display
 *
 *   Shows chain_id, contract address, and nonce on device screen.
 *   Supports NBGL (Stax/Flex) and BAGL (Nano S+/X).
 *****************************************************************************/

#include <string.h>

#include "os.h"
#include "ux.h"
#include "io.h"

#include "globals.h"
#include "sw.h"
#include "sign_7702_auth.h"
#include "ui.h"

// User-denied status — add to sw.h if not present:
//   #define SWO_DENIED_BY_USER 0x6985
#ifndef SWO_DENIED_BY_USER
#define SWO_DENIED_BY_USER 0x6985
#endif

extern const char *get_7702_chain_id_str(void);
extern const char *get_7702_address_str(void);
extern const char *get_7702_nonce_str(void);

/* ═══════════════════════════════════════════════════════════════════
 *  NBGL — Stax / Flex
 * ═══════════════════════════════════════════════════════════════════ */
#ifdef HAVE_NBGL

#include "nbgl_use_case.h"

static nbgl_layoutTagValue_t pairs[3];
static nbgl_layoutTagValueList_t pairList;

static void review_choice_cb(bool confirmed) {
    if (confirmed) {
        G_context.state = STATE_APPROVED;
        sign_7702_auth_and_respond();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        io_send_sw(SWO_DENIED_BY_USER);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

int ui_display_7702_auth(void) {
    pairs[0].item = "Chain ID";
    pairs[0].value = get_7702_chain_id_str();
    pairs[1].item = "Delegate to";
    pairs[1].value = get_7702_address_str();
    pairs[2].item = "Nonce";
    pairs[2].value = get_7702_nonce_str();

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 3;
    pairList.pairs = pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &C_app_boilerplate_64px,
                       "Review EIP-7702\ndelegation",
                       NULL,
                       "Sign delegation?",
                       review_choice_cb);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  BAGL — Nano S+ / Nano X
 * ═══════════════════════════════════════════════════════════════════ */
#else

static void ui_action_approve_7702(void) {
    G_context.state = STATE_APPROVED;
    sign_7702_auth_and_respond();
    ui_menu_main();
}

static void ui_action_reject_7702(void) {
    io_send_sw(SWO_DENIED_BY_USER);
    ui_menu_main();
}

// clang-format off
UX_STEP_NOCB(
    ux_7702_review_step,
    pnn,
    {
        &C_icon_eye,
        "Review",
        "EIP-7702 Auth",
    });

UX_STEP_NOCB(
    ux_7702_chain_id_step,
    bnnn_paging,
    {
        .title = "Chain ID",
        .text = get_7702_chain_id_str(),
    });

UX_STEP_NOCB(
    ux_7702_address_step,
    bnnn_paging,
    {
        .title = "Delegate to",
        .text = get_7702_address_str(),
    });

UX_STEP_NOCB(
    ux_7702_nonce_step,
    bnnn_paging,
    {
        .title = "Nonce",
        .text = get_7702_nonce_str(),
    });

UX_STEP_CB(
    ux_7702_approve_step,
    pb,
    ui_action_approve_7702(),
    {
        &C_icon_validate_14,
        "Approve",
    });

UX_STEP_CB(
    ux_7702_reject_step,
    pb,
    ui_action_reject_7702(),
    {
        &C_icon_crossmark,
        "Reject",
    });

UX_FLOW(ux_7702_auth_flow,
        &ux_7702_review_step,
        &ux_7702_chain_id_step,
        &ux_7702_address_step,
        &ux_7702_nonce_step,
        &ux_7702_approve_step,
        &ux_7702_reject_step);
// clang-format on

int ui_display_7702_auth(void) {
    ux_flow_init(0, ux_7702_auth_flow, NULL);
    return 0;
}

#endif
