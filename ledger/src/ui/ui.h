#pragma once

/**
 * Show the main menu (idle screen).
 */
void ui_menu_main(void);

/**
 * Show settings menu.
 */
void ui_menu_settings(void);

/**
 * Display address confirmation screen.
 *
 * @return 0 on success.
 */
int ui_display_address(void);

/**
 * Display transaction review screen.
 *
 * @return 0 on success.
 */
int ui_display_transaction(void);

/**
 * Display token transaction review screen.
 *
 * @return 0 on success.
 */
int ui_display_token_transaction(void);

/**
 * Display EIP-7702 delegation authorization review screen.
 *
 * Shows chain_id, delegate-to contract address, and nonce.
 * Reads display strings via getters in sign_7702_auth.c:
 *   - get_7702_chain_id_str()
 *   - get_7702_address_str()
 *   - get_7702_nonce_str()
 *
 * On approval: calls sign_7702_auth_and_respond().
 * On rejection: sends SWO_DENIED_BY_USER.
 *
 * @return 0 on success.
 */
int ui_display_7702_auth(void);
