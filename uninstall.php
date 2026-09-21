<?php
/**
 * Removes plugin data on uninstall.
 *
 * @package Community_Login_IdP
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'community_login_idp' );
delete_option( 'community_login_idp_blocklist' );
delete_metadata( 'user', 0, 'community_login_idp_slack_id', '', true );
delete_metadata( 'user', 0, 'community_login_idp_discord_id', '', true );
delete_metadata( 'user', 0, 'community_login_idp_avatar', '', true );
