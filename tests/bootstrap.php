<?php
/**
 * Test bootstrap.
 *
 * Normalize_identity() is pure, so the plugin is loaded without WordPress —
 * only the handful of functions it calls at file scope are stubbed out.
 *
 * @package Community_Login_IdP
 */

define( 'ABSPATH', __DIR__ . '/' );

/**
 * The plugin hooks itself up at file scope; nothing here dispatches hooks.
 */
function add_action() {}

/**
 * The plugin hooks itself up at file scope; nothing here dispatches hooks.
 */
function add_filter() {}

/**
 * Stub of the WordPress function of the same name.
 *
 * @param string $file Absolute path to a plugin file.
 * @return string
 */
function plugin_basename( $file ) {
	return basename( dirname( $file ) ) . '/' . basename( $file );
}

require_once dirname( __DIR__ ) . '/community-login-idp.php';
