<?php
/**
 * Plugin Name:       Community Login IdP
 * Plugin URI:        https://github.com/georgestephanis/community-login-idp
 * Description:       Log in and register with Slack or Discord as the identity provider.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            George Stephanis
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       community-login-idp
 * Domain Path:       /languages
 *
 * @package Community_Login_IdP
 */

namespace Community_Login_IdP;

defined( 'ABSPATH' ) || exit;

const OPTION      = 'community_login_idp';
const META_PREFIX = 'community_login_idp_';
const ACTION      = 'community-login-idp';

/**
 * Moderation data, deliberately not inside the settings option: sanitize_settings()
 * rebuilds that array from the submitted form, so a blocklist living there would
 * be wiped every time someone pressed Save Changes.
 */
const BLOCKLIST = 'community_login_idp_blocklist';

/**
 * Supported providers. Both are plain OAuth2 authorization-code flows, so the
 * only per-provider differences are endpoints, scopes and response shape.
 *
 * @return array<string, array<string, string>>
 */
function providers() {
	return array(
		'slack'   => array(
			'label'     => 'Slack',
			'authorize' => 'https://slack.com/openid/connect/authorize',
			'token'     => 'https://slack.com/api/openid.connect.token',
			'userinfo'  => 'https://slack.com/api/openid.connect.userInfo',
			'scope'     => 'openid email profile',
		),
		'discord' => array(
			'label'     => 'Discord',
			'authorize' => 'https://discord.com/oauth2/authorize',
			'token'     => 'https://discord.com/api/oauth2/token',
			'userinfo'  => 'https://discord.com/api/users/@me',
			'scope'     => 'identify email',
		),
	);
}

/**
 * Plugin settings, with defaults filled in.
 *
 * @return array
 */
function settings() {
	$defaults = array(
		'register_new_users'     => 1,
		'link_by_verified_email' => 0,
		'disable_password_login' => 0,
		'remote_avatars'         => 0,
		'session_hours'          => 48,
		'require_login'          => 0,
		'require_login_feeds'    => 0,
		'require_login_rest'     => 0,
		'require_login_allow'    => '',
	);

	foreach ( array_keys( providers() ) as $slug ) {
		$defaults[ $slug ] = array(
			'enabled'       => 0,
			'client_id'     => '',
			'client_secret' => '',
			'team_id'       => '',
		);
	}

	$saved = get_option( OPTION, array() );

	return is_array( $saved ) ? array_replace_recursive( $defaults, $saved ) : $defaults;
}

/**
 * Providers that are enabled and have credentials.
 *
 * @return array<string, array<string, string>>
 */
function active_providers() {
	$settings = settings();

	return array_filter(
		providers(),
		static function ( $slug ) use ( $settings ) {
			return ! empty( $settings[ $slug ]['enabled'] )
				&& '' !== $settings[ $slug ]['client_id']
				&& '' !== $settings[ $slug ]['client_secret'];
		},
		ARRAY_FILTER_USE_KEY
	);
}

/**
 * The redirect URI registered with the provider's app.
 *
 * @param string $slug Provider slug.
 * @return string
 */
function redirect_uri( $slug ) {
	return add_query_arg(
		array(
			'action'   => ACTION,
			'provider' => $slug,
		),
		wp_login_url()
	);
}

// ----- Login / registration flow -----

add_action( 'login_form_' . ACTION, __NAMESPACE__ . '\handle_request' );

/**
 * Handles both legs of the OAuth dance on wp-login.php?action=community-login-idp.
 */
function handle_request() {
	$slug      = isset( $_GET['provider'] ) ? sanitize_key( wp_unslash( $_GET['provider'] ) ) : '';
	$providers = active_providers();

	if ( ! isset( $providers[ $slug ] ) ) {
		fail( 'unknown_provider' );
	}

	if ( isset( $_GET['code'] ) || isset( $_GET['error'] ) ) {
		handle_callback( $slug, $providers[ $slug ] );
	}

	start_authorization( $slug, $providers[ $slug ] );
}

/**
 * The scopes to request for a provider.
 *
 * `guilds` is a noticeably heavier consent prompt than `identify email`, so it
 * is only asked for when a server restriction is actually configured.
 *
 * @param string $slug     Provider slug.
 * @param array  $provider Provider config.
 * @return string
 */
function scope( $slug, $provider ) {
	$settings = settings();

	if ( 'discord' === $slug && ! empty( $settings['discord']['team_id'] ) ) {
		return $provider['scope'] . ' guilds';
	}

	return $provider['scope'];
}

/**
 * Derives the S256 PKCE code challenge from a verifier.
 *
 * Base64url without padding, per RFC 7636.
 *
 * @param string $verifier Code verifier.
 * @return string
 */
function pkce_challenge( $verifier ) {
	return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 7636 requires base64url here.
}

/**
 * Sends the visitor off to the provider.
 *
 * @param string $slug     Provider slug.
 * @param array  $provider Provider config.
 */
function start_authorization( $slug, $provider ) {
	$settings = settings();
	$state    = wp_generate_password( 32, false );
	// Alphanumeric, so it is already within PKCE's unreserved character set.
	$verifier = wp_generate_password( 64, false );

	set_transient(
		'clidp_state_' . $state,
		array(
			'provider'    => $slug,
			'redirect_to' => isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '',
			'link_user'   => get_current_user_id(),
			'verifier'    => $verifier,
		),
		10 * MINUTE_IN_SECONDS
	);

	$args = array(
		'client_id'             => $settings[ $slug ]['client_id'],
		'scope'                 => scope( $slug, $provider ),
		'response_type'         => 'code',
		'redirect_uri'          => redirect_uri( $slug ),
		'state'                 => $state,
		'code_challenge'        => pkce_challenge( $verifier ),
		'code_challenge_method' => 'S256',
	);

	// Slack lets us pin the workspace picker to a single team.
	if ( 'slack' === $slug && ! empty( $settings['slack']['team_id'] ) ) {
		$args['team'] = $settings['slack']['team_id'];
	}

	// The whole point is to leave the site: this URL is the provider's, not ours.
	wp_redirect( add_query_arg( $args, $provider['authorize'] ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
	exit;
}

/**
 * Handles the provider's redirect back to us.
 *
 * @param string $slug     Provider slug.
 * @param array  $provider Provider config.
 */
function handle_callback( $slug, $provider ) {
	if ( isset( $_GET['error'] ) ) {
		fail( 'denied', '', sanitize_text_field( wp_unslash( $_GET['error'] ) ) );
	}

	$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
	$flow  = $state ? get_transient( 'clidp_state_' . $state ) : false;

	if ( ! is_array( $flow ) || $flow['provider'] !== $slug ) {
		fail( 'bad_state' );
	}

	delete_transient( 'clidp_state_' . $state );

	$settings = settings();
	$token    = wp_remote_post(
		$provider['token'],
		array(
			'timeout' => 15,
			'body'    => array(
				'grant_type'    => 'authorization_code',
				'code'          => isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '',
				'redirect_uri'  => redirect_uri( $slug ),
				'client_id'     => $settings[ $slug ]['client_id'],
				'client_secret' => $settings[ $slug ]['client_secret'],
				'code_verifier' => isset( $flow['verifier'] ) ? $flow['verifier'] : '',
			),
		)
	);

	$token_body = is_wp_error( $token ) ? $token->get_error_message() : wp_remote_retrieve_body( $token );
	$token      = json_decode( $token_body, true );

	if ( empty( $token['access_token'] ) ) {
		fail( 'token', $flow['redirect_to'], $token_body );
	}

	$profile = wp_remote_get(
		$provider['userinfo'],
		array(
			'timeout' => 15,
			'headers' => array( 'Authorization' => 'Bearer ' . $token['access_token'] ),
		)
	);

	$profile_body = is_wp_error( $profile ) ? $profile->get_error_message() : wp_remote_retrieve_body( $profile );
	$identity     = normalize_identity( $slug, json_decode( $profile_body, true ) );

	if ( ! $identity ) {
		fail( 'profile', $flow['redirect_to'], $profile_body );
	}

	// Slack workspace restriction: the picker hint above is advisory, this is the check.
	if ( 'slack' === $slug && ! empty( $settings['slack']['team_id'] ) && $identity['team'] !== $settings['slack']['team_id'] ) {
		fail( 'wrong_team', $flow['redirect_to'], $identity['team'] );
	}

	// Discord has no equivalent claim, so membership costs an extra API call.
	if ( 'discord' === $slug && ! empty( $settings['discord']['team_id'] ) ) {
		$member = in_discord_guild( $token['access_token'], $settings['discord']['team_id'] );

		if ( is_wp_error( $member ) ) {
			fail( 'guild_check', $flow['redirect_to'], $member->get_error_message() );
		}

		if ( ! $member ) {
			fail( 'wrong_team', $flow['redirect_to'], $identity['sub'] );
		}
	}

	// Before resolve_user(), so a blocked account never reaches creation or linking.
	if ( is_blocked( $slug, $identity['sub'] ) ) {
		fail( 'blocked', $flow['redirect_to'], $identity['sub'] );
	}

	$user_id = resolve_user( $slug, $identity, (int) $flow['link_user'] );

	if ( is_wp_error( $user_id ) ) {
		fail( $user_id->get_error_code(), $flow['redirect_to'], $user_id->get_error_message() );
	}

	update_user_meta( $user_id, META_PREFIX . $slug . '_id', $identity['sub'] );

	// Stored whether or not the setting is on, so flipping it on takes effect
	// immediately rather than after everyone has logged in again. Nothing reads
	// it until then, and uninstall.php clears it.
	if ( $identity['avatar'] ) {
		update_user_meta( $user_id, META_PREFIX . 'avatar', esc_url_raw( $identity['avatar'] ) );
	} else {
		delete_user_meta( $user_id, META_PREFIX . 'avatar' );
	}

	// Scoped to this one cookie: we redirect and exit immediately below, so this
	// never touches a password login or anything else in another request.
	$hours = (int) $settings['session_hours'];

	add_filter(
		'auth_cookie_expiration',
		static function () use ( $hours ) {
			return $hours * HOUR_IN_SECONDS;
		},
		99
	);

	wp_set_auth_cookie( $user_id, true );
	do_action( 'wp_login', get_userdata( $user_id )->user_login, get_userdata( $user_id ) );

	$redirect_to = $flow['redirect_to'] ? $flow['redirect_to'] : admin_url();
	wp_safe_redirect( apply_filters( 'login_redirect', $redirect_to, $redirect_to, get_userdata( $user_id ) ) );
	exit;
}

/**
 * Whether a Discord user belongs to a given server.
 *
 * Fails closed: a request that cannot be completed returns an error rather
 * than a `false` that would read as "not a member", so the two are reported
 * differently on the login form.
 *
 * @param string $access_token The user's access token.
 * @param string $guild_id     Discord server (guild) ID.
 * @return bool|\WP_Error
 */
function in_discord_guild( $access_token, $guild_id ) {
	$response = wp_remote_get(
		// ponytail: one page. Discord returns up to 200 guilds and caps a normal
		// account at 100, so pagination only matters for Nitro users in 200+
		// servers. Add the `after` cursor loop if that ever shows up in support.
		'https://discord.com/api/users/@me/guilds',
		array(
			'timeout' => 15,
			'headers' => array( 'Authorization' => 'Bearer ' . $access_token ),
		)
	);

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$guilds = json_decode( wp_remote_retrieve_body( $response ), true );

	if ( ! is_array( $guilds ) ) {
		return new \WP_Error( 'guild_check', wp_remote_retrieve_body( $response ) );
	}

	return in_array( (string) $guild_id, array_column( $guilds, 'id' ), true );
}

/**
 * Builds a Discord CDN avatar URL from the hash on the profile response.
 *
 * An `a_` prefix means an animated avatar, which is only served as a .gif.
 *
 * Accounts with no custom avatar return an empty string rather than Discord's
 * default-avatar endpoint: falling through to whatever default the site has
 * configured is both more consistent and one less URL to construct.
 *
 * @param string      $user_id Discord user ID.
 * @param string|null $hash    Avatar hash, or null when the user has none.
 * @return string
 */
function discord_avatar_url( $user_id, $hash ) {
	if ( empty( $hash ) ) {
		return '';
	}

	return sprintf(
		'https://cdn.discordapp.com/avatars/%s/%s.%s',
		rawurlencode( $user_id ),
		rawurlencode( $hash ),
		0 === strpos( $hash, 'a_' ) ? 'gif' : 'png'
	);
}

/**
 * Flattens a provider's profile response into a common shape.
 *
 * @param string     $slug Provider slug.
 * @param array|null $data Decoded response body.
 * @return array|false
 */
function normalize_identity( $slug, $data ) {
	if ( ! is_array( $data ) ) {
		return false;
	}

	if ( 'slack' === $slug ) {
		if ( empty( $data['sub'] ) ) {
			return false;
		}

		return array(
			'sub'      => (string) $data['sub'],
			'email'    => isset( $data['email'] ) ? $data['email'] : '',
			// Slack only returns emails for confirmed workspace members.
			'verified' => ! empty( $data['email'] ),
			'name'     => isset( $data['name'] ) ? $data['name'] : '',
			'nickname' => isset( $data['email'] ) ? strstr( $data['email'], '@', true ) : '',
			'team'     => isset( $data['https://slack.com/team_id'] ) ? $data['https://slack.com/team_id'] : '',
			// Slack hands back a ready-made URL; Discord makes us build one.
			'avatar'   => isset( $data['picture'] ) ? $data['picture'] : '',
		);
	}

	if ( empty( $data['id'] ) ) {
		return false;
	}

	return array(
		'sub'      => (string) $data['id'],
		'email'    => isset( $data['email'] ) ? $data['email'] : '',
		'verified' => ! empty( $data['verified'] ) && ! empty( $data['email'] ),
		'name'     => isset( $data['global_name'] ) ? $data['global_name'] : ( isset( $data['username'] ) ? $data['username'] : '' ),
		'nickname' => isset( $data['username'] ) ? $data['username'] : '',
		'team'     => '',
		'avatar'   => discord_avatar_url( (string) $data['id'], isset( $data['avatar'] ) ? $data['avatar'] : null ),
	);
}

/**
 * Finds, links, or creates the WordPress user for a remote identity.
 *
 * @param string $slug      Provider slug.
 * @param array  $identity  Normalized identity.
 * @param int    $link_user User ID that started the flow while logged in, if any.
 * @return int|\WP_Error
 */
function resolve_user( $slug, $identity, $link_user = 0 ) {
	$settings = settings();

	$existing = get_users(
		array(
			// phpcs:ignore WordPress.DB.SlowDBQuery -- the only way to look up an identity.
			'meta_key'   => META_PREFIX . $slug . '_id',
			// phpcs:ignore WordPress.DB.SlowDBQuery -- ditto.
			'meta_value' => $identity['sub'],
			'number'     => 1,
			'fields'     => 'ID',
		)
	);

	if ( $existing ) {
		if ( $link_user && (int) $existing[0] !== $link_user ) {
			return new \WP_Error( 'already_linked' );
		}

		return (int) $existing[0];
	}

	// Someone logged in asked to link this account to themselves.
	if ( $link_user ) {
		return $link_user;
	}

	$by_email = $identity['verified'] ? get_user_by( 'email', $identity['email'] ) : false;

	if ( $by_email ) {
		return $settings['link_by_verified_email'] ? $by_email->ID : new \WP_Error( 'email_taken' );
	}

	if ( empty( $settings['register_new_users'] ) ) {
		return new \WP_Error( 'no_registration' );
	}

	if ( ! $identity['verified'] ) {
		return new \WP_Error( 'no_email' );
	}

	$base  = sanitize_user( $identity['nickname'] ? $identity['nickname'] : $slug . '-' . $identity['sub'], true );
	$login = $base;

	$suffix = 1;

	while ( username_exists( $login ) ) {
		++$suffix;
		$login = $base . $suffix;
	}

	$user_id = wp_insert_user(
		array(
			'user_login'   => $login,
			'user_email'   => $identity['email'],
			'user_pass'    => wp_generate_password( 32 ),
			'display_name' => $identity['name'] ? $identity['name'] : $login,
			'role'         => get_option( 'default_role' ),
		)
	);

	// On multisite wp_insert_user() creates a network user with no role on this
	// site, so they would log in to nothing. Add them to the current site.
	if ( ! is_wp_error( $user_id ) && is_multisite() && ! is_user_member_of_blog( $user_id ) ) {
		add_user_to_blog( get_current_blog_id(), $user_id, get_option( 'default_role' ) );
	}

	return $user_id;
}

/**
 * Bails back to the login form with an error code, keeping the visitor's
 * original destination so they can try again without losing their place.
 *
 * @param string $code        Error code.
 * @param string $redirect_to Where the visitor was originally headed.
 * @param mixed  $debug       Optional detail logged when WP_DEBUG is on.
 */
function fail( $code, $redirect_to = '', $debug = null ) {
	if ( null !== $debug && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- diagnostics, WP_DEBUG only.
		error_log(
			sprintf(
				'[community-login-idp] %s: %s',
				$code,
				is_scalar( $debug ) ? $debug : wp_json_encode( $debug )
			)
		);
	}

	$args = array( 'clidp_error' => $code );

	if ( $redirect_to ) {
		$args['redirect_to'] = $redirect_to;
	}

	wp_safe_redirect( add_query_arg( $args, wp_login_url() ) );
	exit;
}

add_filter( 'login_message', __NAMESPACE__ . '\login_message' );

/**
 * Prints our error (if any) and the provider buttons above the login form.
 *
 * @param string $message Existing message.
 * @return string
 */
function login_message( $message ) {
	$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';

	if ( in_array( $action, array( 'login', 'register' ), true ) ) {
		$message .= buttons_html();
	}

	if ( empty( $_GET['clidp_error'] ) ) {
		return $message;
	}

	$messages = array(
		'denied'             => __( 'Authorization was cancelled.', 'community-login-idp' ),
		'bad_state'          => __( 'That login attempt expired. Please try again.', 'community-login-idp' ),
		'wrong_team'         => __( 'That account is not a member of this community.', 'community-login-idp' ),
		// Deliberately vague. Telling someone exactly why they are blocked tells
		// them what to work around.
		'blocked'            => __( 'That account cannot be used to sign in to this site.', 'community-login-idp' ),
		'guild_check'        => __( 'We could not check your membership of this community. Please try again.', 'community-login-idp' ),
		'email_taken'        => __( 'An account already exists with that email address. Log in with your password, then link the account from your profile.', 'community-login-idp' ),
		'already_linked'     => __( 'That account is already linked to a different user.', 'community-login-idp' ),
		'no_registration'    => __( 'New registrations are closed.', 'community-login-idp' ),
		'no_email'           => __( 'We could not get a verified email address from that account.', 'community-login-idp' ),
		'unknown_provider'   => __( 'That sign-in method is not available.', 'community-login-idp' ),
		'token'              => __( 'We could not complete the sign-in with that service. If this keeps happening, check the client ID and secret in the plugin settings.', 'community-login-idp' ),
		'profile'            => __( 'That service did not tell us who you are. Please try again.', 'community-login-idp' ),
		'passwords_disabled' => __( 'Password sign-in is disabled on this site. Please use one of the options above.', 'community-login-idp' ),
	);

	$code = sanitize_key( wp_unslash( $_GET['clidp_error'] ) );
	$text = isset( $messages[ $code ] ) ? $messages[ $code ] : __( 'Sign-in failed. Please try again.', 'community-login-idp' );

	return $message . '<div id="login_error">' . esc_html( $text ) . '</div>';
}

// ----- Deprecating local password logins -----

/**
 * Whether interactive username/password sign-in is switched off.
 *
 * Deliberately returns false when no provider is usable, and can always be
 * overridden from wp-config.php with:
 *
 *     define( 'COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS', true );
 *
 * Without both of those escape hatches a misconfigured provider would lock
 * every administrator out of the site with no way back in.
 *
 * @return bool
 */
function passwords_disabled() {
	if ( defined( 'COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS' ) && COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS ) {
		return false;
	}

	$settings = settings();

	return ! empty( $settings['disable_password_login'] ) && (bool) active_providers();
}

/**
 * Whether this request is an API request rather than an interactive one.
 *
 * Uses core's own definition so application passwords keep working exactly
 * where core intends them to.
 *
 * @return bool
 */
function is_api_request() {
	$is_api_request = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
		|| ( defined( 'REST_REQUEST' ) && REST_REQUEST );

	/** This filter is documented in wp-includes/user.php */
	return (bool) apply_filters( 'application_password_is_api_request', $is_api_request );
}

// Priority 30: after core's username/email/application-password authenticators at 20.
add_filter( 'authenticate', __NAMESPACE__ . '\block_password_login', 30, 3 );

/**
 * Rejects interactive password sign-ins when local passwords are deprecated.
 *
 * Application passwords are untouched: core only honours those on API
 * requests, which is_api_request() lets straight through.
 *
 * @param null|\WP_User|\WP_Error $user     Result of the authenticate stack so far.
 * @param string                  $username Submitted username.
 * @param string                  $password Submitted password.
 * @return null|\WP_User|\WP_Error
 */
function block_password_login( $user, $username, $password ) {
	// Nothing was authenticated by password, so there is nothing to block.
	if ( ! $user instanceof \WP_User || '' === $password ) {
		return $user;
	}

	if ( is_api_request() || ! passwords_disabled() ) {
		return $user;
	}

	return new \WP_Error(
		'clidp_passwords_disabled',
		__( '<strong>Error:</strong> Password sign-in is disabled on this site. Use one of the sign-in buttons instead.', 'community-login-idp' )
	);
}

// Password resets produce a password that cannot be used to log in, so turn
// the whole flow off rather than leave a dead end.
add_filter( 'allow_password_reset', __NAMESPACE__ . '\maybe_block_password_reset' );

/**
 * Disables password resets when local passwords are deprecated.
 *
 * @param bool $allow Whether a reset is allowed.
 * @return bool
 */
function maybe_block_password_reset( $allow ) {
	return passwords_disabled() ? false : $allow;
}

add_filter( 'login_body_class', __NAMESPACE__ . '\login_body_class', 10, 2 );

/**
 * Flags the login page so the stylesheet can hide the password form.
 *
 * @param string[] $classes Body classes.
 * @param string   $action  Current login action.
 * @return string[]
 */
function login_body_class( $classes, $action ) {
	if ( 'login' === $action && passwords_disabled() ) {
		$classes[] = 'clidp-passwords-disabled';
	}

	return $classes;
}

// ----- Buttons -----

add_action( 'login_enqueue_scripts', __NAMESPACE__ . '\enqueue_styles' );

/**
 * Loads the compiled button styles on wp-login.php.
 */
function enqueue_styles() {
	$css = plugin_dir_path( __FILE__ ) . 'build/style-index.css';

	if ( ! active_providers() || ! file_exists( $css ) ) {
		return;
	}

	wp_enqueue_style(
		'community-login-idp',
		plugins_url( 'build/style-index.css', __FILE__ ),
		array(),
		(string) filemtime( $css )
	);
}

/**
 * Builds the sign-in button markup for each active provider.
 *
 * Rendered through `login_message` rather than `login_form`: core fires
 * `login_form` between the password field and the Remember Me checkbox, which
 * drops the buttons into the middle of the password form. `login_message`
 * lands above the form, inside the login box, where they belong.
 *
 * @return string
 */
function buttons_html() {
	$providers = active_providers();

	if ( ! $providers ) {
		return '';
	}

	$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
	$html        = '<div class="clidp-buttons">';

	foreach ( $providers as $slug => $provider ) {
		$url = add_query_arg(
			array(
				'action'      => ACTION,
				'provider'    => $slug,
				'redirect_to' => $redirect_to ? $redirect_to : false,
			),
			wp_login_url()
		);

		$html .= sprintf(
			'<a href="%1$s" class="button button-large clidp-button clidp-button--%2$s">%3$s</a>',
			esc_url( $url ),
			esc_attr( $slug ),
			/* translators: %s: provider name, e.g. Slack. */
			esc_html( sprintf( __( 'Continue with %s', 'community-login-idp' ), $provider['label'] ) )
		);
	}

	if ( ! passwords_disabled() ) {
		$html .= '<p class="clidp-divider"><span>' . esc_html__( 'or', 'community-login-idp' ) . '</span></p>';
	}

	return $html . '</div>';
}

add_action( 'show_user_profile', __NAMESPACE__ . '\render_profile_section' );
add_action( 'edit_user_profile', __NAMESPACE__ . '\render_profile_section' );

/**
 * Providers currently linked to a user, ignoring any that are switched off
 * since those cannot be used to log in.
 *
 * @param int $user_id User ID.
 * @return string[] Provider slugs.
 */
function linked_providers( $user_id ) {
	$linked = array();

	foreach ( array_keys( active_providers() ) as $slug ) {
		if ( get_user_meta( $user_id, META_PREFIX . $slug . '_id', true ) ) {
			$linked[] = $slug;
		}
	}

	return $linked;
}

/**
 * Lets a user link and unlink their own accounts, and lets an administrator
 * unlink someone else's.
 *
 * Linking never looks at email addresses, so a provider account with a
 * different email than the WordPress account links fine.
 *
 * @param \WP_User $user User being edited.
 */
function render_profile_section( $user ) {
	$providers = active_providers();

	if ( ! $providers || ! current_user_can( 'edit_user', $user->ID ) ) {
		return;
	}

	$is_own  = get_current_user_id() === $user->ID;
	$linked  = linked_providers( $user->ID );
	$is_last = 1 === count( $linked ) && passwords_disabled();
	$screen  = $is_own ? admin_url( 'profile.php' ) : add_query_arg( 'user_id', $user->ID, admin_url( 'user-edit.php' ) );

	echo '<h2>' . esc_html__( 'Linked Accounts', 'community-login-idp' ) . '</h2>';
	echo '<table class="form-table" role="presentation"><tbody>';

	foreach ( $providers as $slug => $provider ) {
		$remote_id = get_user_meta( $user->ID, META_PREFIX . $slug . '_id', true );

		echo '<tr><th scope="row">' . esc_html( $provider['label'] ) . '</th><td>';

		if ( $remote_id && $is_last && in_array( $slug, $linked, true ) ) {
			printf(
				'<code>%s</code><p class="description">%s</p>',
				esc_html( $remote_id ),
				esc_html__( 'This is the only linked account and password sign-in is disabled, so unlinking it would lock this user out. Link another provider first.', 'community-login-idp' )
			);
		} elseif ( $remote_id ) {
			printf(
				'<code>%1$s</code> &mdash; <a href="%2$s">%3$s</a>',
				esc_html( $remote_id ),
				esc_url(
					wp_nonce_url(
						add_query_arg( 'clidp_unlink', $slug, $screen ),
						'clidp_unlink_' . $slug . '_' . $user->ID
					)
				),
				esc_html__( 'Unlink', 'community-login-idp' )
			);
		} elseif ( $is_own ) {
			printf(
				'<a class="button" href="%1$s">%2$s</a>',
				esc_url(
					add_query_arg(
						array(
							'action'      => ACTION,
							'provider'    => $slug,
							'redirect_to' => admin_url( 'profile.php' ),
						),
						wp_login_url()
					)
				),
				esc_html__( 'Link account', 'community-login-idp' )
			);
		} else {
			// Linking authenticates the current user, so it can only ever be self-service.
			echo esc_html__( 'Not linked. Only this user can link their own account.', 'community-login-idp' );
		}

		echo '</td></tr>';
	}

	echo '</tbody></table>';
}

add_action( 'load-profile.php', __NAMESPACE__ . '\maybe_unlink' );
add_action( 'load-user-edit.php', __NAMESPACE__ . '\maybe_unlink' );

/**
 * Handles the unlink link from the profile screens.
 */
function maybe_unlink() {
	if ( empty( $_GET['clidp_unlink'] ) ) {
		return;
	}

	$slug    = sanitize_key( wp_unslash( $_GET['clidp_unlink'] ) );
	$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : get_current_user_id();

	check_admin_referer( 'clidp_unlink_' . $slug . '_' . $user_id );

	if ( ! current_user_can( 'edit_user', $user_id ) ) {
		wp_die( esc_html__( 'You are not allowed to change linked accounts for this user.', 'community-login-idp' ), 403 );
	}

	// Removing the last usable login method would lock the account out entirely.
	if ( passwords_disabled() && array( $slug ) === linked_providers( $user_id ) ) {
		wp_die(
			esc_html__( 'That is the only linked account and password sign-in is disabled, so unlinking it would lock this user out of the site. Link another provider first.', 'community-login-idp' ),
			403,
			array( 'back_link' => true )
		);
	}

	delete_user_meta( $user_id, META_PREFIX . $slug . '_id' );

	wp_safe_redirect(
		get_current_user_id() === $user_id
			? admin_url( 'profile.php' )
			: add_query_arg( 'user_id', $user_id, admin_url( 'user-edit.php' ) )
	);
	exit;
}

// ----- Requiring login to view the site -----

add_action( 'template_redirect', __NAMESPACE__ . '\require_login', 0 );

/**
 * Bounces logged-out visitors to the login form.
 *
 * The template_redirect hook is the right one precisely because of what it
 * does not run for: wp-login.php (so the login form and our own OAuth callback stay
 * reachable), wp-admin, admin-ajax.php, wp-cron.php, XML-RPC and the REST
 * API. Those need no exemptions here because they never reach this code.
 *
 * What does reach it, and so is exempted explicitly: robots.txt and the
 * favicon, which WordPress serves through this hook.
 */
function require_login() {
	$settings = settings();

	if ( empty( $settings['require_login'] ) || is_user_logged_in() ) {
		return;
	}

	// Serving a redirect for these breaks crawlers and browsers for no benefit;
	// neither reveals anything about the site's content.
	if ( is_robots() || is_favicon() ) {
		return;
	}

	if ( is_feed() && empty( $settings['require_login_feeds'] ) ) {
		return;
	}

	if ( path_is_allowed( wp_parse_url( request_path(), PHP_URL_PATH ), $settings['require_login_allow'] ) ) {
		return;
	}

	/**
	 * Lets a plugin exempt a request from the login requirement.
	 *
	 * An escape hatch in the same spirit as COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS:
	 * a site-wide redirect will eventually collide with something, and the fix
	 * should not have to be switching the feature off.
	 *
	 * @param bool $require Whether to require login for this request.
	 */
	if ( ! apply_filters( 'community_login_idp_require_login', true ) ) {
		return;
	}

	wp_safe_redirect( wp_login_url( home_url( request_path() ) ) );
	exit;
}

/**
 * The path and query of the current request.
 *
 * @return string
 */
function request_path() {
	return isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
}

/**
 * Whether a request path is on the allowlist.
 *
 * Entries are matched as prefixes, so `/shop` covers everything under it. A
 * blank line or a comment is ignored so the textarea can be annotated.
 *
 * @param string $path      Request path, no query string.
 * @param string $allowlist Newline-separated paths from the setting.
 * @return bool
 */
function path_is_allowed( $path, $allowlist ) {
	$path = '/' . ltrim( (string) $path, '/' );

	foreach ( preg_split( '/\R/', (string) $allowlist ) as $line ) {
		$line = trim( $line );

		if ( '' === $line || 0 === strpos( $line, '#' ) ) {
			continue;
		}

		$line = '/' . ltrim( $line, '/' );

		if ( 0 === strpos( $path, $line ) ) {
			return true;
		}
	}

	return false;
}

add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\require_login_for_rest', 99 );

/**
 * Closes the REST API to logged-out requests, when asked to.
 *
 * Separate setting because closing it is not free: oEmbed of your posts
 * elsewhere, and any theme or plugin that reads the API without a session,
 * stop working.
 *
 * @param \WP_Error|null|true $result Result of the authentication stack so far.
 * @return \WP_Error|null|true
 */
function require_login_for_rest( $result ) {
	$settings = settings();

	if ( ! empty( $result ) || is_user_logged_in() ) {
		return $result;
	}

	if ( empty( $settings['require_login'] ) || empty( $settings['require_login_rest'] ) ) {
		return $result;
	}

	return new \WP_Error(
		'rest_not_logged_in',
		__( 'You must be logged in to use the REST API on this site.', 'community-login-idp' ),
		array( 'status' => 401 )
	);
}

// ----- Blocklist -----

/**
 * Blocked remote accounts, keyed "<provider>:<remote id>".
 *
 * Display data is cached alongside the ID so the admin screen reads as people
 * rather than as a wall of snowflakes and U… strings.
 *
 * ponytail: a single option. Fine for a few hundred entries; if a site ever
 * needs more than that, this becomes a custom table and these four functions
 * are the only things that have to change.
 *
 * @return array<string, array>
 */
function blocklist() {
	$list = get_option( BLOCKLIST, array() );

	return is_array( $list ) ? $list : array();
}

/**
 * Whether a remote account is blocked from signing in.
 *
 * @param string $slug Provider slug.
 * @param string $sub  Remote account ID.
 * @return bool
 */
function is_blocked( $slug, $sub ) {
	return isset( blocklist()[ $slug . ':' . $sub ] );
}

/**
 * Blocks a remote account.
 *
 * @param string $slug     Provider slug.
 * @param string $sub      Remote account ID.
 * @param array  $identity Normalized identity, for the cached display data.
 * @param string $reason   Optional note for whoever reads this later.
 */
function block_account( $slug, $sub, $identity = array(), $reason = '' ) {
	$list = blocklist();

	$list[ $slug . ':' . $sub ] = array(
		'provider'   => $slug,
		'sub'        => (string) $sub,
		'name'       => isset( $identity['name'] ) ? $identity['name'] : '',
		'nickname'   => isset( $identity['nickname'] ) ? $identity['nickname'] : '',
		'email'      => isset( $identity['email'] ) ? $identity['email'] : '',
		'avatar'     => isset( $identity['avatar'] ) ? $identity['avatar'] : '',
		'reason'     => $reason,
		'blocked_by' => get_current_user_id(),
		'blocked_at' => time(),
	);

	update_option( BLOCKLIST, $list, false );
}

/**
 * Unblocks a remote account.
 *
 * @param string $slug Provider slug.
 * @param string $sub  Remote account ID.
 */
function unblock_account( $slug, $sub ) {
	$list = blocklist();

	unset( $list[ $slug . ':' . $sub ] );

	update_option( BLOCKLIST, $list, false );
}

add_filter( 'user_row_actions', __NAMESPACE__ . '\user_row_actions', 10, 2 );

/**
 * Adds a Block sign-in row action on Users, which is where a moderator is
 * actually standing when they decide someone has to go.
 *
 * @param array    $actions Row actions.
 * @param \WP_User $user    The user the row is for.
 * @return array
 */
function user_row_actions( $actions, $user ) {
	if ( ! current_user_can( 'edit_users' ) || get_current_user_id() === (int) $user->ID ) {
		return $actions;
	}

	foreach ( linked_providers( $user->ID ) as $slug ) {
		$sub = get_user_meta( $user->ID, META_PREFIX . $slug . '_id', true );

		if ( is_blocked( $slug, $sub ) ) {
			continue;
		}

		$url = wp_nonce_url(
			add_query_arg(
				array(
					'clidp_block' => $slug,
					'user_id'     => $user->ID,
				),
				admin_url( 'users.php' )
			),
			'clidp_block_' . $slug . '_' . $user->ID
		);

		$actions[ 'clidp_block_' . $slug ] = sprintf(
			'<a href="%s" style="color:#b32d2e">%s</a>',
			esc_url( $url ),
			esc_html(
				sprintf(
					/* translators: %s: provider name, e.g. Slack. */
					__( 'Block %s sign-in', 'community-login-idp' ),
					providers()[ $slug ]['label']
				)
			)
		);
	}

	return $actions;
}

add_action( 'load-users.php', __NAMESPACE__ . '\maybe_block_from_users_screen' );

/**
 * Handles the Block sign-in row action.
 */
function maybe_block_from_users_screen() {
	if ( empty( $_GET['clidp_block'] ) || empty( $_GET['user_id'] ) ) {
		return;
	}

	$slug    = sanitize_key( wp_unslash( $_GET['clidp_block'] ) );
	$user_id = (int) $_GET['user_id'];

	check_admin_referer( 'clidp_block_' . $slug . '_' . $user_id );

	if ( ! current_user_can( 'edit_user', $user_id ) || ! isset( providers()[ $slug ] ) ) {
		wp_die( esc_html__( 'You are not allowed to do that.', 'community-login-idp' ) );
	}

	$sub  = get_user_meta( $user_id, META_PREFIX . $slug . '_id', true );
	$user = get_userdata( $user_id );

	if ( $sub && $user ) {
		block_account(
			$slug,
			$sub,
			array(
				'name'     => $user->display_name,
				'nickname' => $user->user_login,
				'email'    => $user->user_email,
				'avatar'   => get_user_meta( $user_id, META_PREFIX . 'avatar', true ),
			)
		);
	}

	wp_safe_redirect( add_query_arg( 'clidp_blocked', 1, admin_url( 'users.php' ) ) );
	exit;
}

add_action( 'admin_notices', __NAMESPACE__ . '\blocked_notice' );

/**
 * Confirms a block, and says what it did and did not do.
 */
function blocked_notice() {
	if ( empty( $_GET['clidp_blocked'] ) ) {
		return;
	}

	printf(
		'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
		esc_html__( 'That account can no longer sign in. The WordPress user is untouched — delete it separately if you want it gone.', 'community-login-idp' )
	);
}

// ----- Avatars -----

add_filter( 'pre_get_avatar_data', __NAMESPACE__ . '\remote_avatar', 10, 2 );

/**
 * Serves the avatar from the provider's CDN instead of Gravatar.
 *
 * Off by default: hotlinking the CDN leaks every visitor's IP address to
 * Slack or Discord on any page that renders an avatar.
 *
 * @param array $args        Avatar data.
 * @param mixed $id_or_email User ID, email, WP_User, WP_Post or WP_Comment.
 * @return array
 */
function remote_avatar( $args, $id_or_email ) {
	$settings = settings();

	if ( empty( $settings['remote_avatars'] ) || ! empty( $args['force_default'] ) ) {
		return $args;
	}

	$user_id = avatar_user_id( $id_or_email );
	$url     = $user_id ? get_user_meta( $user_id, META_PREFIX . 'avatar', true ) : '';

	if ( ! $url ) {
		return $args;
	}

	$args['url']          = $url;
	$args['found_avatar'] = true;

	return $args;
}

/**
 * Resolves whatever get_avatar_data() was handed into a user ID.
 *
 * @param mixed $id_or_email User ID, email, WP_User, WP_Post or WP_Comment.
 * @return int 0 when it does not resolve to a user.
 */
function avatar_user_id( $id_or_email ) {
	if ( is_numeric( $id_or_email ) ) {
		return (int) $id_or_email;
	}

	if ( $id_or_email instanceof \WP_User ) {
		return (int) $id_or_email->ID;
	}

	if ( $id_or_email instanceof \WP_Post ) {
		return (int) $id_or_email->post_author;
	}

	if ( $id_or_email instanceof \WP_Comment ) {
		return (int) $id_or_email->user_id;
	}

	if ( is_string( $id_or_email ) && is_email( $id_or_email ) ) {
		$user = get_user_by( 'email', $id_or_email );

		return $user ? (int) $user->ID : 0;
	}

	return 0;
}

// ----- Settings screen -----

add_action( 'admin_init', __NAMESPACE__ . '\register_settings' );

/**
 * Registers the option so options.php will save it for us.
 */
function register_settings() {
	register_setting(
		OPTION,
		OPTION,
		array(
			'type'              => 'array',
			'sanitize_callback' => __NAMESPACE__ . '\sanitize_settings',
			'default'           => array(),
		)
	);
}

/**
 * Sanitizes the settings form.
 *
 * @param mixed $input Raw submission.
 * @return array
 */
function sanitize_settings( $input ) {
	$clean = array(
		'register_new_users'     => empty( $input['register_new_users'] ) ? 0 : 1,
		'link_by_verified_email' => empty( $input['link_by_verified_email'] ) ? 0 : 1,
		'disable_password_login' => empty( $input['disable_password_login'] ) ? 0 : 1,
		'remote_avatars'         => empty( $input['remote_avatars'] ) ? 0 : 1,
		// One hour to one year. Zero would mean a cookie that expires immediately.
		'session_hours'          => max( 1, min( 8760, isset( $input['session_hours'] ) ? (int) $input['session_hours'] : 48 ) ),
		'require_login'          => empty( $input['require_login'] ) ? 0 : 1,
		'require_login_feeds'    => empty( $input['require_login_feeds'] ) ? 0 : 1,
		'require_login_rest'     => empty( $input['require_login_rest'] ) ? 0 : 1,
		'require_login_allow'    => isset( $input['require_login_allow'] ) ? sanitize_textarea_field( $input['require_login_allow'] ) : '',
	);

	foreach ( array_keys( providers() ) as $slug ) {
		$clean[ $slug ] = array(
			'enabled'       => empty( $input[ $slug ]['enabled'] ) ? 0 : 1,
			'client_id'     => isset( $input[ $slug ]['client_id'] ) ? sanitize_text_field( $input[ $slug ]['client_id'] ) : '',
			'client_secret' => isset( $input[ $slug ]['client_secret'] ) ? sanitize_text_field( $input[ $slug ]['client_secret'] ) : '',
			'team_id'       => isset( $input[ $slug ]['team_id'] ) ? sanitize_text_field( $input[ $slug ]['team_id'] ) : '',
		);
	}

	return $clean;
}

add_action( 'load-settings_page_community-login-idp', __NAMESPACE__ . '\maybe_unblock' );

/**
 * Handles the Unblock button on the settings screen.
 */
function maybe_unblock() {
	if ( empty( $_GET['clidp_unblock'] ) ) {
		return;
	}

	$key = sanitize_text_field( wp_unslash( $_GET['clidp_unblock'] ) );

	check_admin_referer( 'clidp_unblock_' . $key );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to do that.', 'community-login-idp' ) );
	}

	$list  = blocklist();
	$entry = isset( $list[ $key ] ) ? $list[ $key ] : false;

	if ( $entry ) {
		unblock_account( $entry['provider'], $entry['sub'] );
	}

	wp_safe_redirect( admin_url( 'options-general.php?page=community-login-idp' ) );
	exit;
}

add_action( 'admin_menu', __NAMESPACE__ . '\add_settings_page' );

/**
 * Adds the Settings > Community Login screen.
 */
function add_settings_page() {
	add_options_page(
		__( 'Community Login IdP', 'community-login-idp' ),
		__( 'Community Login', 'community-login-idp' ),
		'manage_options',
		'community-login-idp',
		__NAMESPACE__ . '\render_settings_page'
	);
}

/**
 * Renders the settings screen.
 */
function render_settings_page() {
	$settings = settings();
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Community Login IdP', 'community-login-idp' ); ?></h1>
		<form method="post" action="options.php">
			<?php settings_fields( OPTION ); ?>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Registration', 'community-login-idp' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[register_new_users]" value="1" <?php checked( $settings['register_new_users'] ); ?>> <?php esc_html_e( 'Create a new WordPress account when an unknown person signs in', 'community-login-idp' ); ?></label><br>
						<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[link_by_verified_email]" value="1" <?php checked( $settings['link_by_verified_email'] ); ?>> <?php esc_html_e( 'Automatically link to an existing account with the same verified email address', 'community-login-idp' ); ?></label>
						<p class="description"><?php esc_html_e( 'Only enable automatic linking if you trust the provider to verify email addresses — it lets anyone controlling that email sign in as the matching WordPress user.', 'community-login-idp' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Site visibility', 'community-login-idp' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[require_login]" value="1" <?php checked( $settings['require_login'] ); ?>> <?php esc_html_e( 'Require people to be logged in to view the site', 'community-login-idp' ); ?></label>
						<p class="description"><?php esc_html_e( 'Logged-out visitors are sent to the login form. The login form itself, the provider callback, cron and the admin-ajax endpoint stay reachable, as do robots.txt and the favicon.', 'community-login-idp' ); ?></p>

						<p style="margin-top:1em">
							<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[require_login_feeds]" value="1" <?php checked( $settings['require_login_feeds'] ); ?>> <?php esc_html_e( 'Also require login for RSS and Atom feeds', 'community-login-idp' ); ?></label><br>
							<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[require_login_rest]" value="1" <?php checked( $settings['require_login_rest'] ); ?>> <?php esc_html_e( 'Also require login for the REST API', 'community-login-idp' ); ?></label>
						</p>
						<p class="description"><?php esc_html_e( 'Both are off by default because closing them breaks things quietly: feeds stop updating in readers, and a closed REST API stops oEmbed previews of your posts elsewhere along with any theme or plugin that reads the API without a session. Application passwords keep working either way.', 'community-login-idp' ); ?></p>

						<p style="margin-top:1em">
							<label for="require-login-allow"><?php esc_html_e( 'Always allow these paths:', 'community-login-idp' ); ?></label><br>
							<textarea id="require-login-allow" class="large-text code" rows="4" name="<?php echo esc_attr( OPTION ); ?>[require_login_allow]" placeholder="/about&#10;/contact"><?php echo esc_textarea( $settings['require_login_allow'] ); ?></textarea>
						</p>
						<p class="description"><?php esc_html_e( 'One per line, matched as a prefix — /shop covers everything under it. Blank lines and lines starting with # are ignored.', 'community-login-idp' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="session-hours"><?php esc_html_e( 'Session length', 'community-login-idp' ); ?></label></th>
					<td>
						<input id="session-hours" class="small-text" type="number" min="1" max="8760" step="1" name="<?php echo esc_attr( OPTION ); ?>[session_hours]" value="<?php echo esc_attr( $settings['session_hours'] ); ?>">
						<?php esc_html_e( 'hours', 'community-login-idp' ); ?>
						<p class="description"><?php esc_html_e( 'How long someone stays signed in after using a provider button. Membership of the workspace or server is only rechecked when they sign in again, so this is also how long someone keeps access after leaving your community. The default, 48 hours, matches WordPress’ own.', 'community-login-idp' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Avatars', 'community-login-idp' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[remote_avatars]" value="1" <?php checked( $settings['remote_avatars'] ); ?>> <?php esc_html_e( 'Use the profile picture from the provider', 'community-login-idp' ); ?></label>
						<p class="description"><?php esc_html_e( 'Images are hotlinked from Slack’s or Discord’s CDN, which tells them the IP address of every visitor who loads a page with an avatar on it — the same objection people raise about Gravatar. That is why this is off by default. Users with no linked provider, or no picture set there, keep the site’s normal avatar.', 'community-login-idp' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Password sign-in', 'community-login-idp' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[disable_password_login]" value="1" <?php checked( $settings['disable_password_login'] ); ?>> <?php esc_html_e( 'Disable username and password sign-in', 'community-login-idp' ); ?></label>
						<p class="description">
							<?php esc_html_e( 'Interactive logins must then go through a provider above. Application passwords keep working for the REST API and XML-RPC, so integrations are unaffected. Password resets are switched off too, since the resulting password could not be used.', 'community-login-idp' ); ?>
						</p>
						<p class="description">
							<strong><?php esc_html_e( 'Before you enable this, link your own account to a provider.', 'community-login-idp' ); ?></strong>
							<?php
							printf(
								/* translators: %s: PHP constant definition to add to wp-config.php. */
								esc_html__( 'If a provider ever breaks, restore password sign-in by adding %s to wp-config.php.', 'community-login-idp' ),
								'<code>define( \'COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS\', true );</code>'
							);
							?>
						</p>
					</td>
				</tr>
			</table>

			<?php foreach ( providers() as $slug => $provider ) : ?>
				<h2><?php echo esc_html( $provider['label'] ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enabled', 'community-login-idp' ); ?></th>
						<td><label><input type="checkbox" name="<?php echo esc_attr( OPTION . "[$slug][enabled]" ); ?>" value="1" <?php checked( $settings[ $slug ]['enabled'] ); ?>> <?php esc_html_e( 'Show a sign-in button for this provider', 'community-login-idp' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><label for="<?php echo esc_attr( "$slug-client-id" ); ?>"><?php esc_html_e( 'Client ID', 'community-login-idp' ); ?></label></th>
						<td><input class="regular-text" id="<?php echo esc_attr( "$slug-client-id" ); ?>" type="text" name="<?php echo esc_attr( OPTION . "[$slug][client_id]" ); ?>" value="<?php echo esc_attr( $settings[ $slug ]['client_id'] ); ?>" autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="<?php echo esc_attr( "$slug-client-secret" ); ?>"><?php esc_html_e( 'Client Secret', 'community-login-idp' ); ?></label></th>
						<td><input class="regular-text" id="<?php echo esc_attr( "$slug-client-secret" ); ?>" type="password" name="<?php echo esc_attr( OPTION . "[$slug][client_secret]" ); ?>" value="<?php echo esc_attr( $settings[ $slug ]['client_secret'] ); ?>" autocomplete="new-password"></td>
					</tr>
					<?php if ( 'slack' === $slug ) : ?>
						<tr>
							<th scope="row"><label for="slack-team-id"><?php esc_html_e( 'Workspace ID', 'community-login-idp' ); ?></label></th>
							<td>
								<input class="regular-text" id="slack-team-id" type="text" name="<?php echo esc_attr( OPTION . "[$slug][team_id]" ); ?>" value="<?php echo esc_attr( $settings[ $slug ]['team_id'] ); ?>" placeholder="T0123456789">
								<p class="description"><?php esc_html_e( 'Optional. If set, only members of this Slack workspace may sign in.', 'community-login-idp' ); ?></p>
							</td>
						</tr>
					<?php endif; ?>
					<?php if ( 'discord' === $slug ) : ?>
						<tr>
							<th scope="row"><label for="discord-team-id"><?php esc_html_e( 'Server ID', 'community-login-idp' ); ?></label></th>
							<td>
								<input class="regular-text" id="discord-team-id" type="text" name="<?php echo esc_attr( OPTION . "[$slug][team_id]" ); ?>" value="<?php echo esc_attr( $settings[ $slug ]['team_id'] ); ?>" placeholder="123456789012345678">
								<p class="description">
									<?php esc_html_e( 'Optional but strongly recommended. If set, only members of this Discord server may sign in. Leave it empty and any Discord account in the world can register.', 'community-login-idp' ); ?>
									<br>
									<?php esc_html_e( 'Turn on Developer Mode in Discord, then right-click the server and choose Copy Server ID. Setting this adds the “guilds” permission to the consent screen people see.', 'community-login-idp' ); ?>
								</p>
							</td>
						</tr>
					<?php endif; ?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Redirect URL', 'community-login-idp' ); ?></th>
						<td><code><?php echo esc_html( redirect_uri( $slug ) ); ?></code>
							<p class="description"><?php esc_html_e( 'Add this exact URL to the provider app’s allowed redirect URLs.', 'community-login-idp' ); ?></p>
						</td>
					</tr>
				</table>
			<?php endforeach; ?>

			<?php submit_button(); ?>
		</form>

		<?php render_blocklist(); ?>
	</div>
	<?php
}

/**
 * Lists blocked accounts, with a way back out.
 */
function render_blocklist() {
	$list = blocklist();

	if ( ! $list ) {
		return;
	}

	$providers = providers();
	?>
	<h2><?php esc_html_e( 'Blocked accounts', 'community-login-idp' ); ?></h2>
	<p class="description"><?php esc_html_e( 'These remote accounts cannot sign in, whatever else would otherwise let them. Block someone with the row action on the Users screen.', 'community-login-idp' ); ?></p>
	<table class="widefat striped">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Account', 'community-login-idp' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Provider', 'community-login-idp' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Blocked', 'community-login-idp' ); ?></th>
				<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'community-login-idp' ); ?></span></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $list as $key => $entry ) : ?>
				<?php
				$blocker = get_userdata( $entry['blocked_by'] );
				$url     = wp_nonce_url(
					add_query_arg(
						array(
							'page'          => 'community-login-idp',
							'clidp_unblock' => rawurlencode( $key ),
						),
						admin_url( 'options-general.php' )
					),
					'clidp_unblock_' . $key
				);
				?>
				<tr>
					<td>
						<strong><?php echo esc_html( $entry['name'] ? $entry['name'] : $entry['sub'] ); ?></strong>
						<?php if ( $entry['nickname'] ) : ?>
							<br><?php echo esc_html( $entry['nickname'] ); ?>
						<?php endif; ?>
						<?php if ( $entry['email'] ) : ?>
							<br><?php echo esc_html( $entry['email'] ); ?>
						<?php endif; ?>
						<br><code><?php echo esc_html( $entry['sub'] ); ?></code>
					</td>
					<td><?php echo esc_html( isset( $providers[ $entry['provider'] ] ) ? $providers[ $entry['provider'] ]['label'] : $entry['provider'] ); ?></td>
					<td>
						<?php
						echo esc_html(
							$blocker
								? sprintf(
									/* translators: 1: date, 2: display name of the user who blocked the account. */
									__( '%1$s by %2$s', 'community-login-idp' ),
									date_i18n( get_option( 'date_format' ), $entry['blocked_at'] ),
									$blocker->display_name
								)
								: date_i18n( get_option( 'date_format' ), $entry['blocked_at'] )
						);
						?>
						<?php if ( $entry['reason'] ) : ?>
							<br><em><?php echo esc_html( $entry['reason'] ); ?></em>
						<?php endif; ?>
					</td>
					<td><a class="button" href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Unblock', 'community-login-idp' ); ?></a></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<?php
}

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), __NAMESPACE__ . '\action_links' );

/**
 * Adds a Settings link on the plugins screen.
 *
 * @param array $links Existing links.
 * @return array
 */
function action_links( $links ) {
	array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=community-login-idp' ) ) . '">' . esc_html__( 'Settings', 'community-login-idp' ) . '</a>' );

	return $links;
}
