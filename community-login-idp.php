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
 *
 * @package Community_Login_IdP
 */

namespace Community_Login_IdP;

defined( 'ABSPATH' ) || exit;

const OPTION      = 'community_login_idp';
const META_PREFIX = 'community_login_idp_';
const ACTION      = 'community-login-idp';

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
 * Sends the visitor off to the provider.
 *
 * @param string $slug     Provider slug.
 * @param array  $provider Provider config.
 */
function start_authorization( $slug, $provider ) {
	$settings = settings();
	$state    = wp_generate_password( 32, false );

	set_transient(
		'clidp_state_' . $state,
		array(
			'provider'    => $slug,
			'redirect_to' => isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '',
			'link_user'   => get_current_user_id(),
		),
		10 * MINUTE_IN_SECONDS
	);

	$args = array(
		'client_id'     => $settings[ $slug ]['client_id'],
		'scope'         => $provider['scope'],
		'response_type' => 'code',
		'redirect_uri'  => redirect_uri( $slug ),
		'state'         => $state,
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
		fail( 'denied' );
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
			),
		)
	);

	$token = json_decode( wp_remote_retrieve_body( $token ), true );

	if ( empty( $token['access_token'] ) ) {
		fail( 'token' );
	}

	$profile = wp_remote_get(
		$provider['userinfo'],
		array(
			'timeout' => 15,
			'headers' => array( 'Authorization' => 'Bearer ' . $token['access_token'] ),
		)
	);

	$identity = normalize_identity( $slug, json_decode( wp_remote_retrieve_body( $profile ), true ) );

	if ( ! $identity ) {
		fail( 'profile' );
	}

	// Slack workspace restriction: the picker hint above is advisory, this is the check.
	if ( 'slack' === $slug && ! empty( $settings['slack']['team_id'] ) && $identity['team'] !== $settings['slack']['team_id'] ) {
		fail( 'wrong_team' );
	}

	$user_id = resolve_user( $slug, $identity, (int) $flow['link_user'] );

	if ( is_wp_error( $user_id ) ) {
		fail( $user_id->get_error_code() );
	}

	update_user_meta( $user_id, META_PREFIX . $slug . '_id', $identity['sub'] );

	wp_set_auth_cookie( $user_id, true );
	do_action( 'wp_login', get_userdata( $user_id )->user_login, get_userdata( $user_id ) );

	$redirect_to = $flow['redirect_to'] ? $flow['redirect_to'] : admin_url();
	wp_safe_redirect( apply_filters( 'login_redirect', $redirect_to, $redirect_to, get_userdata( $user_id ) ) );
	exit;
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

	return wp_insert_user(
		array(
			'user_login'   => $login,
			'user_email'   => $identity['email'],
			'user_pass'    => wp_generate_password( 32 ),
			'display_name' => $identity['name'] ? $identity['name'] : $login,
			'role'         => get_option( 'default_role' ),
		)
	);
}

/**
 * Bails back to the login form with an error code.
 *
 * @param string $code Error code.
 */
function fail( $code ) {
	wp_safe_redirect( add_query_arg( 'clidp_error', rawurlencode( $code ), wp_login_url() ) );
	exit;
}

add_filter( 'login_message', __NAMESPACE__ . '\login_error_message' );

/**
 * Renders the error from fail() above the login form.
 *
 * @param string $message Existing message.
 * @return string
 */
function login_error_message( $message ) {
	if ( empty( $_GET['clidp_error'] ) ) {
		return $message;
	}

	$messages = array(
		'denied'          => __( 'Authorization was cancelled.', 'community-login-idp' ),
		'bad_state'       => __( 'That login attempt expired. Please try again.', 'community-login-idp' ),
		'wrong_team'      => __( 'That account is not a member of this community.', 'community-login-idp' ),
		'email_taken'     => __( 'An account already exists with that email address. Log in with your password, then link the account from your profile.', 'community-login-idp' ),
		'already_linked'  => __( 'That account is already linked to a different user.', 'community-login-idp' ),
		'no_registration' => __( 'New registrations are closed.', 'community-login-idp' ),
		'no_email'        => __( 'We could not get a verified email address from that account.', 'community-login-idp' ),
	);

	$code = sanitize_key( wp_unslash( $_GET['clidp_error'] ) );
	$text = isset( $messages[ $code ] ) ? $messages[ $code ] : __( 'Sign-in failed. Please try again.', 'community-login-idp' );

	return $message . '<div id="login_error">' . esc_html( $text ) . '</div>';
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

add_action( 'login_form', __NAMESPACE__ . '\render_buttons' );
add_action( 'register_form', __NAMESPACE__ . '\render_buttons' );

/**
 * Renders a sign-in button for each active provider.
 */
function render_buttons() {
	$providers = active_providers();

	if ( ! $providers ) {
		return;
	}

	$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';

	echo '<p class="clidp-buttons">';

	foreach ( $providers as $slug => $provider ) {
		$url = add_query_arg(
			array(
				'action'      => ACTION,
				'provider'    => $slug,
				'redirect_to' => $redirect_to ? $redirect_to : false,
			),
			wp_login_url()
		);

		printf(
			'<a href="%1$s" class="button button-large clidp-button clidp-button--%2$s">%3$s</a>',
			esc_url( $url ),
			esc_attr( $slug ),
			/* translators: %s: provider name, e.g. Slack. */
			esc_html( sprintf( __( 'Continue with %s', 'community-login-idp' ), $provider['label'] ) )
		);
	}

	echo '</p>';
}

add_action( 'show_user_profile', __NAMESPACE__ . '\render_profile_section' );

/**
 * Lets a logged-in user link or unlink their own accounts.
 *
 * @param \WP_User $user Current user.
 */
function render_profile_section( $user ) {
	$providers = active_providers();

	if ( ! $providers ) {
		return;
	}

	echo '<h2>' . esc_html__( 'Linked Accounts', 'community-login-idp' ) . '</h2><table class="form-table"><tbody>';

	foreach ( $providers as $slug => $provider ) {
		$linked = get_user_meta( $user->ID, META_PREFIX . $slug . '_id', true );

		echo '<tr><th>' . esc_html( $provider['label'] ) . '</th><td>';

		if ( $linked ) {
			printf(
				'%s &mdash; <a href="%s">%s</a>',
				esc_html( $linked ),
				esc_url( wp_nonce_url( add_query_arg( 'clidp_unlink', $slug, admin_url( 'profile.php' ) ), 'clidp_unlink_' . $slug ) ),
				esc_html__( 'Unlink', 'community-login-idp' )
			);
		} else {
			printf(
				'<a class="button" href="%s">%s</a>',
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
		}

		echo '</td></tr>';
	}

	echo '</tbody></table>';
}

add_action( 'load-profile.php', __NAMESPACE__ . '\maybe_unlink' );

/**
 * Handles the unlink link from the profile screen.
 */
function maybe_unlink() {
	if ( empty( $_GET['clidp_unlink'] ) ) {
		return;
	}

	$slug = sanitize_key( wp_unslash( $_GET['clidp_unlink'] ) );

	check_admin_referer( 'clidp_unlink_' . $slug );

	delete_user_meta( get_current_user_id(), META_PREFIX . $slug . '_id' );

	wp_safe_redirect( admin_url( 'profile.php' ) );
	exit;
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
	</div>
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
