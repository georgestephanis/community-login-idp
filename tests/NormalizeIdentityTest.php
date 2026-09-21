<?php
/**
 * Tests for normalize_identity().
 *
 * @package Community_Login_IdP
 */

use PHPUnit\Framework\TestCase;

use function Community_Login_IdP\normalize_identity;

/**
 * The one pure function in the plugin, and the one most likely to break when a
 * provider changes its response shape.
 */
class NormalizeIdentityTest extends TestCase {

	/**
	 * Slack returns an email only for confirmed workspace members.
	 */
	public function test_slack_with_email() {
		$identity = normalize_identity(
			'slack',
			array(
				'sub'                       => 'U012ABCDEF',
				'email'                     => 'someone@example.com',
				'name'                      => 'Some One',
				'https://slack.com/team_id' => 'T0123456789',
			)
		);

		$this->assertSame( 'U012ABCDEF', $identity['sub'] );
		$this->assertSame( 'someone@example.com', $identity['email'] );
		$this->assertTrue( $identity['verified'] );
		$this->assertSame( 'Some One', $identity['name'] );
		$this->assertSame( 'someone', $identity['nickname'] );
		$this->assertSame( 'T0123456789', $identity['team'] );
	}

	/**
	 * No email means nothing to verify against.
	 */
	public function test_slack_without_email() {
		$identity = normalize_identity( 'slack', array( 'sub' => 'U012ABCDEF' ) );

		$this->assertSame( '', $identity['email'] );
		$this->assertFalse( $identity['verified'] );
		$this->assertSame( '', $identity['nickname'] );
	}

	/**
	 * The team claim is absent unless the app requested the right scopes.
	 */
	public function test_slack_without_team_claim() {
		$identity = normalize_identity( 'slack', array( 'sub' => 'U012ABCDEF' ) );

		$this->assertSame( '', $identity['team'] );
	}

	/**
	 * Slack identifies users by `sub`; without one there is no identity.
	 */
	public function test_slack_without_sub() {
		$this->assertFalse( normalize_identity( 'slack', array( 'email' => 'someone@example.com' ) ) );
	}

	/**
	 * Discord flags its own email verification separately.
	 */
	public function test_discord_verified() {
		$identity = normalize_identity(
			'discord',
			array(
				'id'          => '80351110224678912',
				'email'       => 'someone@example.com',
				'verified'    => true,
				'username'    => 'someone',
				'global_name' => 'Some One',
			)
		);

		$this->assertSame( '80351110224678912', $identity['sub'] );
		$this->assertTrue( $identity['verified'] );
		$this->assertSame( 'Some One', $identity['name'] );
		$this->assertSame( 'someone', $identity['nickname'] );
		$this->assertSame( '', $identity['team'] );
	}

	/**
	 * An unverified Discord email must not be trusted for account linking.
	 */
	public function test_discord_unverified() {
		$identity = normalize_identity(
			'discord',
			array(
				'id'       => '80351110224678912',
				'email'    => 'someone@example.com',
				'verified' => false,
				'username' => 'someone',
			)
		);

		$this->assertFalse( $identity['verified'] );
	}

	/**
	 * `global_name` is the display name and is null for older accounts.
	 */
	public function test_discord_without_global_name() {
		$identity = normalize_identity(
			'discord',
			array(
				'id'       => '80351110224678912',
				'username' => 'someone',
			)
		);

		$this->assertSame( 'someone', $identity['name'] );
	}

	/**
	 * Discord identifies users by `id`.
	 */
	public function test_discord_without_id() {
		$this->assertFalse( normalize_identity( 'discord', array( 'username' => 'someone' ) ) );
	}

	/**
	 * A failed request or an error body must never look like an identity.
	 *
	 * @dataProvider garbage
	 *
	 * @param mixed $data Decoded response body.
	 */
	public function test_garbage_input( $data ) {
		$this->assertFalse( normalize_identity( 'slack', $data ) );
		$this->assertFalse( normalize_identity( 'discord', $data ) );
	}

	/**
	 * Response bodies that are not a profile.
	 *
	 * @return array<string, array{0: mixed}>
	 */
	public static function garbage() {
		return array(
			'null'         => array( null ),
			'string'       => array( 'not json' ),
			'empty array'  => array( array() ),
			'bool'         => array( false ),
			'error object' => array(
				array(
					'ok'    => false,
					'error' => 'invalid_auth',
				),
			),
		);
	}
}
