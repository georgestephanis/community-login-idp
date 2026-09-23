<?php
/**
 * Tests for the role map parser and matcher.
 *
 * @package Community_Login_IdP
 */

use PHPUnit\Framework\TestCase;

use function Community_Login_IdP\map_role;
use function Community_Login_IdP\parse_role_map;
use function Community_Login_IdP\slack_role_tags;

/**
 * The map decides what role a new account gets, so its ordering matters.
 */
class RoleMapTest extends TestCase {

	/**
	 * Blank lines, comments and junk are skipped; whitespace is trimmed.
	 */
	public function test_parsing() {
		$this->assertSame(
			array(
				'admin'  => 'editor',
				'member' => 'contributor',
			),
			parse_role_map( "# a comment\n admin = editor \n\nnot a rule\nmember=contributor\n" )
		);
	}

	/**
	 * A duplicate left-hand side keeps the first rule, matching "first wins".
	 */
	public function test_duplicate_keeps_first() {
		$this->assertSame( array( 'admin' => 'editor' ), parse_role_map( "admin = editor\nadmin = author" ) );
	}

	/**
	 * The first matching line wins, not the first matching provider role.
	 */
	public function test_first_line_wins() {
		$map = "owner = administrator\nadmin = editor\nmember = subscriber";

		$this->assertSame( 'editor', map_role( $map, array( 'admin', 'member' ) ) );
		$this->assertSame( 'administrator', map_role( $map, array( 'member', 'admin', 'owner' ) ) );
	}

	/**
	 * No match means no role, so the caller falls back to the site default.
	 */
	public function test_no_match() {
		$this->assertSame( '', map_role( 'admin = editor', array( 'member' ) ) );
		$this->assertSame( '', map_role( '', array( 'admin' ) ) );
	}

	/**
	 * Slack flags overlap on purpose, and `member` is always the catch-all.
	 */
	public function test_slack_tags() {
		$this->assertSame(
			array( 'owner', 'admin', 'member' ),
			slack_role_tags(
				array(
					'is_owner' => true,
					'is_admin' => true,
				)
			)
		);
		$this->assertSame(
			array( 'single_channel_guest', 'guest', 'member' ),
			slack_role_tags(
				array(
					'is_restricted'       => true,
					'is_ultra_restricted' => true,
				)
			)
		);
		$this->assertSame( array( 'member' ), slack_role_tags( array() ) );
	}
}
