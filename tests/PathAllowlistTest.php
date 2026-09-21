<?php
/**
 * Tests for path_is_allowed().
 *
 * @package Community_Login_IdP
 */

use PHPUnit\Framework\TestCase;

use function Community_Login_IdP\path_is_allowed;

/**
 * This decides what stays public on a site someone has made private, so both
 * directions of a mistake matter: a leak, or an unreachable page.
 */
class PathAllowlistTest extends TestCase {

	/**
	 * Entries match as a prefix, so one line covers a whole section.
	 */
	public function test_prefix_match() {
		$this->assertTrue( path_is_allowed( '/shop', '/shop' ) );
		$this->assertTrue( path_is_allowed( '/shop/socks', '/shop' ) );
		$this->assertFalse( path_is_allowed( '/blog/socks', '/shop' ) );
	}

	/**
	 * A leading slash is optional in the setting and on the path.
	 */
	public function test_leading_slash_is_optional() {
		$this->assertTrue( path_is_allowed( '/about', 'about' ) );
		$this->assertTrue( path_is_allowed( 'about', '/about' ) );
	}

	/**
	 * Several entries, one per line, however the browser sent the newlines.
	 */
	public function test_multiple_entries() {
		$allowlist = "/about\r\n/contact\n/shop";

		$this->assertTrue( path_is_allowed( '/contact', $allowlist ) );
		$this->assertTrue( path_is_allowed( '/shop/socks', $allowlist ) );
		$this->assertFalse( path_is_allowed( '/members', $allowlist ) );
	}

	/**
	 * The textarea can be annotated without the notes becoming rules.
	 */
	public function test_blank_lines_and_comments_are_ignored() {
		$allowlist = "# public pages\n\n/about\n   \n";

		$this->assertTrue( path_is_allowed( '/about', $allowlist ) );
		$this->assertFalse( path_is_allowed( '/anything', $allowlist ) );
	}

	/**
	 * An empty allowlist must not become a match-everything.
	 *
	 * @dataProvider empty_lists
	 *
	 * @param mixed $allowlist The setting value.
	 */
	public function test_empty_allowlist_allows_nothing( $allowlist ) {
		$this->assertFalse( path_is_allowed( '/', $allowlist ) );
		$this->assertFalse( path_is_allowed( '/anything', $allowlist ) );
	}

	/**
	 * Ways the setting can be empty.
	 *
	 * @return array<string, array{0: mixed}>
	 */
	public static function empty_lists() {
		return array(
			'empty string' => array( '' ),
			'whitespace'   => array( "  \n\n  " ),
			'comment only' => array( '# nothing here' ),
			'null'         => array( null ),
		);
	}
}
