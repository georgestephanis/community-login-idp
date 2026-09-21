<?php
/**
 * Tests for discord_avatar_url().
 *
 * @package Community_Login_IdP
 */

use PHPUnit\Framework\TestCase;

use function Community_Login_IdP\discord_avatar_url;

/**
 * Discord hands back a hash, not a URL, and the extension depends on the hash.
 */
class DiscordAvatarTest extends TestCase {

	/**
	 * The ordinary case.
	 */
	public function test_static_avatar() {
		$this->assertSame(
			'https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png',
			discord_avatar_url( '80351110224678912', '8342729096ea3675442027381ff50dfe' )
		);
	}

	/**
	 * An `a_` prefix means animated, and Discord only serves those as .gif.
	 */
	public function test_animated_avatar() {
		$this->assertSame(
			'https://cdn.discordapp.com/avatars/80351110224678912/a_8342729096ea3675442027381ff50dfe.gif',
			discord_avatar_url( '80351110224678912', 'a_8342729096ea3675442027381ff50dfe' )
		);
	}

	/**
	 * No custom avatar falls through to whatever default the site has set.
	 *
	 * @dataProvider no_avatar
	 *
	 * @param mixed $hash Avatar hash as it arrives on the profile response.
	 */
	public function test_no_avatar( $hash ) {
		$this->assertSame( '', discord_avatar_url( '80351110224678912', $hash ) );
	}

	/**
	 * Ways the profile response says "no picture".
	 *
	 * @return array<string, array{0: mixed}>
	 */
	public static function no_avatar() {
		return array(
			'null'   => array( null ),
			'empty'  => array( '' ),
			'absent' => array( false ),
		);
	}
}
