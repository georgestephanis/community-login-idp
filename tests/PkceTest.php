<?php
/**
 * Tests for pkce_challenge().
 *
 * @package Community_Login_IdP
 */

use PHPUnit\Framework\TestCase;

use function Community_Login_IdP\pkce_challenge;

/**
 * If the challenge is derived wrongly the token exchange fails for everyone,
 * so it is worth pinning to the spec's own test vector.
 */
class PkceTest extends TestCase {

	/**
	 * The worked example from RFC 7636 appendix B.
	 */
	public function test_rfc_7636_test_vector() {
		$this->assertSame(
			'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
			pkce_challenge( 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' )
		);
	}

	/**
	 * Base64url: no padding, and none of the characters that need escaping in a
	 * query string.
	 */
	public function test_challenge_is_url_safe() {
		for ( $i = 0; $i < 50; $i++ ) {
			$challenge = pkce_challenge( 'verifier' . $i );

			$this->assertSame( 43, strlen( $challenge ) );
			$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]+$/', $challenge );
		}
	}
}
