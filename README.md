# Community Login IdP

A WordPress plugin that lets people register and log in with **Slack** or **Discord** as the identity provider. Useful when your site sits alongside a community chat and you want membership there to be the source of truth for accounts here.

Both providers use the same OAuth 2.0 authorization-code flow, so the plugin is one generic flow plus a small table of endpoints.

## Requirements

- WordPress 6.0+
- PHP 7.4+

## Install

```bash
composer install   # dev tooling only (PHPCS/WPCS) — not needed at runtime
npm install
npm run build      # compiles src/ → build/, required for the button styles
```

Then activate the plugin and go to **Settings → Community Login**.

## Setting up the provider apps

Each provider needs its own app so you have a client ID and secret. The settings screen prints the exact **Redirect URL** to paste into each app — it looks like:

```
https://example.com/wp-login.php?action=community-login-idp&provider=slack
```

### Slack

1. Create an app at <https://api.slack.com/apps>.
2. Under **OpenID Connect**, enable Sign in with Slack and add the redirect URL.
3. Scopes are requested by the plugin (`openid email profile`); no bot token is needed.
4. Copy the **Client ID** and **Client Secret** into the settings screen.
5. Optionally set the **Workspace ID** (`T…`) to restrict sign-in to one workspace. It both pre-selects the workspace and is verified server-side after login.

### Discord

1. Create an application at <https://discord.com/developers/applications>.
2. Under **OAuth2**, add the redirect URL.
3. Scopes are requested by the plugin (`identify email`).
4. Copy the **Client ID** and **Client Secret** into the settings screen.

## How accounts are matched

On each sign-in, in order:

1. **Existing link** — a WordPress user with `community_login_idp_<provider>_id` user meta matching the remote account ID. Logs them in.
2. **Linking** — if the flow was started by someone already logged in (the **Link account** button on their profile), the remote account is attached to that user.
3. **Verified email match** — only if *Automatically link to an existing account with the same verified email address* is enabled. **Off by default:** turning it on means anyone who controls that email address at the provider can sign in as the matching WordPress user, including an administrator. Enable it only if you trust the provider's email verification.
4. **Registration** — if registration is enabled in the plugin settings, a new user is created with the site's default role. A verified email address is required.

Otherwise the attempt is rejected with a message on the login form.

## Linking accounts from the profile screen

**Users → Profile** has a *Linked Accounts* section. Linking there runs the same OAuth flow, but because the person is already logged in it attaches the provider account to *their* account and skips every matching rule above.

That means **the email addresses do not have to match.** If your Slack email differs from your WordPress email, link from the profile screen once and every later sign-in goes through the stored account ID, not the email.

To swap to a different remote account: unlink, then link again and authorize as the other account.

Two guards apply:

- An account already linked to a different WordPress user cannot be linked twice.
- If password sign-in is disabled, the last remaining link cannot be removed — that would lock the account out with no way back in. Link another provider first.

Administrators see the same section on other users' profiles, but **unlink only**. Linking authenticates whoever is clicking, so it is necessarily self-service.

## Making the provider the only way in

Enable **Disable username and password sign-in** in the settings to deprecate local passwords. When it is on:

- Interactive sign-in must go through a configured provider. The password form and the register / lost-password links are hidden.
- **Application passwords keep working** for the REST API and XML-RPC, so scripts and integrations are unaffected. The plugin uses core's own `application_password_is_api_request` definition to decide what counts as an API request.
- Password resets are disabled, since the resulting password could not be used to log in.

Two safety catches stop this from locking you out:

1. It has no effect unless at least one provider is enabled and has credentials.
2. Adding this to `wp-config.php` restores password sign-in unconditionally:

   ```php
   define( 'COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS', true );
   ```

**Link your own account to a provider before turning this on.**

Note that this controls *authentication*, not *access*. It does not make the site private — anonymous visitors can still read public content. If you want to require login to view the site at all, that is a separate plugin (such as Force Login) for now.

## Security notes

- CSRF is handled by the OAuth `state` parameter, stored in a 10-minute transient and verified before any response data is read. The callback is an external redirect, so a WordPress nonce is not possible there.
- Client secrets are stored in the `community_login_idp` option in plaintext, like every other WordPress OAuth plugin. If that is not acceptable, filter `pre_option_community_login_idp` to inject values from environment variables instead.
- Disabling password sign-in (above) covers interactive logins only. Application passwords are intentionally left working; revoke those per-user under **Users → Profile** if you need to cut off API access too.

## Development

```bash
npm run start       # watch build
npm run lint:js
npm run lint:css
npm run format      # prettier via wp-scripts

composer run lint   # phpcs (WPCS + PHPCompatibility)
composer run format # phpcbf
```

## What is deliberately left out

- **Discord guild (server) restriction** — needs the `guilds` scope plus another API call. Slack's workspace check covers the equivalent case; add the Discord one when someone actually needs it.
- **Avatar/display-name syncing on every login.** Profile fields are set once at registration and then left alone.
- **Requiring login to view the site.** Authentication only; see the note above.
- **SAML, generic OIDC, or any other provider.** Adding one is a new entry in `providers()` plus a branch in `normalize_identity()`.

## License

GPL-2.0-or-later
