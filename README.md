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

Users can link and unlink providers themselves from **Users → Profile**.

## Security notes

- CSRF is handled by the OAuth `state` parameter, stored in a 10-minute transient and verified before any response data is read. The callback is an external redirect, so a WordPress nonce is not possible there.
- Client secrets are stored in the `community_login_idp` option in plaintext, like every other WordPress OAuth plugin. If that is not acceptable, filter `pre_option_community_login_idp` to inject values from environment variables instead.
- The plugin does **not** disable password login. Combine with a plugin that does if you want the provider to be the only way in.

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
- **SAML, generic OIDC, or any other provider.** Adding one is a new entry in `providers()` plus a branch in `normalize_identity()`.

## License

GPL-2.0-or-later
