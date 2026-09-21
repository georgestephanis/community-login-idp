# Community Login IdP

A WordPress plugin that lets people register and log in with **Slack** or **Discord** as the identity provider. Useful when your site sits alongside a community chat and you want membership there to be the source of truth for accounts here.

Both providers use the same OAuth 2.0 authorization-code flow, so the plugin is one generic flow plus a small table of endpoints.

## Requirements

- WordPress 6.0+
- PHP 7.4+

## Install

Download the zip from the [latest release](https://github.com/georgestephanis/community-login-idp/releases/latest) and install it through **Plugins → Add New → Upload Plugin**. Release zips have the stylesheet already compiled.

To install from a clone instead, build the assets first — `build/` is not committed, and without it the sign-in buttons render unstyled:

```bash
composer install   # dev tooling only (PHPCS/WPCS/PHPUnit) — not needed at runtime
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
3. Scopes are requested by the plugin (`identify email`, plus `guilds` when a Server ID is set).
4. Copy the **Client ID** and **Client Secret** into the settings screen.
5. Set the **Server ID** to restrict sign-in to members of one Discord server. Turn on **Developer Mode** (User Settings → Advanced), then right-click the server and choose **Copy Server ID**. Leave it empty and any Discord account in the world can register.

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

## Blocking someone

When an account from the provider has to go, **Users → hover a row → Block Slack sign-in** (or Discord). That remote account can no longer authenticate, whatever else would otherwise let it in — it is checked before account lookup, linking or creation, so a blocked account cannot register a fresh WordPress user either.

Blocking does not touch the WordPress user. The account stays, its content stays, and existing sessions are not terminated — delete or edit the user separately if that is what you want. The reasoning is that "stop them getting back in" and "erase them" are different decisions and should not be one button.

Blocked accounts are listed at the bottom of **Settings → Community Login**, with an **Unblock** button. The list caches the display name and email as they were at the time of blocking, so it reads as people rather than as a wall of `U…` strings.

The login form tells a blocked person only that the account cannot be used to sign in. That is deliberate: telling someone exactly why they are blocked tells them what to work around.

## Avatars

Off by default. Turn on **Use the profile picture from the provider** and avatars come from Slack's or Discord's CDN instead of Gravatar. The URL is refreshed on every sign-in, so changing your picture in the chat changes it here.

Anyone without a linked provider, or without a picture set there, keeps the site's normal avatar — this only ever adds a source, it never removes one.

It is off by default because hotlinking the provider's CDN tells Slack or Discord the IP address of every visitor who loads a page with an avatar on it, including visitors who have nothing to do with your community. That is the same objection people raise about Gravatar, so it is not a new category of problem, but it should be your decision rather than a default. Sideloading the images into the media library would avoid it at the cost of storage, staleness, and cleanup on uninstall; not worth it yet.

## Security notes

- CSRF is handled by the OAuth `state` parameter, stored in a 10-minute transient and verified before any response data is read. The callback is an external redirect, so a WordPress nonce is not possible there.
- Client secrets are stored in the `community_login_idp` option in plaintext, like every other WordPress OAuth plugin. If that is not acceptable, filter `pre_option_community_login_idp` to inject values from environment variables instead.
- Disabling password sign-in (above) covers interactive logins only. Application passwords are intentionally left working; revoke those per-user under **Users → Profile** if you need to cut off API access too.

## Releasing

Tag and push:

```bash
git tag v0.2.0 && git push --tags
```

`.github/workflows/release.yml` builds the assets, assembles a zip of everything in `.distignore`'s complement, and attaches it to a generated GitHub release. That zip is also what WordPress.org would want.

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

- **Display-name and email syncing on every login.** Profile fields are set once at registration and then left alone. Avatars are the exception — see below.
- **Requiring login to view the site.** Authentication only; see the note above.
- **SAML, generic OIDC, or any other provider.** Adding one is a new entry in `providers()` plus a branch in `normalize_identity()`.

## License

GPL-2.0-or-later
