# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

A single-file WordPress plugin: Slack and Discord as OAuth identity providers for WordPress login and registration. See `README.md` for setup and behaviour.

## Layout

```
community-login-idp.php   the entire plugin — flow, buttons, profile UI, settings
uninstall.php             option + user meta cleanup — add every new key here
languages/                generated .pot — run `composer run make-pot` after touching strings
tests/                    PHPUnit, no WordPress install needed
src/style.scss            login button styles (compiled by wp-scripts)
src/index.js              entry point; exists only to import the SCSS
build/                    generated, gitignored — run `npm run build`
```

There is no `includes/`, no class hierarchy, and no autoloader. **Keep it that way** unless the file genuinely outgrows itself. Everything lives in the `Community_Login_IdP` namespace as plain functions hooked directly at the bottom of their own section.

## Conventions

- WordPress Coding Standards, enforced by `.phpcs.xml.dist`. Run `composer run lint` before finishing; `composer run format` fixes most of it.
- JS/CSS go through `@wordpress/scripts`: `npm run lint:js`, `npm run lint:css`, `npm run build`.
- Escape on output (`esc_html`, `esc_attr`, `esc_url`), sanitize on input, text domain `community-login-idp` on every user-facing string. Regenerate `languages/community-login-idp.pot` with `composer run make-pot` when you add or change one.
- Settings live in one array option, `community_login_idp`, read through `settings()` so defaults are always present. Do not add a second settings option.
- The blocklist is the one other option, `community_login_idp_blocklist`, and it is moderation data rather than settings. It has to live outside the settings option because `sanitize_settings()` rebuilds that array from the submitted form, which would wipe anything the form does not render.
- Remote account IDs live in user meta `community_login_idp_<provider>_id`; the cached avatar URL in `community_login_idp_avatar`. Add anything new to `uninstall.php`.
- `app_token` is the provider's own bot token, read through `app_token()`. It is for lookups the sign-in flow cannot make. The *user's* access token is still discarded at the end of `handle_callback()` and must stay that way — storing per-user tokens is a much larger question than storing one per site.
- `role_map` is the per-provider `remote role = WordPress role` textarea, parsed by `parse_role_map()`. It is read **only** at account creation, in `resolve_user()`. Do not apply it on later sign-ins without being asked: that turns the provider into something that can demote WordPress users, and is the whole reason the feature is creation-only.
- `team_id` is the per-provider membership restriction: a Slack workspace, a Discord server. Same key, different label on the settings screen.

## Adding a provider

1. Add an entry to `providers()`: label, authorize/token/userinfo URLs, scope.
2. Add a branch to `normalize_identity()` returning `sub`, `email`, `verified`, `name`, `nickname`, `team`, `avatar`.
3. Add a colour rule for `.clidp-button--<slug>` in `src/style.scss`.
4. Add the slug to `uninstall.php`.

Everything else — settings fields, buttons, the flow — is generic and needs no changes.

## Do not

- Do not add a dependency for something a few lines of core WordPress already does. `wp_remote_post` is the HTTP client; there is no OAuth library here and there should not be one.
- Do not loosen the `state` check in `handle_callback()`. It is the only CSRF protection the callback can have.
- Do not narrow the exemptions in `require_login()`. It hangs off `template_redirect` specifically because wp-login.php, the OAuth callback, cron, admin-ajax and XML-RPC never reach that hook; robots.txt and the favicon do and are exempted by hand. Moving it to an earlier hook to "catch more" is how a private-site feature locks everyone out.
- Do not remove either lockout guard in `passwords_disabled()` — the "at least one active provider" check and the `COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS` constant. They are the only way back into a site whose provider broke.
- Do not block application passwords when password sign-in is disabled. `is_api_request()` deliberately mirrors core so API access keeps working.
- Do not make "link by verified email" default to on. It is an account-takeover vector if the provider's verification is weak, which is why it is an explicit opt-in with a warning.
- Do not sync display names, emails or other profile fields on every login, and do not build a REST API surface, unless asked. The avatar URL is the one exception: it is refreshed on each login so the picture does not go stale, and it is only *displayed* when the opt-in `remote_avatars` setting is on.

## Testing

`composer run test` runs PHPUnit against `tests/`. The bootstrap stubs the few WordPress functions the plugin calls at file scope and loads the plugin directly, so there is no WordPress test install to set up.

Only pure logic is tested — `normalize_identity()` today. The flow is almost entirely I/O against a third party, so tests of the rest would test the mocks. Verify that by hand against a local site (Local by WPEngine) with a real Slack/Discord app pointed at the printed redirect URL. If you add non-trivial pure logic, add a test for it.
