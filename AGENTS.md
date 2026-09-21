# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

A single-file WordPress plugin: Slack and Discord as OAuth identity providers for WordPress login and registration. See `README.md` for setup and behaviour.

## Layout

```
community-login-idp.php   the entire plugin — flow, buttons, profile UI, settings
uninstall.php             option + user meta cleanup
src/style.scss            login button styles (compiled by wp-scripts)
src/index.js              entry point; exists only to import the SCSS
build/                    generated, gitignored — run `npm run build`
```

There is no `includes/`, no class hierarchy, and no autoloader. **Keep it that way** unless the file genuinely outgrows itself. Everything lives in the `Community_Login_IdP` namespace as plain functions hooked directly at the bottom of their own section.

## Conventions

- WordPress Coding Standards, enforced by `.phpcs.xml.dist`. Run `composer run lint` before finishing; `composer run format` fixes most of it.
- JS/CSS go through `@wordpress/scripts`: `npm run lint:js`, `npm run lint:css`, `npm run build`.
- Escape on output (`esc_html`, `esc_attr`, `esc_url`), sanitize on input, text domain `community-login-idp` on every user-facing string.
- Options live in one array option, `community_login_idp`, read through `settings()` so defaults are always present. Do not add a second option.
- Remote account IDs live in user meta `community_login_idp_<provider>_id`.

## Adding a provider

1. Add an entry to `providers()`: label, authorize/token/userinfo URLs, scope.
2. Add a branch to `normalize_identity()` returning `sub`, `email`, `verified`, `name`, `nickname`, `team`.
3. Add a colour rule for `.clidp-button--<slug>` in `src/style.scss`.
4. Add the slug to `uninstall.php`.

Everything else — settings fields, buttons, the flow — is generic and needs no changes.

## Do not

- Do not add a dependency for something a few lines of core WordPress already does. `wp_remote_post` is the HTTP client; there is no OAuth library here and there should not be one.
- Do not loosen the `state` check in `handle_callback()`. It is the only CSRF protection the callback can have.
- Do not make "link by verified email" default to on. It is an account-takeover vector if the provider's verification is weak, which is why it is an explicit opt-in with a warning.
- Do not sync profile data on every login, add avatar handling, or build a REST API surface unless asked.

## Testing

There is no test suite. Verify by hand against a local site (Local by WPEngine) with a real Slack/Discord app pointed at the printed redirect URL — the flow is almost entirely I/O against a third party, so unit tests would test the mocks. If you add non-trivial pure logic (e.g. identity normalization edge cases), a small test for that function is welcome.
