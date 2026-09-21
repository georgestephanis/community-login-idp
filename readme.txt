=== Community Login IdP ===
Contributors: georgestephanis
Tags: login, oauth, slack, discord, sso
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Register and log in with Slack or Discord as the identity provider, so membership in your community chat is the source of truth for accounts here.

== Description ==

For sites that sit alongside a community Slack workspace or Discord server. People sign in with the account they already have there, and you never manage a password.

* **Slack and Discord**, both over a standard OAuth 2.0 authorization-code flow with PKCE.
* **Membership restriction.** Pin sign-in to one Slack workspace or one Discord server. Verified server-side on every sign-in, not just suggested in the picker.
* **Account linking.** People with an existing WordPress account link a provider to it from their profile screen. Administrators can unlink, but linking is necessarily self-service — it authenticates whoever clicks it.
* **Optional password deprecation.** Turn off username and password sign-in entirely, with two independent escape hatches so a broken provider cannot lock you out.
* **Blocklist.** Block a remote account from authenticating at all, from a row action on the Users screen.
* **Optional remote avatars.** Off by default; see the FAQ for the privacy tradeoff.
* **Application passwords keep working** when password sign-in is off, so the REST API, XML-RPC and your integrations are unaffected.

= How accounts are matched =

On each sign-in, in order:

1. An existing link — a WordPress user whose `community_login_idp_<provider>_id` user meta matches the remote account.
2. A link in progress — if the flow was started from the **Link account** button on a profile screen, the remote account is attached to that user.
3. A verified email match — **only** if you have enabled automatic linking. Off by default; see the FAQ.
4. A new account, if registration is enabled and the provider gave a verified email address.

== Installation ==

1. Upload the plugin zip through **Plugins → Add New → Upload Plugin**, and activate it.
2. Go to **Settings → Community Login**. The screen prints the exact **Redirect URL** for each provider — you will paste it into the provider's app.
3. Create the provider app (below), then paste its Client ID and Client Secret into the settings screen and tick **Enabled**.

= Slack =

1. Create an app at https://api.slack.com/apps.
2. Under **OAuth & Permissions**, add the redirect URL exactly as the settings screen prints it.
3. Copy the **Client ID** and **Client Secret** from **Basic Information**.
4. Optionally set the **Workspace ID** to restrict sign-in to one workspace. See the FAQ for how to find it.

= Discord =

1. Create an application at https://discord.com/developers/applications.
2. Under **OAuth2**, add the redirect URL exactly as the settings screen prints it.
3. Copy the **Client ID** and **Client Secret**.
4. Set the **Server ID** to restrict sign-in to one Discord server. Strongly recommended — leave it empty and any Discord account in the world can register.

== Frequently Asked Questions ==

= Where do I find my Slack Workspace ID? =

It is the `T…` value. The quickest way: open Slack in a browser and read it out of the URL — `app.slack.com/client/T0123456789/…`. The part starting with `T` is the workspace ID.

Alternatively, in the Slack desktop or web app, click the workspace name, then **Settings & administration → Workspace settings**; the ID appears in the address bar the same way.

= Where do I find my Discord Server ID? =

Turn on **Developer Mode** under **User Settings → Advanced**, then right-click the server in the sidebar and choose **Copy Server ID**. It is a long number.

Setting a Server ID adds the `guilds` permission to the consent screen people see when signing in, because the plugin has to ask Discord which servers they belong to. Without a Server ID, that permission is never requested.

= What happens if I disable password sign-in and the provider breaks? =

Two things stop that from locking you out.

First, the setting has no effect at all unless at least one provider is enabled and has credentials. Removing the credentials restores password sign-in.

Second, adding this to `wp-config.php` restores password sign-in unconditionally, no matter what the setting says:

`define( 'COMMUNITY_LOGIN_IDP_ALLOW_PASSWORDS', true );`

Link your own account to a provider before turning the setting on.

= Does disabling password sign-in break the REST API or my integrations? =

No. Application passwords keep working, deliberately. The plugin uses WordPress core's own definition of an API request to decide what to leave alone, so anything that authenticates with an application password is unaffected.

If you also want to cut off a specific user's API access, revoke their application passwords under **Users → Profile**.

= Does this make my site private? =

No. It controls *authentication* — who may log in and how. Anonymous visitors can still read whatever is publicly published. Making the site private is a separate concern and a separate plugin for now.

= Should I enable "automatically link to an existing account with the same verified email address"? =

Only if you trust the provider's email verification. It is off by default on purpose: if someone can get the provider to attest an email address they do not really control, that setting lets them sign in as the matching WordPress user.

With it off, a provider account whose email matches an existing user is refused, and the person is told to log in with their password and link from their profile screen instead. That proves they control both accounts.

= How long do people stay signed in? =

48 hours by default — the same as a WordPress login without *Remember Me*. Change it under **Settings → Community Login → Session length**.

Worth thinking about, because membership of your Slack workspace or Discord server is only checked when someone signs in. The session length is therefore also how long someone keeps access after leaving your community. A long session is convenient and slow to revoke; a short one is the reverse.

= How do I stop someone from signing in? =

On **Users**, hover their row and choose **Block Slack sign-in** or **Block Discord sign-in**. That remote account can no longer authenticate, whatever else would otherwise let it in, and it cannot register a new WordPress account either.

Blocking does not delete or change the WordPress user, and does not end an existing session — those are separate decisions, so they are separate actions. Blocked accounts are listed at the bottom of **Settings → Community Login** with an Unblock button.

The person is told only that the account cannot be used to sign in. Telling them exactly why tells them what to work around.

= Should I turn on remote avatars? =

It is your call, which is why it is off by default. With it on, profile pictures are hotlinked from Slack's or Discord's CDN, which tells them the IP address of every visitor who loads a page with an avatar on it — including visitors who have nothing to do with your community. That is the same objection people raise about Gravatar, so it is not a new category of problem, but it should not be silently on.

With it off, nothing is requested from the provider's CDN and avatars behave exactly as WordPress normally does.

Either way, users with no linked provider, or no picture set there, keep the site's normal avatar.

= Can someone link a provider account that is already linked to another user? =

No. One remote account maps to one WordPress user.

= What happens when someone leaves the workspace or server? =

Their next sign-in attempt fails the membership check. An existing WordPress session is not terminated, and the WordPress account itself stays as it is.

== Troubleshooting ==

Sign-in failures come back to the login form with a message. If `WP_DEBUG` is on, the provider's raw error body is written to the PHP error log, prefixed `[community-login-idp]` — that is usually the fastest way to the real cause.

= "We could not complete the sign-in with that service." =

The token exchange failed. Almost always a wrong **Client ID** or **Client Secret**, or a **Redirect URL** that does not match the one registered in the provider's app character for character — including `http` vs `https` and any `www`.

= "That service did not tell us who you are." =

The token worked but the profile request did not return a usable profile. Check the app's scopes: Slack needs `openid email profile`, Discord `identify email`.

= "That account is not a member of this community." =

The account is not in the configured Slack workspace or Discord server. Check the **Workspace ID** / **Server ID** is the right one, and that the person really is a member.

= "We could not check your membership of this community." =

Discord only. The membership lookup itself failed — a network problem or a Discord outage, not a rejection. Trying again usually works.

= "That login attempt expired." =

The sign-in took more than ten minutes, or the browser dropped the transient. Start again. If it happens constantly, suspect an object cache dropping transients, or a page cache serving the login page.

= "An account already exists with that email address." =

A WordPress user already has that email, and automatic email linking is off. Log in with the password and link the provider from the profile screen. See the FAQ above for why this is the default.

= The sign-in buttons are unstyled =

The compiled stylesheet is missing. Install from a release zip, or run `npm install && npm run build` if you installed from a clone.

== Screenshots ==

1. The settings screen, with both providers configured.
2. The login form with provider buttons.
3. The linked-accounts section on the profile screen.

== Changelog ==

= 0.1.0 =
* Initial release.
* Slack and Discord sign-in and registration over OAuth 2.0 with PKCE.
* Slack workspace and Discord server membership restrictions.
* Account linking and unlinking from the profile screen.
* Optional deprecation of username and password sign-in, with lockout escape hatches.
* Optional remote avatars from the provider, off by default.
* Blocklist for remote accounts, with a row action on the Users screen.
* Configurable session length, defaulting to 48 hours.
