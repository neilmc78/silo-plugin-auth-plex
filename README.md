# Silo Plex Sign-in

A [Silo](https://github.com/Silo-Server/silo-server) sign-in plugin that adds a "Sign in with Plex" button. Only Plex accounts that can reach your Plex Media Server get in: the server's owner and the people it is shared with.

## How it works

1. The person clicks **Sign in with Plex**. The plugin creates a plex.tv PIN and sends the browser to Plex's own sign-in page, so Silo never sees the Plex password.
2. Plex sends the browser back to Silo's OAuth callback. The plugin reads the approved PIN's token, loads the Plex account and lists the servers it can reach.
3. The account is let in only if your server's machine identifier is on that list. Silo keys the account on the Plex account's `uuid`, which never changes.
4. Silo keeps the Plex token (encrypted) and re-checks the account later. Once the server is no longer shared with the person, Silo signs them out.

Whether a first Plex sign-in creates a Silo account is Silo's **Create accounts on first sign-in** switch on the Sign-in settings page, not a plugin setting.

## Setup

1. Open `http://<plex-server>:32400/identity` and copy `machineIdentifier`.
2. Install the plugin in Silo (**Admin → Plugins → Upload**) with the `plugin-linux-amd64` binary from a release.
3. Paste the machine identifier under **Plex server**, save, and run **Check Connection**.
4. Enable the provider on Silo's Sign-in settings page.

Nothing is registered at Plex. Silo's public URL must be reachable from the browser, because Plex sends the browser back to it.

## Build

```sh
make build      # ./plugin for this machine
make build-all  # dist/plugin-linux-{amd64,arm64}
make test
```

Pushing a `v*` tag, or running the Release workflow by hand, builds the binaries and attaches them to a GitHub release.

## Security notes

- A denial leaves `external_subject` empty. Logs and denial details never contain tokens or PIN codes.
- The PIN code stays in Silo's server-side flow state. A callback whose `code` names any other PIN is refused.
- A token plex.tv refuses on re-check counts as "cannot check", not "revoked", because Plex answers both the same way. Silo then ages the session out instead of signing the person out at once.
