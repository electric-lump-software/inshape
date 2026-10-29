# inshape

inshape starts your command with its secrets already in place, and refuses to start it if anything looks wrong.

It is a small static binary for Linux (x86_64 and aarch64, musl). It signs in to Infisical, fetches the secrets from the folders you name, checks them in memory, revokes its sign-in token, and then replaces itself with your command. The command's environment is your host environment plus the checked secrets. Nothing is written to disk.

## Command line

```
inshape [--optional] --allowlist FILE -- CMD [ARGS...]
inshape --version
inshape --help
```

- `--allowlist FILE` names the secrets the command may receive, one per line. Required.
- `--optional` starts the command without Infisical if none of the four sign-in settings is set. Without it, no settings at all is an error (exit 64), so a missing configuration never passes silently. A partly set configuration is always an error.
- Everything after `--` is the command and its arguments.

## Settings

Settings are read from the environment.

| Name | Required | Meaning |
| --- | --- | --- |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` | yes | Universal auth client id. |
| `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` | yes | Universal auth client secret. |
| `INFISICAL_PROJECT_ID` | yes | The project to read. |
| `INFISICAL_ENV` | yes | The environment slug, for example `prod`. No whitespace. |
| `INFISICAL_PATHS` | no | Space-separated folders to read. Default `/`. |
| `INFISICAL_API_URL` | no | Base URL of Infisical. Default `https://app.infisical.com`. Must start with `https://`, with no credentials, query or fragment. |
| `INFISICAL_PROXY_URL` | no | An http proxy, written `http://[user:pass@]host:port`. |

Empty values count as unset. Whitespace-only values and values containing a NUL byte are refused.

Folders in `INFISICAL_PATHS` must be written canonically: a leading slash, no trailing slash, no empty segments, and segments made of letters, digits, `-` and `_`. So `/core` is fine, and `/core/`, `core` and `//core` are refused at start-up (exit 64). inshape compares each secret's reported folder with the one it asked for, exactly, so there is no room for two spellings of the same folder. A folder listed twice is refused too.

The proxy URL must be plain `http://` to the proxy with an explicit port and no path. The proxy password must be percent-encoded: write `%` as `%25`, `@` as `%40`, and so on. The proxy URL is never printed.

The ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` variables, in any case, are ignored. The only proxy inshape uses is `INFISICAL_PROXY_URL`.

## What it calls

Each request has a 10 second timeout, is never retried, and has its response body capped at 1 MiB.

1. `POST {api}/api/v1/auth/universal-auth/login` with the client id and secret. The answer holds an access token.
2. `GET {api}/api/v4/secrets` once per folder, with the token as a bearer header, asking for no secret reference expansion, no imports and no recursion.
3. `POST {api}/api/v1/auth/token/revoke` with the token, as soon as all folders are fetched. If the revoke fails, inshape logs a warning and carries on, because the token expires on its own.

## The allowlist

One secret name per line. Blank lines are ignored, and so are lines starting with `#`.

```
# what the app may receive
SECRET_KEY_BASE
STRIPE_API_KEY
```

A name must match `^[A-Z][A-Z0-9_]*$`. Writing `NAME=value`, a repeated name, or an empty file is an error.

These names are never allowed in the file: `LD_*`, `PATH`, `HOME`, `ERL_*`, `RELEASE_*`, `INFISICAL_*`, and anything ending in `DATABASE_URL`.

Canary names, those matching `^INFISICAL_CANARY_[A-Z0-9_]+$`, are allowed without being listed.

## The checks

inshape refuses to start (exit 65) if any of these fail. It collects every problem across every folder and reports them all in one go, naming folders and secret names but never values.

- A folder has no secrets, or no folder was fetched.
- A folder has no `INFISICAL_CANARY_*` secret. Put one in every folder: it proves the folder you asked for is the folder you got.
- A secret is not in the allowlist, or its name is not valid.
- A name appears twice in one folder, or in more than one folder.
- A secret comes back from another environment or another folder than the one requested, or without that information.
- A value is hidden by Infisical, empty, whitespace-only or contains a NUL byte.

When Infisical is configured, inshape also refuses before it even signs in (exit 64) when the host environment already sets a name the allowlist names, or any `INFISICAL_CANARY_*`. Otherwise a stale host value could quietly win or lose against the fetched one. The message names the variable, never its value.

## Exit codes

| Code | Meaning |
| --- | --- |
| 64 | Bad arguments, settings or allowlist. |
| 65 | Secrets refused, or Infisical gave an unusable answer. |
| 69 | Infisical or the proxy was unreachable, timed out, failed TLS or answered 5xx. |
| 71 | Starting the command failed. |
| 77 | Infisical answered 401 or 403. |

Log lines go to stderr and start with `inshape: `. They may hold folder paths, counts, canary names, rejected names, clashing host variable names, the allowlist path, the command's path and HTTP status codes. They never hold secret values, tokens, the client secret, response bodies or the proxy URL.

## The command's environment

The command gets the host environment with every name starting `INFISICAL_` removed (that includes `INFISICAL_PATHS`, `INFISICAL_API_URL` and `INFISICAL_PROXY_URL`, as well as the four sign-in settings), plus the checked secrets and the canaries. With `--optional` and nothing configured, it gets the host environment with the `INFISICAL_` names removed.

## Installing in a container

Fetch a pinned release and check its hash. Take the hash from `SHA256SUMS` on the release page, and check the attestation (below) when you pick a new version.

```
ADD --checksum=sha256:<sha> --chmod=0755 https://github.com/electric-lump-software/inshape/releases/download/vX.Y.Z/inshape-x86_64-unknown-linux-musl /usr/local/bin/inshape
ENTRYPOINT ["inshape", "--allowlist", "/app/secrets.allow", "--"]
CMD ["/app/bin/server"]
```

Releases hold `inshape-x86_64-unknown-linux-musl`, `inshape-aarch64-unknown-linux-musl` and `SHA256SUMS`.

## Building from source

```
cargo build --release --locked
```

The toolchain is pinned in `rust-toolchain.toml`. `scripts/build-release.sh` makes the static release binaries.

## Verifying a release

The binaries are static, built from the tagged commit on GitHub's runners, and attested. The build is reproducible: it is run twice, in different directories with different cargo homes, and the release is stopped unless both hashes match. `scripts/build-release.sh` is the build and `scripts/verify-release.sh` is the check.

```
gh attestation verify inshape-x86_64-unknown-linux-musl --repo electric-lump-software/inshape
```

## What you are trusting

- **Infisical and its TLS certificate.** inshape talks to the API over https, using the bundled web PKI root certificates. Whoever can answer as Infisical can hand it any secret that passes the checks.
- **The allowlist and the canaries.** The checks stop a wrong folder, a wrong environment, an unexpected name or a hidden value from being loaded. They cannot tell a right value from a wrong one with the right name.
- **The host.** The secrets sit in the command's environment, as with any env-based scheme. Anyone who can read that process's environment can read them. inshape keeps them off disk and out of its own logs, and revokes its token before the command starts.
- **Your proxy, if you set one.** The connection to Infisical is TLS through the proxy, so the proxy sees where you connect but not what is sent. It does see the proxy password you give it.
- **This build.** Check the attestation and the hash before you pin a version. Dependencies are few and pinned in `Cargo.lock`.

## End-to-end test

`.github/workflows/e2e.yml` runs the release binaries on both architectures against a real throwaway Infisical project: directly, through a CONNECT proxy (tinyproxy with BasicAuth), and with a wrong client secret (which must exit 77). It runs on version tags, weekly, and on demand:

```
gh workflow run e2e.yml
```

It expects a project with an environment `staging` and two folders: `/one` holding `E2E_ONE` and `INFISICAL_CANARY_ONE`, and `/two` holding `E2E_TWO` and `INFISICAL_CANARY_TWO`. Every value must be a dummy. The repository secrets `INSHAPE_E2E_CLIENT_ID`, `INSHAPE_E2E_CLIENT_SECRET` and `INSHAPE_E2E_PROJECT_ID` hold the sign-in settings. The test compares names only: the command must receive the host names (minus `INFISICAL_*`) plus exactly those four, each non-empty. Values are never printed. `e2e/expect.sh` is for CI only (it needs GNU `env -0`). The wrong-secret check runs once per run, from one job, so the identity's lockout threshold must allow one failed login per run.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).

## Licence

MIT.
