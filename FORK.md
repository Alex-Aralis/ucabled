# About this fork

This is a private copy of [fuzy112/ucabled](https://github.com/fuzy112/ucabled),
taken on 2026-10-23 at the v0.2.0 release (c7741d6). It has no upstream remote
on purpose, so nothing from the original author arrives without review.

Before it was installed, all of `src/`, `dist/`, `install.sh` and the
`Cargo.lock` checksums were audited. Nothing malicious turned up.

Changes on top of v0.2.0:

- **Android sign-in** (`ctap::normalize_assertion_options`): Firefox sends
  getAssertion options as `{"uv": true, "up": true}`, which is not canonical
  CBOR, and Android's hybrid authenticator rejects that request with
  "Something went wrong". The bridge now drops `up: true`, the CTAP default,
  and sorts the remaining keys, the same way Chromium sends them.
- **Agent re-registration**: after the daemon restarted, the session agent's
  one attempt to register again came before the daemon served
  `RegisterAgent`, and it was never retried, so no QR window appeared. The
  agent now retries 10 times, one second apart.

GitHub Actions are disabled on this repository. The upstream workflows rely on
third-party actions and a Cachix token, and are kept only for reference.

Install it the way `README.md` describes ("other distros"). Build with a plain
`cargo build --release`: `cargo test` rebuilds the binaries with dev-dependency
features, so they differ from a release build.
