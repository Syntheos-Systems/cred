# Contributing to cred

Guidelines for contributing to the YubiKey-encrypted credential manager.

## Development Setup

```bash
git clone https://codeberg.org/GhostFrame/cred.git
cd cred

cargo build --release
```

**Requirements:**
- Rust 1.70+
- C linker
- YubiKey with HMAC-SHA1 programmed on slot 2 (for testing encryption)
- .NET 8 SDK (only if building ykchallenge on Windows)

## Architecture

cred is a single Cargo project with three binaries and a Windows helper:

```
src/
  main.rs        CLI entrypoint (cred) -- store, get, list, delete, init, TUI mode
  server.rs      HTTP daemon (credd) -- axum server with two-tier auth
  gui.rs         Desktop GUI (cred-gui) -- egui/eframe, talks to credd
  crypto.rs      AES-256-GCM encryption, Argon2id key derivation, YubiKey challenge-response
  yubikey.rs     YubiKey HMAC-SHA1 interface (ykman on Linux, ykchallenge on Windows)
  backend.rs     Backend API client -- stores encrypted blobs in any HTTP API
  store.rs       Local secret store logic and cache
  agent_keys.rs  Agent key management (generation, validation, rate limiting)
  types.rs       Shared types (SecretType, SecretEntry, etc.)

ykchallenge/     .NET 8 helper for YubiKey HMAC-SHA1 on Windows
```

### Key Design Decisions

1. **YubiKey-or-nothing.** No master password fallback. The encryption key is derived from a YubiKey HMAC-SHA1 challenge-response stretched through Argon2id. Remove the key, remove access.

2. **Backend-agnostic storage.** cred stores encrypted blobs via a simple HTTP API (POST /store, GET /list, DELETE /memory/:id). The default backend is Engram, but anything implementing those three endpoints works.

3. **Two-tier auth on credd.** Owner keys have full access. Agent keys are read-only. Agent keys use constant-time comparison with exponential backoff on failure.

4. **Zero plaintext at rest.** The backend never sees plaintext. Each secret is AES-256-GCM encrypted with a per-secret random nonce before leaving the client.

5. **Zeroize sensitive memory.** All key material uses the `zeroize` crate to scrub RAM on drop.

## Testing

```bash
cargo test
```

Testing the full encryption path requires a YubiKey. For CI or keyless development, test individual modules:

```bash
# Test crypto primitives (no YubiKey needed if you mock the challenge)
cargo test --lib crypto

# Test type serialization
cargo test --lib types
```

Areas that need test coverage:

| Feature | Location |
|---------|----------|
| Agent key auth and rate limiting | `src/agent_keys.rs`, `src/server.rs` |
| Backend failover and retry | `src/backend.rs` |
| Secret type validation | `src/types.rs` |
| TUI mode | `src/main.rs` (TUI section) |
| GUI state management | `src/gui.rs` |

## Code Style

- Rust 2021 edition
- `cargo fmt` and `cargo clippy` before committing
- Sensitive data wrapped in `Zeroizing<T>` where possible
- Error handling: `anyhow` for binaries, `thiserror` for library-style modules

## Pull Request Process

1. Fork the repo and create a feature branch
2. Run `cargo test` and `cargo clippy`
3. Never commit real secrets, challenge files, or agent keys
4. Submit a PR with a clear description of what changed and why

## Areas Where Help Is Needed

- **Secret rotation**: cred has no built-in rotation workflow. A `cred rotate` command that re-encrypts under a new challenge would be useful.
- **Backup/restore**: Exporting and importing encrypted vaults between machines.
- **TOTP generation**: The `login` secret type stores `totp_seed` but there is no `cred totp <service>` command to generate codes.
- **Shell completion**: Tab completion for service and key names in bash/zsh/fish.

## License

Elastic License 2.0 (ELv2). See [LICENSE](LICENSE) for details.
