# cred

YubiKey-encrypted credential manager with a CLI, TUI, GUI, and HTTP daemon.

## What it does

cred stores secrets encrypted with AES-256-GCM. The encryption key is derived from a YubiKey HMAC-SHA1 challenge-response, stretched through Argon2id. No YubiKey plugged in = no decryption. Period.

### Components

- **cred** -- CLI for storing, retrieving, listing, and deleting secrets. Includes a TUI mode.
- **credd** -- HTTP daemon that serves secrets over a REST API with two-tier auth (owner key + agent keys).
- **cred-gui** -- Native desktop GUI (egui) that talks to credd.
- **ykchallenge** -- .NET 8 helper for YubiKey HMAC-SHA1 on Windows (where ykman has HID access issues).

### Secret types

| Type | Fields |
|------|--------|
| `api-key` | key, url (optional), notes (optional) |
| `login` | url, username, password, totp_seed (optional) |
| `oauth-app` | client_id, client_secret, redirect_url (optional), scopes (optional) |
| `ssh-key` | private_key, public_key (optional), passphrase (optional) |
| `note` | content |
| `environment` | arbitrary key=value pairs |

### Encryption chain

```
YubiKey HMAC-SHA1 (slot 2, challenge-response)
    -> 20-byte HMAC output
    -> Argon2id (19 MiB, 2 iterations, fixed domain-separation salt)
    -> 256-bit AES key
    -> AES-256-GCM per-secret encryption (random 96-bit nonce)
```

## Backend

cred stores encrypted secrets in any HTTP API that implements these endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/store` | Store a memory (body: `{content, category, source, importance, is_static}`) |
| `GET` | `/list?category=credential&limit=500` | List memories by category |
| `DELETE` | `/memory/{id}` | Delete a memory by ID |

The storage format is: `[CRED:v3] service/key = <hex-encoded-ciphertext>`

Set `ENGRAM_URL` and `ENGRAM_API_KEY` environment variables to point cred at your backend.

## Build

Requires Rust 1.70+ and a C linker. Builds on both Linux and Windows.

```bash
# CLI
cargo build --release --bin cred

# HTTP daemon
cargo build --release --bin credd

# GUI (requires system OpenGL headers on Linux)
cargo build --release --bin cred-gui
```

Install the binaries wherever your PATH points:

```bash
# Linux
cp target/release/cred target/release/credd ~/.local/bin/

# Windows
cp target/release/cred.exe target/release/credd.exe ~/.local/bin/
```

### Multi-machine setup

cred is designed to run on multiple machines sharing the same backend. Each machine needs:
- Its own YubiKey programmed with the **same HMAC secret**
- Its own challenge file at `~/.config/cred/challenge` (generated per machine)
- The same `ENGRAM_URL` and `ENGRAM_API_KEY` environment variables

The CLI (`cred`) runs on any machine with a YubiKey. The daemon (`credd`) typically runs on one server and other machines access it via the HTTP API or use `cred` directly against the shared backend.

### ykchallenge (Windows only)

On Windows, `ykman` has HID exclusive access issues, so cred uses a .NET 8 helper instead. On Linux, `ykman` works directly and ykchallenge is not needed.

Requires .NET 8 SDK.

```bash
cd ykchallenge
dotnet build -c Release
```

## Setup

1. **Plug in a YubiKey** with HMAC-SHA1 programmed on slot 2. Use `ykman otp chalresp 2 --force <secret_hex>` on Linux, or `ykchallenge program <secret_hex>` on Windows.

2. **Run `cred init`** to generate a challenge file and verify YubiKey access. The challenge is saved to `~/.config/cred/challenge`.

3. **Set environment variables:**
   ```bash
   export ENGRAM_URL=http://your-backend:port
   export ENGRAM_API_KEY=your-api-key
   ```

4. **Store a secret:**
   ```bash
   cred store myservice api-key -s api-key
   # Prompts for the key value interactively
   ```

5. **Retrieve:**
   ```bash
   cred get myservice api-key
   cred get myservice api-key --raw        # bare value, for piping
   cred get myservice api-key --field key   # specific field
   ```

## credd (HTTP daemon)

```bash
export CRED_OWNER_KEY=your-owner-key    # required, must differ from ENGRAM_API_KEY
export ENGRAM_URL=http://your-backend:port
export ENGRAM_API_KEY=your-api-key
export CREDD_BIND=0.0.0.0:4400         # optional, default 0.0.0.0:4400

credd
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | none | Health check |
| `GET` | `/secrets` | owner or agent | List all secrets (redacted) |
| `GET` | `/secret/{service}/{key}` | owner or agent | Get a secret |
| `POST` | `/secret` | owner only | Store a secret |
| `DELETE` | `/secret/{service}/{key}` | owner only | Delete a secret |
| `POST` | `/agent-keys` | owner only | Create an agent key |
| `GET` | `/agent-keys` | owner only | List agent keys |
| `DELETE` | `/agent-keys/{agent_id}` | owner only | Revoke an agent key |

### Agent keys

credd supports two-tier auth. The owner key has full access. Agent keys (created via `cred agent-key generate <agent-id>`) have read-only access to secrets. Agent keys are stored in `~/.config/cred/agent-keys.json`.

```bash
# Generate an agent key
cred agent-key generate my-agent

# The key is printed once -- save it. Agents use it as a Bearer token.
```

## cred-gui

```bash
export CREDD_URL=http://localhost:4400  # optional, this is the default
export CRED_OWNER_KEY=your-owner-key

cred-gui
```

## Security notes

- Master key only exists in memory while cred/credd is running. Remove the YubiKey to lock.
- Challenge file at `~/.config/cred/challenge` is unique per machine. Back it up -- losing it means re-encrypting all secrets.
- Recovery file (v2) includes the per-machine challenge. Recover to a new machine without losing access to existing secrets.
- Two YubiKeys can be programmed with the same HMAC secret for redundancy.
- `CRED_OWNER_KEY` must be set explicitly for credd. It cannot fall back to `ENGRAM_API_KEY`.
- Agent keys have scoped access. Empty scopes = metadata only (type, field names). Use `--scope github/*` or `--scope '*'` when generating agent keys to grant plaintext access.
- Agent keys use constant-time comparison. Rate limiting is per source IP -- one bad actor cannot lock out other clients.
- Service and key names are validated: alphanumeric, hyphens, underscores, dots only (max 128 chars).
- Audit log at `~/.config/cred/audit.log` tracks all agent access.
- All secrets are encrypted at rest. The backend never sees plaintext.

## License

[Elastic License 2.0 (ELv2)](LICENSE)

---

Support: **support@syntheos.dev** · Security: **security@syntheos.dev** · [Security Policy](SECURITY.md)

