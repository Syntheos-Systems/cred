// Shared modules -- some items are only used by cred or credd (not both).
mod agent_keys;
mod backend;
mod backend_engram;
mod backend_sqlite;
mod crypto;
mod store;
mod types;
#[allow(dead_code)]
mod yubikey;

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use zeroize::Zeroize;

use crate::store::CredStore;
use crate::types::{Secret, SecretValue};

#[derive(Parser)]
#[command(name = "cred", about = "YubiKey-encrypted credential manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize: generate HMAC secret, program YubiKey, create recovery kit
    Init,
    /// Store a secret (prompts interactively for fields based on type)
    Store {
        /// Service name (e.g., github, aws)
        service: String,
        /// Key name (e.g., api-key, admin, oauth-client-secret)
        key: String,
        /// Secret type: api-key, login, oauth-app, ssh-key, note, environment
        #[arg(short, long, default_value = "api-key")]
        secret_type: String,
    },
    /// Retrieve a secret
    Get {
        /// Service name
        service: String,
        /// Key name
        key: String,
        /// Extract a specific field (e.g., password, username, key)
        #[arg(short, long)]
        field: Option<String>,
        /// Print raw value only (for piping)
        #[arg(short, long)]
        raw: bool,
    },
    /// List all stored secrets (values redacted)
    List {
        /// Filter by service name
        #[arg(short, long)]
        service: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Service name
        service: String,
        /// Key name
        key: String,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Recover: decrypt recovery file and program a new YubiKey
    Recover {
        /// Path to recovery.enc file
        #[arg(short, long, default_value = "~/.config/cred/recovery.enc")]
        from: String,
    },
    /// Bulk import secrets from stdin (one per line: service<TAB>key<TAB>value)
    Import {
        /// Dry run: show what would be imported without storing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Manage agent keys (two-tier auth: agents get token proxy access only)
    AgentKey {
        #[command(subcommand)]
        action: AgentKeyAction,
    },
    /// Launch interactive TUI
    Tui,
}

#[derive(Subcommand)]
enum AgentKeyAction {
    /// Generate a new agent key (shown once, save it immediately)
    Generate {
        /// Agent identifier (e.g. ci-bot, deploy-agent, my-app)
        agent_id: String,
        /// Optional description
        #[arg(short, long, default_value = "")]
        description: String,
        /// Scopes for secret access (e.g. "github/*", "aws/api-key", "*")
        #[arg(long)]
        scope: Vec<String>,
    },
    /// List all agent keys (active and revoked)
    List,
    /// Revoke an agent key (permanently disables it)
    Revoke {
        /// Agent identifier to revoke
        agent_id: String,
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cred=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init().await,
        Commands::Recover { from } => cmd_recover(&from).await,
        // Agent key management: no YubiKey needed
        Commands::AgentKey { action } => cmd_agent_key(action).await,
        // All other commands need the YubiKey
        cmd => {
            let store = unlock_store()?;
            match cmd {
                Commands::Store { service, key, secret_type } => {
                    cmd_store(&store, &service, &key, &secret_type).await
                }
                Commands::Get { service, key, field, raw } => {
                    cmd_get(&store, &service, &key, field.as_deref(), raw).await
                }
                Commands::List { service } => {
                    cmd_list(&store, service.as_deref()).await
                }
                Commands::Delete { service, key, yes } => {
                    cmd_delete(&store, &service, &key, yes).await
                }
                Commands::Import { dry_run } => cmd_import(&store, dry_run).await,
                Commands::Tui => cmd_tui(store).await,
                Commands::Init | Commands::Recover { .. } | Commands::AgentKey { .. } => unreachable!(),
            }
        }
    }
}

/// Derive the master key from YubiKey and create an unlocked store.
fn unlock_store() -> Result<CredStore> {
    let config_dir = config_dir();
    let challenge_path = config_dir.join("challenge");

    if !challenge_path.exists() {
        anyhow::bail!(
            "cred not initialized. Run `cred init` first to set up YubiKey encryption."
        );
    }

    eprintln!("unlocking with YubiKey...");
    let key = yubikey::derive_master_key()
        .context("failed to derive key from YubiKey -- is it plugged in?")?;
    eprintln!("unlocked.");

    CredStore::new(key)
}

// ---------------------------------------------------------------------------
// Init ceremony
// ---------------------------------------------------------------------------

async fn cmd_init() -> Result<()> {
    let config_dir = config_dir();
    let challenge_path = config_dir.join("challenge");

    if challenge_path.exists() {
        eprintln!("WARNING: cred is already initialized.");
        eprintln!("Re-initializing will generate a NEW encryption key.");
        eprintln!("All existing encrypted credentials will become UNREADABLE.");
        eprintln!();
        print!("continue? this is destructive. [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("cancelled");
            return Ok(());
        }
    }

    // Step 1: Check YubiKey is present
    eprintln!("checking for YubiKey...");
    let info = yubikey::device_info()
        .context("no YubiKey detected -- plug one in and try again")?;
    eprintln!("{}", info.trim());

    // Step 2: Generate HMAC secret
    let secret = crypto::generate_hmac_secret();
    let secret_hex = hex::encode(&secret);

    // Step 3: Show the secret ONCE for paper backup
    eprintln!();
    eprintln!("=== HMAC SECRET (write this down NOW, it will not be shown again) ===");
    eprintln!();
    eprintln!("  {}", secret_hex);
    eprintln!();
    eprintln!("This 40-character hex string is your master secret.");
    eprintln!("Store it in: Bitwarden secure note, paper in a safe, USB drive.");
    eprintln!("If all YubiKeys are lost, this is the ONLY way to recover.");
    eprintln!("======================================================================");
    eprintln!();

    print!("have you written it down? [y/N] ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("cancelled -- secret was NOT programmed");
        return Ok(());
    }

    // Step 4: Program the YubiKey
    eprintln!("programming YubiKey slot 2 with HMAC-SHA1 secret...");
    yubikey::program_hmac_secret(&secret)
        .context("failed to program YubiKey")?;
    eprintln!("YubiKey programmed.");

    // Step 5: Generate challenge (needed for recovery bundle)
    let challenge = yubikey::get_or_create_challenge()?;

    // Step 6: Create recovery file (v2: includes challenge)
    eprintln!();
    eprintln!("creating recovery file...");
    let passphrase = rpassword::read_password_from_tty(Some("recovery passphrase: "))
        .context("failed to read passphrase")?;
    let confirm = rpassword::read_password_from_tty(Some("confirm passphrase: "))
        .context("failed to read passphrase")?;

    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }
    if passphrase.len() < 20 {
        anyhow::bail!("passphrase too short (minimum 20 characters). use a memorable phrase.");
    }

    let recovery_data = crypto::encrypt_recovery_v2(&passphrase, &secret, &challenge)?;
    std::fs::create_dir_all(&config_dir)?;
    let recovery_path = config_dir.join("recovery.enc");
    std::fs::write(&recovery_path, &recovery_data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&recovery_path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("recovery file written to: {}", recovery_path.display());
    eprintln!("copy this to your USB drive and/or another safe location.");

    // Step 7: Verify the whole chain works
    eprintln!();
    eprintln!("verifying encryption chain...");
    let key = yubikey::derive_master_key()?;
    let test_plaintext = b"cred-init-verification-test";
    let encrypted = crypto::encrypt(&key, test_plaintext)?;
    let decrypted = crypto::decrypt(&key, &encrypted)?;
    assert_eq!(decrypted, test_plaintext, "encryption verification failed");
    eprintln!("verification passed.");

    eprintln!();
    eprintln!("cred initialized successfully.");
    eprintln!("you can now use: cred store <service> <key>");
    eprintln!();
    eprintln!("NEXT STEPS:");
    eprintln!("  1. Copy recovery.enc to your USB boot drive");
    eprintln!("  2. Store the hex secret in Bitwarden");
    eprintln!("  3. Program your other YubiKeys with the same secret:");
    eprintln!("     sudo python3 -c \"from ykman._cli.__main__ import main; import sys; sys.argv = ['ykman', 'otp', 'chalresp', '2', '--force', '<secret_hex>']; main()\"");
    eprintln!("  4. Store a secret: cred store github api-key");

    Ok(())
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

async fn cmd_recover(from: &str) -> Result<()> {
    let path = shellexpand(from);

    if !std::path::Path::new(&path).exists() {
        anyhow::bail!("recovery file not found: {}", path);
    }

    eprintln!("reading recovery file: {}", path);
    let data = std::fs::read(&path)?;

    let passphrase = rpassword::read_password_from_tty(Some("recovery passphrase: "))
        .context("failed to read passphrase")?;

    let (secret, recovered_challenge) = crypto::decrypt_recovery_v2(&passphrase, &data)
        .context("decryption failed -- wrong passphrase?")?;

    eprintln!("secret recovered ({} bytes)", secret.len());
    if let Some(ref challenge) = recovered_challenge {
        eprintln!("challenge file recovered ({} bytes)", challenge.len());
    } else {
        eprintln!("WARNING: v1 recovery file -- no challenge included.");
        eprintln!("if your challenge file (~/.config/cred/challenge) is lost,");
        eprintln!("you will need to re-encrypt all secrets after recovery.");
    }
    eprintln!();

    // Check if YubiKey is present for programming
    if yubikey::device_info().is_ok() {
        print!("YubiKey detected. Program it with the recovered secret? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("y") {
            yubikey::program_hmac_secret(&secret)?;
            eprintln!("YubiKey programmed.");

            // Restore challenge file if we have it
            if let Some(ref challenge) = recovered_challenge {
                let config_dir = std::env::var("XDG_CONFIG_HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| {
                        let home = std::env::var("HOME")
                            .or_else(|_| std::env::var("USERPROFILE"))
                            .unwrap_or_else(|_| ".".to_string());
                        std::path::PathBuf::from(home).join(".config")
                    })
                    .join("cred");
                std::fs::create_dir_all(&config_dir)?;
                let challenge_path = config_dir.join("challenge");
                std::fs::write(&challenge_path, challenge)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&challenge_path, std::fs::Permissions::from_mode(0o600))?;
                }
                eprintln!("challenge file restored.");
            } else {
                let _challenge = yubikey::get_or_create_challenge()?;
                eprintln!("WARNING: no challenge in recovery bundle -- generated new challenge.");
                eprintln!("existing secrets encrypted with the old challenge will be undecryptable.");
            }
            eprintln!("ready to use.");
            return Ok(());
        }
    }

    // If no YubiKey or user declined, just show the hex
    eprintln!("HMAC secret (hex): {}", hex::encode(&secret));
    eprintln!("program a YubiKey manually:");
    eprintln!("  ykman otp chalresp 2 --force {}", hex::encode(&secret));

    Ok(())
}

// ---------------------------------------------------------------------------
// Bulk import
// ---------------------------------------------------------------------------

async fn cmd_import(store: &CredStore, dry_run: bool) -> Result<()> {
    eprintln!("reading secrets from stdin (one per line)");
    eprintln!("format: service<TAB>key<TAB>value");
    eprintln!("lines starting with # are ignored");
    eprintln!("press Ctrl-D when done");
    if dry_run {
        eprintln!("(dry run -- nothing will be stored)");
    }
    eprintln!();

    let stdin = io::stdin();
    let mut imported = 0u32;
    let mut skipped = 0u32;
    let mut errors = 0u32;

    for (lineno, line) in stdin.lock().lines().enumerate() {
        let line = line.context("failed to read stdin")?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() != 3 {
            eprintln!(
                "  line {}: skipping (expected 3 tab-separated fields, got {}): {}",
                lineno + 1,
                parts.len(),
                &line[..line.len().min(40)]
            );
            skipped += 1;
            continue;
        }

        let (service, key, value) = (parts[0].trim(), parts[1].trim(), parts[2].trim());

        if service.is_empty() || key.is_empty() || value.is_empty() {
            eprintln!("  line {}: skipping (empty field)", lineno + 1);
            skipped += 1;
            continue;
        }

        if dry_run {
            eprintln!(
                "  [dry run] would store: {}/{} ({} chars)",
                service,
                key,
                value.len()
            );
            imported += 1;
        } else {
            let secret = Secret::new(service, key, SecretValue::ApiKey {
                key: value.to_string(),
                url: None,
                notes: None,
            });
            match store.store(&secret).await {
                Ok(id) => {
                    eprintln!("  stored: {}/{} (engram_id={})", service, key, id);
                    imported += 1;
                }
                Err(e) => {
                    eprintln!("  ERROR storing {}/{}: {}", service, key, e);
                    errors += 1;
                }
            }
        }
    }

    eprintln!();
    if dry_run {
        eprintln!(
            "dry run complete: {} would be imported, {} skipped",
            imported, skipped
        );
    } else {
        eprintln!(
            "import complete: {} stored, {} skipped, {} errors",
            imported, skipped, errors
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Agent key management (no YubiKey required)
// ---------------------------------------------------------------------------

async fn cmd_agent_key(action: AgentKeyAction) -> Result<()> {
    match action {
        AgentKeyAction::Generate {
            agent_id,
            description,
            scope,
        } => cmd_agent_key_generate(&agent_id, &description, scope).await,
        AgentKeyAction::List => cmd_agent_key_list().await,
        AgentKeyAction::Revoke { agent_id, yes } => {
            cmd_agent_key_revoke(&agent_id, yes).await
        }
    }
}

async fn cmd_agent_key_generate(agent_id: &str, description: &str, scopes: Vec<String>) -> Result<()> {
    // Validate agent_id: alphanumeric + hyphens only
    if agent_id.is_empty() {
        anyhow::bail!("agent_id cannot be empty");
    }
    if !agent_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("agent_id must contain only alphanumeric characters, hyphens, and underscores");
    }

    let mut store = agent_keys::AgentKeyStore::load()?;
    let key = store.generate(agent_id, description, scopes)?;

    eprintln!();
    eprintln!("=== AGENT KEY GENERATED ===");
    eprintln!();
    eprintln!("  Agent:  {}", agent_id);
    eprintln!("  Key:    {}", key);
    eprintln!();
    eprintln!("SAVE THIS KEY NOW. It will NOT be shown again.");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  curl http://localhost:4400/secret/myservice/mykey \\");
    eprintln!("    -H \"Authorization: Bearer {}\"", key);
    eprintln!("===========================");

    Ok(())
}

async fn cmd_agent_key_list() -> Result<()> {
    let store = agent_keys::AgentKeyStore::load()?;
    let keys = store.list();

    if keys.is_empty() {
        println!("no agent keys configured");
        println!("generate one with: cred agent-key generate <agent_id>");
        return Ok(());
    }

    // Column widths
    let max_id = keys.iter().map(|k| k.id.len()).max().unwrap_or(8).max(8);
    let max_desc = keys
        .iter()
        .map(|k| k.description.len())
        .max()
        .unwrap_or(11)
        .max(11)
        .min(30);

    println!(
        "{:<width_id$}  {:<10}  {:<8}  {:<20}  {:<20}  {}",
        "AGENT ID",
        "KEY PREFIX",
        "STATUS",
        "CREATED",
        "LAST USED",
        "DESCRIPTION",
        width_id = max_id,
    );
    println!(
        "{:-<width_id$}  {:-<10}  {:-<8}  {:-<20}  {:-<20}  {:-<width_desc$}",
        "",
        "",
        "",
        "",
        "",
        "",
        width_id = max_id,
        width_desc = max_desc,
    );

    for key in &keys {
        let prefix = if key.key.len() >= 8 {
            format!("{}...", &key.key[..8])
        } else {
            "???".to_string()
        };
        let status = if key.revoked { "REVOKED" } else { "active" };
        let created = key.created_at.format("%Y-%m-%d %H:%M").to_string();
        let last_used = key
            .last_used
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());
        let desc = if key.description.len() > 30 {
            format!("{}...", &key.description[..27])
        } else {
            key.description.clone()
        };

        println!(
            "{:<width_id$}  {:<10}  {:<8}  {:<20}  {:<20}  {}",
            key.id,
            prefix,
            status,
            created,
            last_used,
            desc,
            width_id = max_id,
        );
    }

    let active = keys.iter().filter(|k| !k.revoked).count();
    let revoked = keys.len() - active;
    println!("\n{} key(s) ({} active, {} revoked)", keys.len(), active, revoked);

    Ok(())
}

async fn cmd_agent_key_revoke(agent_id: &str, skip_confirm: bool) -> Result<()> {
    if !skip_confirm {
        print!("revoke agent key '{}'? This is permanent. [y/N] ", agent_id);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("cancelled");
            return Ok(());
        }
    }

    let mut store = agent_keys::AgentKeyStore::load()?;
    store.revoke(agent_id)?;
    println!("revoked agent key for '{}'", agent_id);
    println!("the agent can no longer authenticate to credd.");

    Ok(())
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

fn prompt(label: &str) -> Result<String> {
    print!("{}: ", label);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn prompt_secret(label: &str) -> Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        rpassword::read_password_from_tty(Some(&format!("{}: ", label)))
            .context("failed to read secret")
    } else {
        // Piped input -- just read a line
        eprint!("{}: ", label);
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        Ok(buf.trim().to_string())
    }
}

async fn cmd_store(store: &CredStore, service: &str, key: &str, secret_type: &str) -> Result<()> {
    if let Err(msg) = crate::types::validate_name(service, "service") {
        anyhow::bail!("{}", msg);
    }
    if let Err(msg) = crate::types::validate_name(key, "key") {
        anyhow::bail!("{}", msg);
    }

    let value = match secret_type {
        "login" => {
            let url = prompt("url")?;
            let username = prompt("username")?;
            let password = prompt_secret("password")?;
            let totp_raw = prompt("totp_seed (leave blank if none)")?;
            let totp_seed = if totp_raw.is_empty() { None } else { Some(totp_raw) };
            if url.is_empty() || username.is_empty() || password.is_empty() {
                anyhow::bail!("url, username, and password are required");
            }
            SecretValue::Login { url, username, password, totp_seed }
        }
        "api-key" | "apikey" => {
            let key_val = prompt_secret("key")?;
            if key_val.is_empty() {
                anyhow::bail!("key cannot be empty");
            }
            let url_raw = prompt("url (leave blank if none)")?;
            let url = if url_raw.is_empty() { None } else { Some(url_raw) };
            SecretValue::ApiKey { key: key_val, url, notes: None }
        }
        "oauth-app" | "oauthapp" => {
            let client_id = prompt("client_id")?;
            let client_secret = prompt_secret("client_secret")?;
            if client_id.is_empty() || client_secret.is_empty() {
                anyhow::bail!("client_id and client_secret are required");
            }
            let redirect_raw = prompt("redirect_url (leave blank if none)")?;
            let redirect_url = if redirect_raw.is_empty() { None } else { Some(redirect_raw) };
            SecretValue::OAuthApp { client_id, client_secret, redirect_url, scopes: None }
        }
        "ssh-key" | "sshkey" => {
            eprintln!("paste private key (end with a line containing only '---END---'):");
            let mut private_key = String::new();
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                if line.trim() == "---END---" { break; }
                private_key.push_str(&line);
                private_key.push('\n');
            }
            if private_key.trim().is_empty() {
                anyhow::bail!("private key cannot be empty");
            }
            let passphrase_raw = prompt_secret("passphrase (leave blank if none)")?;
            let passphrase = if passphrase_raw.is_empty() { None } else { Some(passphrase_raw) };
            SecretValue::SshKey { private_key, public_key: None, passphrase }
        }
        "note" => {
            let content = prompt_secret("content")?;
            if content.is_empty() {
                anyhow::bail!("content cannot be empty");
            }
            SecretValue::Note { content }
        }
        "environment" | "env" => {
            eprintln!("enter env vars (KEY=VALUE, one per line, blank line to finish):");
            let mut vars = std::collections::HashMap::new();
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() { break; }
                if let Some((k, v)) = line.split_once('=') {
                    vars.insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    eprintln!("  skipping invalid line (expected KEY=VALUE): {}", line);
                }
            }
            if vars.is_empty() {
                anyhow::bail!("no env vars entered");
            }
            SecretValue::Environment { vars }
        }
        other => {
            anyhow::bail!("unknown secret type '{}'. Valid types: api-key, login, oauth-app, ssh-key, note, environment", other);
        }
    };

    let secret = Secret::new(service, key, value);
    let id = store.store(&secret).await?;
    println!("stored {}/{} ({}) engram_id={}", service, key, secret_type, id);
    Ok(())
}

async fn cmd_get(store: &CredStore, service: &str, key: &str, field: Option<&str>, raw: bool) -> Result<()> {
    let secret = store.get(service, key).await?;

    if let Some(field_name) = field {
        // Extract specific field
        let val = secret.value.get_field(field_name)
            .ok_or_else(|| anyhow::anyhow!("field '{}' not found in {}/{} (type: {})", field_name, service, key, secret.value.type_name()))?;
        if raw {
            print!("{}", val);
            io::stdout().flush()?;
        } else {
            println!("{}/{}.{} = {}", secret.service, secret.key, field_name, val);
        }
    } else if raw {
        // Bare raw: try bare_value, else serialize the whole value as JSON
        match secret.value.bare_value() {
            Some(v) => {
                print!("{}", v);
                io::stdout().flush()?;
            }
            None => {
                let json = serde_json::to_string(&secret.value)?;
                print!("{}", json);
                io::stdout().flush()?;
            }
        }
    } else {
        // Pretty print all fields
        println!("service:  {}", secret.service);
        println!("key:      {}", secret.key);
        println!("type:     {}", secret.value.type_name());
        println!("fields:   {}", secret.value.field_names().join(", "));
        println!("preview:  {}", secret.value.redacted_preview());
        if let Some(id) = secret.engram_id {
            println!("engram:   #{}", id);
        }
        println!();
        println!("use --field <name> to extract a specific value");
        println!("use --raw to get bare JSON or single field value");
    }
    Ok(())
}

async fn cmd_list(store: &CredStore, service_filter: Option<&str>) -> Result<()> {
    let secrets = store.list_all().await?;
    let filtered: Vec<_> = match service_filter {
        Some(svc) => secrets.into_iter().filter(|s| s.service == svc).collect(),
        None => secrets,
    };

    if filtered.is_empty() {
        println!("no secrets stored");
        return Ok(());
    }

    // Column widths
    let max_svc = filtered.iter().map(|s| s.service.len()).max().unwrap_or(7).max(7);
    let max_key = filtered.iter().map(|s| s.key.len()).max().unwrap_or(3).max(3);
    let max_type = filtered.iter().map(|s| s.value.type_name().len()).max().unwrap_or(4).max(4);

    println!(
        "{:<width_s$}  {:<width_k$}  {:<width_t$}  {}",
        "SERVICE",
        "KEY",
        "TYPE",
        "PREVIEW",
        width_s = max_svc,
        width_k = max_key,
        width_t = max_type,
    );
    println!(
        "{:-<width_s$}  {:-<width_k$}  {:-<width_t$}  {:-<30}",
        "",
        "",
        "",
        "",
        width_s = max_svc,
        width_k = max_key,
        width_t = max_type,
    );

    for secret in &filtered {
        println!(
            "{:<width_s$}  {:<width_k$}  {:<width_t$}  {}",
            secret.service,
            secret.key,
            secret.value.type_name(),
            secret.value.redacted_preview(),
            width_s = max_svc,
            width_k = max_key,
            width_t = max_type,
        );
    }

    println!("\n{} secret(s)", filtered.len());
    Ok(())
}

async fn cmd_delete(store: &CredStore, service: &str, key: &str, skip_confirm: bool) -> Result<()> {
    if !skip_confirm {
        print!("delete {}/{}? [y/N] ", service, key);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("cancelled");
            return Ok(());
        }
    }

    store.delete(service, key).await?;
    println!("deleted {}/{}", service, key);
    Ok(())
}

// ---------------------------------------------------------------------------
// TUI
// ---------------------------------------------------------------------------

struct TuiApp {
    store: Arc<CredStore>,
    secrets: Vec<Secret>,
    table_state: TableState,
    mode: TuiMode,
    input_buf: String,
    input_field: InputField,
    status_msg: String,
    show_values: bool,
    filter: String,
}

#[derive(PartialEq)]
enum TuiMode {
    Normal,
    Adding,
    Filtering,
    Confirm,
    Detail,
}

#[derive(PartialEq)]
enum InputField {
    Service,
    Key,
    Value,
}

impl TuiApp {
    fn new(store: Arc<CredStore>) -> Self {
        Self {
            store,
            secrets: Vec::new(),
            table_state: TableState::default(),
            mode: TuiMode::Normal,
            input_buf: String::new(),
            input_field: InputField::Service,
            status_msg: String::new(),
            show_values: false,
            filter: String::new(),
        }
    }

    async fn refresh(&mut self) {
        match self.store.list_all().await {
            Ok(secrets) => {
                self.secrets = secrets;
                if self.secrets.is_empty() {
                    self.table_state.select(None);
                } else if self.table_state.selected().is_none() {
                    self.table_state.select(Some(0));
                }
            }
            Err(e) => {
                self.status_msg = format!("error: {}", e);
            }
        }
    }

    fn filtered_secrets(&self) -> Vec<&Secret> {
        if self.filter.is_empty() {
            self.secrets.iter().collect()
        } else {
            let f = self.filter.to_lowercase();
            self.secrets
                .iter()
                .filter(|s| {
                    s.service.to_lowercase().contains(&f)
                        || s.key.to_lowercase().contains(&f)
                })
                .collect()
        }
    }

    fn selected_secret(&self) -> Option<&Secret> {
        let filtered = self.filtered_secrets();
        self.table_state
            .selected()
            .and_then(|i| filtered.get(i).copied())
    }
}

async fn cmd_tui(store: CredStore) -> Result<()> {
    let store = Arc::new(store);
    let mut app = TuiApp::new(store);
    app.refresh().await;

    // Terminal setup
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Temp buffers for add flow
    let mut add_service = String::new();
    let mut add_key = String::new();

    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match app.mode {
                    TuiMode::Normal => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            let filtered = app.filtered_secrets();
                            if !filtered.is_empty() {
                                let i = app
                                    .table_state
                                    .selected()
                                    .map(|i| (i + 1) % filtered.len())
                                    .unwrap_or(0);
                                app.table_state.select(Some(i));
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            let filtered = app.filtered_secrets();
                            if !filtered.is_empty() {
                                let i = app
                                    .table_state
                                    .selected()
                                    .map(|i| {
                                        if i == 0 {
                                            filtered.len() - 1
                                        } else {
                                            i - 1
                                        }
                                    })
                                    .unwrap_or(0);
                                app.table_state.select(Some(i));
                            }
                        }
                        KeyCode::Char('a') => {
                            app.mode = TuiMode::Adding;
                            app.input_field = InputField::Service;
                            app.input_buf.clear();
                            add_service.clear();
                            add_key.clear();
                            app.status_msg = "enter service name".to_string();
                        }
                        KeyCode::Char('d') => {
                            if app.selected_secret().is_some() {
                                app.mode = TuiMode::Confirm;
                                app.status_msg = "delete? (y/n)".to_string();
                            }
                        }
                        KeyCode::Char('v') => {
                            app.show_values = !app.show_values;
                            app.status_msg = if app.show_values {
                                "values visible".to_string()
                            } else {
                                "values hidden".to_string()
                            };
                        }
                        KeyCode::Char('/') => {
                            app.mode = TuiMode::Filtering;
                            app.input_buf = app.filter.clone();
                            app.status_msg = "filter:".to_string();
                        }
                        KeyCode::Enter => {
                            if app.selected_secret().is_some() {
                                app.mode = TuiMode::Detail;
                            }
                        }
                        KeyCode::Char('r') => {
                            app.refresh().await;
                            app.status_msg = "refreshed".to_string();
                        }
                        _ => {}
                    },

                    TuiMode::Adding => match key.code {
                        KeyCode::Esc => {
                            app.input_buf.zeroize();
                            add_service.zeroize();
                            add_key.zeroize();
                            app.mode = TuiMode::Normal;
                            app.status_msg.clear();
                        }
                        KeyCode::Enter => match app.input_field {
                            InputField::Service => {
                                if app.input_buf.is_empty() {
                                    app.status_msg = "service name cannot be empty".to_string();
                                } else {
                                    add_service = app.input_buf.clone();
                                    app.input_buf.clear();
                                    app.input_field = InputField::Key;
                                    app.status_msg = "enter key name".to_string();
                                }
                            }
                            InputField::Key => {
                                if app.input_buf.is_empty() {
                                    app.status_msg = "key name cannot be empty".to_string();
                                } else {
                                    add_key = app.input_buf.clone();
                                    app.input_buf.clear();
                                    app.input_field = InputField::Value;
                                    app.status_msg = "enter api-key value".to_string();
                                }
                            }
                            InputField::Value => {
                                if app.input_buf.is_empty() {
                                    app.status_msg = "value cannot be empty".to_string();
                                } else {
                                    let secret = Secret::new(
                                        &add_service,
                                        &add_key,
                                        SecretValue::ApiKey {
                                            key: app.input_buf.clone(),
                                            url: None,
                                            notes: None,
                                        },
                                    );
                                    // Zeroize sensitive data immediately before async store
                                    app.input_buf.zeroize();
                                    match app.store.store(&secret).await {
                                        Ok(id) => {
                                            app.status_msg = format!(
                                                "stored {}/{} (id={})",
                                                add_service, add_key, id
                                            );
                                            app.refresh().await;
                                        }
                                        Err(e) => {
                                            app.status_msg = format!("error: {}", e);
                                        }
                                    }
                                    add_service.zeroize();
                                    add_key.zeroize();
                                    app.mode = TuiMode::Normal;
                                }
                            }
                        },
                        KeyCode::Backspace => {
                            app.input_buf.pop();
                        }
                        KeyCode::Char(c) => {
                            app.input_buf.push(c);
                        }
                        _ => {}
                    },

                    TuiMode::Filtering => match key.code {
                        KeyCode::Esc => {
                            app.filter.clear();
                            app.mode = TuiMode::Normal;
                            app.status_msg.clear();
                            app.table_state.select(if app.secrets.is_empty() {
                                None
                            } else {
                                Some(0)
                            });
                        }
                        KeyCode::Enter => {
                            app.filter = app.input_buf.clone();
                            app.mode = TuiMode::Normal;
                            app.status_msg = if app.filter.is_empty() {
                                String::new()
                            } else {
                                format!("filter: {}", app.filter)
                            };
                            app.table_state.select(if app.filtered_secrets().is_empty() {
                                None
                            } else {
                                Some(0)
                            });
                        }
                        KeyCode::Backspace => {
                            app.input_buf.pop();
                        }
                        KeyCode::Char(c) => {
                            app.input_buf.push(c);
                        }
                        _ => {}
                    },

                    TuiMode::Confirm => match key.code {
                        KeyCode::Char('y') => {
                            if let Some(secret) = app.selected_secret() {
                                let svc = secret.service.clone();
                                let key = secret.key.clone();
                                match app.store.delete(&svc, &key).await {
                                    Ok(()) => {
                                        app.status_msg = format!("deleted {}/{}", svc, key);
                                        app.refresh().await;
                                    }
                                    Err(e) => {
                                        app.status_msg = format!("error: {}", e);
                                    }
                                }
                            }
                            app.mode = TuiMode::Normal;
                        }
                        _ => {
                            app.mode = TuiMode::Normal;
                            app.status_msg = "cancelled".to_string();
                        }
                    },

                    TuiMode::Detail => match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                            app.mode = TuiMode::Normal;
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn draw_ui(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),   // table
            Constraint::Length(3), // status / input
        ])
        .split(f.area());

    draw_header(f, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_status(f, app, chunks[2]);

    // Modal overlay for detail view
    if app.mode == TuiMode::Detail {
        if let Some(secret) = app.selected_secret() {
            draw_detail_modal(f, secret, app.show_values);
        }
    }
}

fn draw_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled("cred", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::styled("a", Style::default().fg(Color::Yellow)),
        Span::raw("dd "),
        Span::styled("d", Style::default().fg(Color::Yellow)),
        Span::raw("elete "),
        Span::styled("v", Style::default().fg(Color::Yellow)),
        Span::raw("alues "),
        Span::styled("/", Style::default().fg(Color::Yellow)),
        Span::raw("filter "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw("efresh "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw("uit"),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));

    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let filtered = app.filtered_secrets();

    let header = Row::new(vec![
        Cell::from("SERVICE").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Cell::from("KEY").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Cell::from("TYPE").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Cell::from("PREVIEW").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = filtered
        .iter()
        .map(|secret| {
            let preview = if app.show_values {
                secret.value.redacted_preview()
            } else {
                secret.value.type_name().to_string()
            };
            Row::new(vec![
                Cell::from(secret.service.clone()).style(Style::default().fg(Color::Green)),
                Cell::from(secret.key.clone()),
                Cell::from(secret.value.type_name()).style(Style::default().fg(Color::Yellow)),
                Cell::from(preview).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(35),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(if app.filter.is_empty() {
                    format!(" secrets ({}) ", app.secrets.len())
                } else {
                    format!(
                        " secrets ({}/{}) [{}] ",
                        filtered.len(),
                        app.secrets.len(),
                        app.filter
                    )
                }),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_status(f: &mut Frame, app: &TuiApp, area: Rect) {
    let content = match app.mode {
        TuiMode::Adding => {
            let field_name = match app.input_field {
                InputField::Service => "service",
                InputField::Key => "key",
                InputField::Value => "value",
            };
            let display = if app.input_field == InputField::Value {
                "*".repeat(app.input_buf.len())
            } else {
                app.input_buf.clone()
            };
            format!("[add] {}: {}|", field_name, display)
        }
        TuiMode::Filtering => {
            format!("/{}", app.input_buf)
        }
        _ => app.status_msg.clone(),
    };

    let status = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(status, area);
}

fn draw_detail_modal(f: &mut Frame, secret: &Secret, show_value: bool) {
    let area = f.area();
    let modal_width = 60.min(area.width - 4);
    let modal_height = 10.min(area.height - 4);
    let modal_area = Rect::new(
        (area.width - modal_width) / 2,
        (area.height - modal_height) / 2,
        modal_width,
        modal_height,
    );

    f.render_widget(Clear, modal_area);

    let preview = if show_value {
        secret.value.redacted_preview()
    } else {
        "[hidden - press v to show]".to_string()
    };

    let fields_str = secret.value.field_names().join(", ");

    let lines = vec![
        Line::from(vec![
            Span::styled("Service: ", Style::default().fg(Color::Cyan)),
            Span::raw(&secret.service),
        ]),
        Line::from(vec![
            Span::styled("Key:     ", Style::default().fg(Color::Cyan)),
            Span::raw(&secret.key),
        ]),
        Line::from(vec![
            Span::styled("Type:    ", Style::default().fg(Color::Cyan)),
            Span::raw(secret.value.type_name()),
        ]),
        Line::from(vec![
            Span::styled("Fields:  ", Style::default().fg(Color::Cyan)),
            Span::raw(&fields_str),
        ]),
        Line::from(vec![
            Span::styled("Preview: ", Style::default().fg(Color::Cyan)),
            Span::raw(preview),
        ]),
        Line::from(vec![
            Span::styled("Engram:  ", Style::default().fg(Color::Cyan)),
            Span::raw(
                secret.engram_id
                    .map(|id| format!("#{}", id))
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "press ESC to close, v to toggle values",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" detail "),
    );
    f.render_widget(detail, modal_area);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn config_dir() -> std::path::PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
        })
        .join("cred")
}

fn shellexpand(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    path.to_string()
}
