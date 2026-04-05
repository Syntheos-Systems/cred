use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Agent key types
// ---------------------------------------------------------------------------

/// A single agent key. Agents authenticate with this key to get restricted
/// access (auth proxy only, no plaintext credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKey {
    /// Unique identifier for the agent (e.g. "ci-bot", "deploy-agent", "my-app")
    pub id: String,
    /// 64-character hex string (32 random bytes)
    pub key: String,
    /// When this key was generated
    pub created_at: DateTime<Utc>,
    /// Last time this key was used for authentication
    pub last_used: Option<DateTime<Utc>>,
    /// Whether this key has been revoked
    pub revoked: bool,
    /// Optional description
    #[serde(default)]
    pub description: String,
    /// Scopes this agent can access. Each scope is "service/key" or "service/*".
    /// Empty means metadata-only access (no plaintext).
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Persistent store for agent keys. Saved to ~/.config/cred/agent-keys.json.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentKeyStore {
    pub keys: HashMap<String, AgentKey>,
    #[serde(skip)]
    path: PathBuf,
}

impl AgentKeyStore {
    /// Load agent keys from disk, or create empty store if file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = config_dir().join("agent-keys.json");
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let mut store: AgentKeyStore = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            store.path = path;
            info!("loaded {} agent key(s)", store.keys.len());
            Ok(store)
        } else {
            info!("no agent-keys.json found, starting fresh");
            Ok(Self {
                keys: HashMap::new(),
                path,
            })
        }
    }

    /// Load from a specific path (used by tests or custom configs).
    #[allow(dead_code)]
    pub fn load_from(path: PathBuf) -> Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let mut store: AgentKeyStore = serde_json::from_str(&content)?;
            store.path = path;
            Ok(store)
        } else {
            Ok(Self {
                keys: HashMap::new(),
                path,
            })
        }
    }

    /// Save agent keys to disk with restrictive permissions.
    pub fn save(&self) -> Result<()> {
        let dir = self.path.parent().unwrap();
        std::fs::create_dir_all(dir)?;

        let content = serde_json::to_string_pretty(&self)?;
        std::fs::write(&self.path, &content)?;

        // chmod 600 -- owner read/write only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!(
            "saved {} agent key(s) to {}",
            self.keys.len(),
            self.path.display()
        );
        Ok(())
    }

    /// Generate a new agent key. Returns the key string (shown once to the user).
    pub fn generate(&mut self, agent_id: &str, description: &str, scopes: Vec<String>) -> Result<String> {
        // Validate scope format: each must be "*", "service/*", or "service/key"
        for scope in &scopes {
            if scope == "*" {
                continue;
            }
            let parts: Vec<&str> = scope.splitn(2, '/').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                anyhow::bail!("invalid scope '{}': must be '*', 'service/*', or 'service/key'", scope);
            }
            // Validate the service part uses allowed characters
            if !parts[0].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
                anyhow::bail!("invalid scope '{}': service name contains invalid characters", scope);
            }
            // Key part can be "*" or a valid name
            if parts[1] != "*" && !parts[1].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
                anyhow::bail!("invalid scope '{}': key name contains invalid characters", scope);
            }
        }

        if self.keys.contains_key(agent_id) {
            let existing = &self.keys[agent_id];
            if !existing.revoked {
                anyhow::bail!(
                    "agent key '{}' already exists and is active. Revoke it first.",
                    agent_id
                );
            }
            // If revoked, we allow regeneration (replaces the old entry)
            warn!("replacing revoked key for '{}'", agent_id);
        }

        // Generate 32 cryptographically random bytes -> 64-char hex
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let key_hex = hex::encode(bytes);

        let agent_key = AgentKey {
            id: agent_id.to_string(),
            key: key_hex.clone(),
            created_at: Utc::now(),
            last_used: None,
            revoked: false,
            description: description.to_string(),
            scopes,
        };

        self.keys.insert(agent_id.to_string(), agent_key);
        self.save()?;

        info!("generated agent key for '{}'", agent_id);
        Ok(key_hex)
    }

    /// Validate a bearer token against all active agent keys.
    /// Returns the agent ID if valid. Uses constant-time comparison.
    pub fn validate(&self, bearer_token: &str) -> Option<String> {
        let token = bearer_token.trim();
        if token.is_empty() {
            return None;
        }

        for (id, agent_key) in &self.keys {
            if agent_key.revoked {
                continue;
            }
            if constant_time_eq(token.as_bytes(), agent_key.key.as_bytes()) {
                return Some(id.clone());
            }
        }

        None
    }

    /// Record that an agent key was used (updates last_used timestamp).
    pub fn touch(&mut self, agent_id: &str) {
        if let Some(key) = self.keys.get_mut(agent_id) {
            key.last_used = Some(Utc::now());
            // Best-effort save -- don't fail the request if disk write fails
            if let Err(e) = self.save() {
                warn!("failed to persist last_used for '{}': {}", agent_id, e);
            }
        }
    }

    /// Revoke an agent key. The key remains in the store (for audit) but
    /// can no longer authenticate.
    pub fn revoke(&mut self, agent_id: &str) -> Result<()> {
        let key = self
            .keys
            .get_mut(agent_id)
            .ok_or_else(|| anyhow::anyhow!("agent key '{}' not found", agent_id))?;

        if key.revoked {
            anyhow::bail!("agent key '{}' is already revoked", agent_id);
        }

        key.revoked = true;
        self.save()?;
        info!("revoked agent key for '{}'", agent_id);
        Ok(())
    }

    /// List all agent keys (active and revoked).
    pub fn list(&self) -> Vec<&AgentKey> {
        let mut keys: Vec<&AgentKey> = self.keys.values().collect();
        keys.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        keys
    }

    /// Count of active (non-revoked) keys.
    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.keys.values().filter(|k| !k.revoked).count()
    }

    /// Check if an agent has scope to read plaintext for a given service/key.
    pub fn has_scope(&self, agent_id: &str, service: &str, key: &str) -> bool {
        let agent = match self.keys.get(agent_id) {
            Some(a) if !a.revoked => a,
            _ => return false,
        };
        let exact = format!("{}/{}", service, key);
        let wildcard = format!("{}/*", service);
        agent.scopes.iter().any(|s| s == &exact || s == &wildcard || s == "*")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constant-time byte comparison to prevent timing attacks on key validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| PathBuf::from("."))
        })
        .join("cred")
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

/// Append a line to the audit log. Best-effort -- failures are warned but
/// don't block the request.
pub fn audit_log(agent_id: &str, action: &str, detail: &str) {
    let log_path = config_dir().join("audit.log");
    let timestamp = Utc::now().to_rfc3339();
    let line = format!(
        "{} agent={} action={} {}\n",
        timestamp, agent_id, action, detail
    );

    if let Err(e) = append_to_file(&log_path, &line) {
        warn!("audit log write failed: {}", e);
    }
}

fn append_to_file(path: &PathBuf, content: &str) -> Result<()> {
    use std::io::Write;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    // Set permissions on first create
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    file.write_all(content.as_bytes())?;
    Ok(())
}
