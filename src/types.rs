use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


// ---------------------------------------------------------------------------
// Secret value types
// ---------------------------------------------------------------------------

/// The actual secret payload. Tagged JSON for clean serialization.
/// Stored encrypted as the body of a [CRED:v3] Engram entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretValue {
    Login {
        url: String,
        username: String,
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp_seed: Option<String>,
    },
    ApiKey {
        key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    OAuthApp {
        client_id: String,
        client_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scopes: Option<Vec<String>>,
    },
    SshKey {
        private_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    Note {
        content: String,
    },
    Environment {
        vars: HashMap<String, String>,
    },
}

impl SecretValue {
    /// The type name for display and list output.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "Login",
            Self::ApiKey { .. } => "ApiKey",
            Self::OAuthApp { .. } => "OAuthApp",
            Self::SshKey { .. } => "SshKey",
            Self::Note { .. } => "Note",
            Self::Environment { .. } => "Environment",
        }
    }

    /// Field names for list display (values never shown).
    pub fn field_names(&self) -> Vec<String> {
        match self {
            Self::Login { totp_seed, .. } => {
                let mut f = vec!["url".to_string(), "username".to_string(), "password".to_string()];
                if totp_seed.is_some() { f.push("totp_seed".to_string()); }
                f
            }
            Self::ApiKey { url, notes, .. } => {
                let mut f = vec!["key".to_string()];
                if url.is_some() { f.push("url".to_string()); }
                if notes.is_some() { f.push("notes".to_string()); }
                f
            }
            Self::OAuthApp { redirect_url, scopes, .. } => {
                let mut f = vec!["client_id".to_string(), "client_secret".to_string()];
                if redirect_url.is_some() { f.push("redirect_url".to_string()); }
                if scopes.is_some() { f.push("scopes".to_string()); }
                f
            }
            Self::SshKey { public_key, passphrase, .. } => {
                let mut f = vec!["private_key".to_string()];
                if public_key.is_some() { f.push("public_key".to_string()); }
                if passphrase.is_some() { f.push("passphrase".to_string()); }
                f
            }
            Self::Note { .. } => vec!["content".to_string()],
            Self::Environment { vars } => vars.keys().cloned().collect(),
        }
    }

    /// One-line redacted preview for list display.
    pub fn redacted_preview(&self) -> String {
        match self {
            Self::Login { username, url, .. } => format!("{} @ {}", username, url),
            Self::ApiKey { key, .. } => format!("{}...{}", &key[..2.min(key.len())], &key[key.len().saturating_sub(2)..]),
            Self::OAuthApp { client_id, .. } => format!("client_id={}", client_id),
            Self::SshKey { .. } => "[private key]".to_string(),
            Self::Note { content } => format!("{}...", &content[..40.min(content.len())]),
            Self::Environment { vars } => {
                let names: Vec<_> = vars.keys().map(|k| format!("{}=***", k)).collect();
                names.join(", ")
            }
        }
    }

    /// Get a specific field value by name. Used for {{secret:svc/key.field}} substitution.
    /// Returns None if field doesn't exist.
    pub fn get_field(&self, field: &str) -> Option<String> {
        match self {
            Self::Login { url, username, password, totp_seed } => match field {
                "url" => Some(url.clone()),
                "username" => Some(username.clone()),
                "password" => Some(password.clone()),
                "totp_seed" => totp_seed.clone(),
                _ => None,
            },
            Self::ApiKey { key, url, notes } => match field {
                "key" => Some(key.clone()),
                "url" => url.clone(),
                "notes" => notes.clone(),
                _ => None,
            },
            Self::OAuthApp { client_id, client_secret, redirect_url, scopes } => match field {
                "client_id" => Some(client_id.clone()),
                "client_secret" => Some(client_secret.clone()),
                "redirect_url" => redirect_url.clone(),
                "scopes" => scopes.as_ref().map(|s| s.join(",")),
                _ => None,
            },
            Self::SshKey { private_key, public_key, passphrase } => match field {
                "private_key" => Some(private_key.clone()),
                "public_key" => public_key.clone(),
                "passphrase" => passphrase.clone(),
                _ => None,
            },
            Self::Note { content } => match field {
                "content" => Some(content.clone()),
                _ => None,
            },
            Self::Environment { vars } => vars.get(field).cloned(),
        }
    }

    /// Whether a bare {{secret:svc/key}} reference (no field) is valid for this type.
    /// Only ApiKey and Note support bare references.
    pub fn bare_value(&self) -> Option<String> {
        match self {
            Self::ApiKey { key, .. } => Some(key.clone()),
            Self::Note { content } => Some(content.clone()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Secret storage type
// ---------------------------------------------------------------------------

/// A stored secret. Replaces the old Credential type.
#[derive(Debug, Clone)]
pub struct Secret {
    pub service: String,
    pub key: String,
    pub value: SecretValue,
    pub engram_id: Option<u64>,
    pub created_at: Option<DateTime<Utc>>,
}

impl Secret {
    pub fn new(service: impl Into<String>, key: impl Into<String>, value: SecretValue) -> Self {
        Self {
            service: service.into(),
            key: key.into(),
            value,
            engram_id: None,
            created_at: Some(Utc::now()),
        }
    }
}

// ---------------------------------------------------------------------------
// Engram API types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct EngramStoreRequest {
    pub content: String,
    pub category: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub importance: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_static: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct EngramStoreResponse {
    #[allow(dead_code)]
    pub stored: bool,
    pub id: u64,
    #[allow(dead_code)]
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct EngramMemory {
    pub id: u64,
    pub content: String,
    #[allow(dead_code)]
    pub category: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub source: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub created_at: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub importance: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct EngramListResponse {
    pub results: Vec<EngramMemory>,
}

// ---------------------------------------------------------------------------
// HTTP API types (credd)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

/// Request body for POST /secret
#[derive(Debug, Deserialize)]
pub struct StoreSecretRequest {
    pub service: String,
    pub key: String,
    pub value: SecretValue,
}

/// Response for GET /secret/{svc}/{key}
#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub service: String,
    pub key: String,
    #[serde(rename = "type")]
    pub secret_type: String,
    pub value: SecretValue,
}

/// Response for agent-level secret access.
/// Returns the value only if the agent has explicit scope for this service/key.
/// Otherwise returns metadata only, with a field-substitution hint.
#[derive(Debug, Serialize)]
pub struct AgentSecretResponse {
    pub service: String,
    pub key: String,
    #[serde(rename = "type")]
    pub secret_type: String,
    pub field_names: Vec<String>,
    /// Only populated if the agent has scope for this service/key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretValue>,
    /// Hint when value is withheld
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Item in GET /secrets list response
#[derive(Debug, Serialize)]
pub struct SecretListItem {
    pub service: String,
    pub key: String,
    #[serde(rename = "type")]
    pub secret_type: String,
    pub field_names: Vec<String>,
    pub redacted_preview: String,
    pub engram_id: Option<u64>,
}

// ---------------------------------------------------------------------------
// Agent key management API types (unchanged)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum AuthLevel {
    Owner,
    Agent(String),
}

impl AuthLevel {
    pub fn is_owner(&self) -> bool { matches!(self, AuthLevel::Owner) }
    pub fn is_agent(&self) -> bool { matches!(self, AuthLevel::Agent(_)) }
    pub fn agent_id(&self) -> Option<&str> {
        match self { AuthLevel::Agent(id) => Some(id), AuthLevel::Owner => None }
    }
    pub fn display_name(&self) -> String {
        match self { AuthLevel::Owner => "owner".to_string(), AuthLevel::Agent(id) => format!("agent:{}", id) }
    }
}

#[derive(Debug, Deserialize)]
pub struct AgentKeyCreateRequest {
    pub agent_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentKeyCreateResponse {
    pub agent_id: String,
    pub key: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct AgentKeyListItem {
    pub id: String,
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
    pub description: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Validate a service or key name. Names must be 1-128 characters,
/// ASCII alphanumeric plus hyphen, underscore, and dot.
/// No slashes, equals, spaces, or control characters.
pub fn validate_name(name: &str, label: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{} cannot be empty", label));
    }
    if name.len() > 128 {
        return Err(format!("{} too long (max 128 characters)", label));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return Err(format!(
            "{} contains invalid characters (allowed: a-z, A-Z, 0-9, hyphen, underscore, dot)",
            label
        ));
    }
    Ok(())
}
