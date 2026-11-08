// SPDX-License-Identifier: MPL-2.0
//! Formally Verified Gatekeeper Core
//!
//! Replaces the Ada/SPARK gatekeeper with a native verified Rust engine,
//! certified through a quad-tier formal verification & model checking matrix:
//! - **Creusot** (Deductive verification via Why3 / Coq)
//! - **Verus** (SMT-based deductive verification via Z3)
//! - **Pearlite** (Functional specification contracts)
//! - **Kani** (Bounded model checking)

pub mod creusot;
pub mod kani;
pub mod pearlite;
pub mod verus;

use serde::{Deserialize, Serialize};

/// Linux capabilities evaluated by the gatekeeper (matching Ada Capability enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Capability {
    Chown = 0,
    DacOverride = 1,
    Fsetid = 2,
    Fowner = 3,
    Mknod = 4,
    NetRaw = 5,
    Setgid = 6,
    Setuid = 7,
    Setfcap = 8,
    Setpcap = 9,
    NetBindService = 10,
    SysChroot = 11,
    Kill = 12,
    AuditWrite = 13,
    NetAdmin = 14,
    SysAdmin = 15,
}

impl Capability {
    pub const ALL: [Capability; 16] = [
        Capability::Chown,
        Capability::DacOverride,
        Capability::Fsetid,
        Capability::Fowner,
        Capability::Mknod,
        Capability::NetRaw,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setfcap,
        Capability::Setpcap,
        Capability::NetBindService,
        Capability::SysChroot,
        Capability::Kill,
        Capability::AuditWrite,
        Capability::NetAdmin,
        Capability::SysAdmin,
    ];

    /// Parse an ASCII case-insensitive capability name, with or without `CAP_`.
    /// Returns `None` for names outside the supported capability set.
    pub fn from_name(name: &str) -> Option<Self> {
        let upper = name.to_ascii_uppercase();
        let stripped = upper.strip_prefix("CAP_").unwrap_or(&upper);
        match stripped {
            "CHOWN" => Some(Capability::Chown),
            "DAC_OVERRIDE" => Some(Capability::DacOverride),
            "FSETID" => Some(Capability::Fsetid),
            "FOWNER" => Some(Capability::Fowner),
            "MKNOD" => Some(Capability::Mknod),
            "NET_RAW" => Some(Capability::NetRaw),
            "SETGID" => Some(Capability::Setgid),
            "SETUID" => Some(Capability::Setuid),
            "SETFCAP" => Some(Capability::Setfcap),
            "SETPCAP" => Some(Capability::Setpcap),
            "NET_BIND_SERVICE" => Some(Capability::NetBindService),
            "SYS_CHROOT" => Some(Capability::SysChroot),
            "KILL" => Some(Capability::Kill),
            "AUDIT_WRITE" => Some(Capability::AuditWrite),
            "NET_ADMIN" => Some(Capability::NetAdmin),
            "SYS_ADMIN" => Some(Capability::SysAdmin),
            _ => None,
        }
    }
}

/// Bitmask set of capabilities for zero-allocation evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub mask: u16,
}

impl CapabilitySet {
    pub const EMPTY: Self = Self { mask: 0 };

    /// Default unprivileged capability set (matches Ada Default_Capabilities).
    pub fn default_capabilities() -> Self {
        let mut set = Self::EMPTY;
        for cap in Capability::ALL {
            if cap != Capability::NetAdmin && cap != Capability::SysAdmin {
                set.insert(cap);
            }
        }
        set
    }

    #[inline]
    pub const fn has(&self, cap: Capability) -> bool {
        (self.mask & (1 << (cap as u8))) != 0
    }

    #[inline]
    pub fn insert(&mut self, cap: Capability) {
        self.mask |= 1 << (cap as u8);
    }

    #[inline]
    pub fn remove(&mut self, cap: Capability) {
        self.mask &= !(1 << (cap as u8));
    }
}

/// Network privilege level (matches Ada Privilege_Level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    #[default]
    Unprivileged,
    Restricted,
    Admin,
}

impl PrivilegeLevel {
    /// Parse a case-insensitive network mode; `host` is an alias for `admin`.
    /// Unrecognized values select `Unprivileged`.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "restricted" => PrivilegeLevel::Restricted,
            "admin" | "host" => PrivilegeLevel::Admin,
            _ => PrivilegeLevel::Unprivileged,
        }
    }
}

/// Container configuration record (matches Ada Container_Config).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerConfig {
    pub is_privileged: bool,
    pub root_read_only: bool,
    pub capabilities: CapabilitySet,
    pub user_id: u32,
    pub user_namespace: bool,
    pub network_mode: PrivilegeLevel,
    pub no_new_privileges: bool,
    pub seccomp_enabled: bool,
}

impl Default for ContainerConfig {
    /// Return a nonprivileged configuration with UID 1000, a user namespace,
    /// read-only root, seccomp, no-new-privileges, and default capabilities.
    fn default() -> Self {
        Self {
            is_privileged: false,
            root_read_only: true,
            capabilities: CapabilitySet::default_capabilities(),
            user_id: 1000,
            user_namespace: true,
            network_mode: PrivilegeLevel::Unprivileged,
            no_new_privileges: true,
            seccomp_enabled: true,
        }
    }
}

/// Formal Ghost Predicate: Mathematical definition of "secure"
/// (Ported directly from Ada `function Is_Secure return Boolean with Ghost`).
/// Privileged configurations always satisfy this predicate. Otherwise, it checks
/// capability, UID, user namespace, and network policy; root filesystem and
/// seccomp settings do not affect the result.
#[inline]
pub fn is_secure(config: &ContainerConfig) -> bool {
    config.is_privileged
        || (!config.capabilities.has(Capability::SysAdmin)
            && (config.user_id > 0 || config.user_namespace)
            && (!config.capabilities.has(Capability::NetAdmin)
                || config.network_mode != PrivilegeLevel::Unprivileged)
            && (config.user_id > 0
                || config.no_new_privileges
                || config.user_namespace))
}

/// Validation result codes matching C ABI / Ada To_Exit_Code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ValidationResult {
    Valid = 0,
    InvalidCapabilities = 1,
    InvalidUserNamespace = 2,
    InvalidNetworkMode = 3,
    InvalidPrivilegeEscape = 4,
    ParseError = 5,
    InternalError = -1,
}

impl ValidationResult {
    /// Return the ABI status code: zero for success, 1–5 for policy or parse
    /// failures, and -1 for an internal error.
    pub fn to_exit_code(self) -> i32 {
        self as i32
    }

    /// Decode status codes 0–5; all other values map to `InternalError`.
    pub fn from_exit_code(code: i32) -> Self {
        match code {
            0 => ValidationResult::Valid,
            1 => ValidationResult::InvalidCapabilities,
            2 => ValidationResult::InvalidUserNamespace,
            3 => ValidationResult::InvalidNetworkMode,
            4 => ValidationResult::InvalidPrivilegeEscape,
            5 => ValidationResult::ParseError,
            _ => ValidationResult::InternalError,
        }
    }
}

/// Validate capability, UID, user namespace, and network policy.
///
/// Privileged configurations return `Valid` without checks. Otherwise, returns
/// the first failure in this order: `SysAdmin`, root without a user namespace,
/// then `NetAdmin` with unprivileged networking. Root filesystem and seccomp
/// settings are not checked.
/// POSTCONDITION: If result == Valid, then is_secure(config) == true.
pub fn validate_configuration(config: &ContainerConfig) -> ValidationResult {
    if config.is_privileged {
        return ValidationResult::Valid;
    }

    if config.capabilities.has(Capability::SysAdmin) {
        return ValidationResult::InvalidCapabilities;
    }

    if config.user_id == 0 && !config.user_namespace {
        return ValidationResult::InvalidUserNamespace;
    }

    if config.capabilities.has(Capability::NetAdmin)
        && config.network_mode == PrivilegeLevel::Unprivileged
    {
        return ValidationResult::InvalidNetworkMode;
    }

    if config.user_id == 0 && !config.no_new_privileges && !config.user_namespace {
        return ValidationResult::InvalidPrivilegeEscape;
    }

    ValidationResult::Valid
}

/// Check if a configuration satisfies all security policies.
#[inline]
pub fn is_valid_configuration(config: &ContainerConfig) -> bool {
    validate_configuration(config) == ValidationResult::Valid
}

/// Remove `SysAdmin`, enable a user namespace for root, and remove `NetAdmin`
/// when networking is unprivileged. Privileged configurations are unchanged.
/// POSTCONDITION: is_secure(config) == true.
pub fn apply_security_defaults(config: &mut ContainerConfig) {
    if !config.is_privileged {
        config.capabilities.remove(Capability::SysAdmin);

        if config.user_id == 0 {
            config.user_namespace = true;
        }

        if config.capabilities.has(Capability::NetAdmin)
            && config.network_mode == PrivilegeLevel::Unprivileged
        {
            config.capabilities.remove(Capability::NetAdmin);
        }

        if config.user_id == 0 && !config.user_namespace {
            config.no_new_privileges = true;
        }
    }
}

/// Human-readable error description matching Ada / C stub.
/// Codes outside 0–5 return the internal-error description.
pub fn get_error_message(code: i32) -> &'static str {
    match code {
        0 => "Configuration is valid and secure",
        1 => "SYS_ADMIN capability requires privileged mode",
        2 => "Root UID (0) requires user namespace to be enabled",
        3 => "NET_ADMIN capability requires Restricted or Admin network mode",
        4 => "Potential privilege escalation: set no_new_privileges or enable user namespace",
        5 => "Failed to parse container configuration",
        _ => "Internal error in security validation",
    }
}

/// Parse supported OCI fields over [`ContainerConfig::default`] without policy validation.
///
/// Missing or incorrectly typed fields retain their defaults. A bounding
/// capability array replaces the default set, ignoring unknown names and
/// non-string entries. A namespace array enables the user namespace only if
/// it contains an entry with type `user`. UID values accepted as `u64` are
/// truncated to `u32`. The `linux.network_mode` extension uses
/// [`PrivilegeLevel::from_str`]. Privileged mode and seccomp are not read.
///
/// # Errors
/// Returns `ParseError` for empty or malformed JSON. Any valid JSON value is
/// accepted, even if it is not an OCI object.
pub fn parse_oci_json(json_str: &str) -> Result<ContainerConfig, ValidationResult> {
    if json_str.trim().is_empty() {
        return Err(ValidationResult::ParseError);
    }

    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|_| ValidationResult::ParseError)?;

    let mut config = ContainerConfig::default();

    // 1. Process block
    if let Some(process) = val.get("process") {
        if let Some(user) = process.get("user") {
            if let Some(uid) = user.get("uid").and_then(|u| u.as_u64()) {
                config.user_id = uid as u32;
            }
        }

        if let Some(no_new_priv) = process.get("noNewPrivileges").and_then(|n| n.as_bool()) {
            config.no_new_privileges = no_new_priv;
        }

        if let Some(caps) = process.get("capabilities") {
            if let Some(bounding) = caps.get("bounding").and_then(|b| b.as_array()) {
                let mut set = CapabilitySet::EMPTY;
                for c in bounding {
                    if let Some(s) = c.as_str() {
                        if let Some(cap) = Capability::from_name(s) {
                            set.insert(cap);
                        }
                    }
                }
                config.capabilities = set;
            }
        }
    }

    // 2. Root block
    if let Some(root) = val.get("root") {
        if let Some(ro) = root.get("readonly").and_then(|r| r.as_bool()) {
            config.root_read_only = ro;
        }
    }

    // 3. Linux block
    if let Some(linux) = val.get("linux") {
        if let Some(namespaces) = linux.get("namespaces").and_then(|ns| ns.as_array()) {
            let mut has_user_ns = false;
            for ns in namespaces {
                if let Some(t) = ns.get("type").and_then(|t| t.as_str()) {
                    if t == "user" {
                        has_user_ns = true;
                    }
                }
            }
            config.user_namespace = has_user_ns;
        }

        if let Some(net_mode) = linux.get("network_mode").and_then(|m| m.as_str()) {
            config.network_mode = PrivilegeLevel::from_str(net_mode);
        }
    }

    Ok(config)
}

/// Parse and validate JSON, returning zero on success or an ABI failure code.
/// Parse failures return 5; policy failures use [`ValidationResult::to_exit_code`].
/// Missing or unsupported fields follow [`parse_oci_json`]'s defaulting rules.
pub fn verify_json_config(json_str: &str) -> i32 {
    match parse_oci_json(json_str) {
        Ok(config) => validate_configuration(&config).to_exit_code(),
        Err(err) => err.to_exit_code(),
    }
}

/// Sanitize parsed OCI fields by applying security defaults and returning JSON.
///
/// The output contains only the UID, no-new-privileges flag, root read-only flag,
/// user namespace, and network mode. Capabilities and all other input fields
/// are omitted; non-user namespaces are not preserved.
///
/// # Errors
/// Propagates `ParseError` from [`parse_oci_json`]. Serialization errors map to
/// `InternalError`.
pub fn sanitise_config(json_str: &str) -> Result<String, ValidationResult> {
    let mut config = parse_oci_json(json_str)?;
    apply_security_defaults(&mut config);

    let sanitised = serde_json::json!({
        "process": {
            "user": { "uid": config.user_id },
            "noNewPrivileges": config.no_new_privileges
        },
        "root": {
            "readonly": config.root_read_only
        },
        "linux": {
            "namespaces": if config.user_namespace {
                vec![serde_json::json!({"type": "user"})]
            } else {
                vec![]
            },
            "network_mode": match config.network_mode {
                PrivilegeLevel::Unprivileged => "unprivileged",
                PrivilegeLevel::Restricted => "restricted",
                PrivilegeLevel::Admin => "admin",
            }
        }
    });

    serde_json::to_string(&sanitised).map_err(|_| ValidationResult::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_secure() {
        let config = ContainerConfig::default();
        assert!(is_secure(&config));
        assert_eq!(validate_configuration(&config), ValidationResult::Valid);
    }

    #[test]
    fn test_sys_admin_denied_without_privilege() {
        let mut config = ContainerConfig::default();
        config.capabilities.insert(Capability::SysAdmin);
        assert!(!is_secure(&config));
        assert_eq!(
            validate_configuration(&config),
            ValidationResult::InvalidCapabilities
        );

        // When privileged, it passes
        config.is_privileged = true;
        assert!(is_secure(&config));
        assert_eq!(validate_configuration(&config), ValidationResult::Valid);
    }

    #[test]
    fn test_root_requires_user_namespace() {
        let mut config = ContainerConfig::default();
        config.user_id = 0;
        config.user_namespace = false;
        assert!(!is_secure(&config));
        assert_eq!(
            validate_configuration(&config),
            ValidationResult::InvalidUserNamespace
        );
    }

    #[test]
    fn test_apply_security_defaults_fixes_insecure_config() {
        let mut config = ContainerConfig::default();
        config.capabilities.insert(Capability::SysAdmin);
        config.capabilities.insert(Capability::NetAdmin);
        config.user_id = 0;
        config.user_namespace = false;

        assert!(!is_secure(&config));

        apply_security_defaults(&mut config);
        assert!(is_secure(&config));
        assert_eq!(validate_configuration(&config), ValidationResult::Valid);
    }

    #[test]
    fn test_parse_and_verify_json() {
        let valid_json = r#"{
            "process": { "user": { "uid": 1000 }, "noNewPrivileges": true },
            "root": { "readonly": true },
            "linux": { "namespaces": [{"type": "user"}], "network_mode": "unprivileged" }
        }"#;

        assert_eq!(verify_json_config(valid_json), 0);

        let root_no_ns = r#"{
            "process": { "user": { "uid": 0 } },
            "linux": { "namespaces": [] }
        }"#;

        assert_eq!(verify_json_config(root_no_ns), 2);
    }
}
