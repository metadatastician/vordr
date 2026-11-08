// SPDX-License-Identifier: MPL-2.0
//! Native Rust gatekeeper with runtime policy tests and verification scaffolding.
//! Kani harnesses and Creusot contracts require their respective verification tools.
//! Pearlite is Creusot's contract language; the local Pearlite and Verus modules
//! are unverified specification sketches.

pub mod creusot;
#[path = "kani.rs"]
pub mod kani_proofs;
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

    /// Canonical OCI capability name, inverse of `from_name`.
    pub fn name(self) -> &'static str {
        const NAMES: [&str; 16] = [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE",
            "CAP_NET_ADMIN",
            "CAP_SYS_ADMIN",
        ];
        NAMES[self as usize]
    }

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
            && (config.user_id > 0 || config.no_new_privileges || config.user_namespace))
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
#[cfg_attr(feature = "creusot", creusot_contracts::macros::ensures(matches!(result, ValidationResult::Valid) ==> creusot::spec_is_secure(*config)))]
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
#[cfg_attr(feature = "creusot", creusot_contracts::macros::ensures(creusot::spec_is_secure(^config)))]
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

/// Parse supported OCI security fields without policy validation.
///
/// `process.user.uid` is required and must fit in `u32`. Optional fields default
/// to no capabilities, no user namespace, no privilege barrier, a writable root,
/// and unprivileged networking. Capabilities are collected from all five OCI
/// sets; unknown names and malformed entries are rejected. A namespace array
/// enables the user namespace only if it contains an entry with type `user`.
/// The `linux.network_mode` extension accepts `unprivileged`, `restricted`,
/// `admin`, and the `host` alias. Privileged mode and seccomp are not read.
/// This parser does not validate the full OCI schema.
///
/// # Errors
/// Returns `ParseError` for empty or malformed JSON, a non-object input, missing
/// required fields, an out-of-range UID, or malformed supported security fields.
pub fn parse_oci_json(json_str: &str) -> Result<ContainerConfig, ValidationResult> {
    let val = serde_json::from_str(json_str).map_err(|_| ValidationResult::ParseError)?;
    parse_oci_value(&val)
}

fn parse_oci_value(val: &serde_json::Value) -> Result<ContainerConfig, ValidationResult> {
    use ValidationResult::ParseError;
    let object = val.as_object().ok_or(ParseError)?;
    let process = object
        .get("process")
        .and_then(|v| v.as_object())
        .ok_or(ParseError)?;
    let user = process
        .get("user")
        .and_then(|v| v.as_object())
        .ok_or(ParseError)?;
    let uid = user.get("uid").and_then(|v| v.as_u64()).ok_or(ParseError)?;
    let mut config = ContainerConfig {
        user_id: u32::try_from(uid).map_err(|_| ParseError)?,
        capabilities: CapabilitySet::EMPTY,
        user_namespace: false,
        no_new_privileges: false,
        root_read_only: false,
        seccomp_enabled: false,
        ..ContainerConfig::default()
    };
    if let Some(value) = process.get("noNewPrivileges") {
        config.no_new_privileges = value.as_bool().ok_or(ParseError)?;
    }
    if let Some(value) = process.get("capabilities") {
        let sets = value.as_object().ok_or(ParseError)?;
        for (name, value) in sets {
            if ![
                "bounding",
                "effective",
                "permitted",
                "inheritable",
                "ambient",
            ]
            .contains(&name.as_str())
            {
                return Err(ParseError);
            }
            for entry in value.as_array().ok_or(ParseError)? {
                let cap =
                    Capability::from_name(entry.as_str().ok_or(ParseError)?).ok_or(ParseError)?;
                config.capabilities.insert(cap);
            }
        }
    }
    if let Some(root) = object.get("root") {
        let root = root.as_object().ok_or(ParseError)?;
        if let Some(value) = root.get("readonly") {
            config.root_read_only = value.as_bool().ok_or(ParseError)?;
        }
    }
    if let Some(linux) = object.get("linux") {
        let linux = linux.as_object().ok_or(ParseError)?;
        if let Some(value) = linux.get("namespaces") {
            for ns in value.as_array().ok_or(ParseError)? {
                let ns = ns.as_object().ok_or(ParseError)?;
                let kind = ns.get("type").and_then(|v| v.as_str()).ok_or(ParseError)?;
                if let Some(path) = ns.get("path") {
                    path.as_str().ok_or(ParseError)?;
                }
                config.user_namespace |= kind == "user";
            }
        }
        if let Some(value) = linux.get("network_mode") {
            config.network_mode = match value.as_str().ok_or(ParseError)? {
                "unprivileged" => PrivilegeLevel::Unprivileged,
                "restricted" => PrivilegeLevel::Restricted,
                "admin" | "host" => PrivilegeLevel::Admin,
                _ => return Err(ParseError),
            };
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
/// Preserves existing OCI fields, including non-user namespaces. Removes denied
/// capabilities from every supplied capability set, adds a bounding set if absent,
/// writes the hardened no-new-privileges flag, and adds a user namespace for root
/// when needed.
///
/// # Errors
/// Propagates `ParseError` from [`parse_oci_json`]. Serialization errors map to
/// `InternalError`.
pub fn sanitise_config(json_str: &str) -> Result<String, ValidationResult> {
    let mut value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|_| ValidationResult::ParseError)?;
    let mut config = parse_oci_value(&value)?;
    apply_security_defaults(&mut config);
    value["process"]["noNewPrivileges"] = config.no_new_privileges.into();
    let process = value["process"]
        .as_object_mut()
        .ok_or(ValidationResult::ParseError)?;
    let caps = process
        .entry("capabilities")
        .or_insert_with(|| serde_json::json!({}));
    // Preserve each set's membership, removing capabilities denied by hardening.
    for set in caps
        .as_object_mut()
        .ok_or(ValidationResult::ParseError)?
        .values_mut()
    {
        set.as_array_mut()
            .ok_or(ValidationResult::ParseError)?
            .retain(|entry| {
                Capability::from_name(entry.as_str().unwrap_or_default())
                    .map(|cap| config.capabilities.has(cap))
                    .unwrap_or(false)
            });
    }
    if caps.get("bounding").is_none() {
        caps["bounding"] = serde_json::json!(Capability::ALL
            .into_iter()
            .filter(|cap| config.capabilities.has(*cap))
            .map(Capability::name)
            .collect::<Vec<_>>());
    }
    if config.user_namespace {
        let object = value.as_object_mut().ok_or(ValidationResult::ParseError)?;
        let linux = object
            .entry("linux")
            .or_insert_with(|| serde_json::json!({}));
        let ns = linux
            .as_object_mut()
            .ok_or(ValidationResult::ParseError)?
            .entry("namespaces")
            .or_insert_with(|| serde_json::json!([]));
        let ns = ns.as_array_mut().ok_or(ValidationResult::ParseError)?;
        if !ns.iter().any(|entry| entry["type"] == "user") {
            ns.push(serde_json::json!({"type": "user"}));
        }
    }
    serde_json::to_string(&value).map_err(|_| ValidationResult::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_json_rejects_missing_and_malformed_values() {
        use serde_json::json;
        assert_eq!(parse_oci_json("{}"), Err(ValidationResult::ParseError));
        let base = json!({"process":{"user":{"uid":0}}});
        let cfg = parse_oci_json(&base.to_string()).unwrap();
        assert!(!cfg.user_namespace);
        assert_eq!(
            validate_configuration(&cfg),
            ValidationResult::InvalidUserNamespace
        );
        for (pointer, invalid) in [
            ("/process/user/uid", json!(4294967296u64)),
            ("/process/user/uid", json!(-1)),
            ("/process/user/uid", json!("1000")),
            ("/process/noNewPrivileges", json!(null)),
            ("/root/readonly", json!("true")),
            ("/linux/network_mode", json!("typo")),
            ("/linux/namespaces", json!(false)),
            ("/linux/namespaces", json!([{"type":false}])),
        ] {
            let mut val = json!({"process":{"user":{"uid":1000},"noNewPrivileges":true},
                "root":{"readonly":true},"linux":{"namespaces":[],"network_mode":"unprivileged"}});
            *val.pointer_mut(pointer).unwrap() = invalid;
            assert_eq!(
                parse_oci_json(&val.to_string()),
                Err(ValidationResult::ParseError),
                "{pointer}"
            );
        }
        for set in [
            "bounding",
            "effective",
            "permitted",
            "inheritable",
            "ambient",
        ] {
            for invalid in [json!(["CAP_UNKNOWN"]), json!([3]), json!(null)] {
                let val = json!({"process":{"user":{"uid":1000},"capabilities":{set:invalid}}});
                assert_eq!(
                    parse_oci_json(&val.to_string()),
                    Err(ValidationResult::ParseError)
                );
            }
            let val =
                json!({"process":{"user":{"uid":1000},"capabilities":{set:["CAP_SYS_ADMIN"]}}});
            assert_eq!(verify_json_config(&val.to_string()), 1);
        }
    }

    #[test]
    fn sanitisation_preserves_oci_fields_and_hardens_all_sets() {
        use serde_json::json;
        let input = json!({"ociVersion":"1.1.0","annotations":{"custom":"keep"},
            "mounts":[{"destination":"/data"}],"root":{"path":"rootfs","readonly":false},
            "process":{"user":{"uid":0,"gid":42},"args":["sh"],"env":["A=B"],
                "capabilities":{"bounding":["CAP_SYS_ADMIN","CAP_CHOWN"],
                    "effective":["CAP_NET_ADMIN"],"permitted":["CAP_SYS_ADMIN"],
                    "ambient":["CAP_NET_ADMIN"],"inheritable":["CAP_CHOWN"]}},
            "linux":{"namespaces":[{"type":"mount"}],"resources":{"pids":{"limit":5}}}});
        let output: serde_json::Value =
            serde_json::from_str(&sanitise_config(&input.to_string()).unwrap()).unwrap();
        for pointer in [
            "/annotations",
            "/mounts",
            "/root",
            "/process/user",
            "/process/args",
            "/process/env",
            "/linux/resources",
        ] {
            assert_eq!(input.pointer(pointer), output.pointer(pointer), "{pointer}");
        }
        assert_eq!(
            output["linux"]["namespaces"][0],
            input["linux"]["namespaces"][0]
        );
        assert_eq!(verify_json_config(&output.to_string()), 0);
        assert_eq!(
            output["process"]["capabilities"]["bounding"],
            json!(["CAP_CHOWN"])
        );
        for set in ["effective", "permitted", "ambient"] {
            assert_eq!(output["process"]["capabilities"][set], json!([]));
        }
        for cap in Capability::ALL {
            assert_eq!(Capability::from_name(cap.name()), Some(cap));
        }
    }

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
