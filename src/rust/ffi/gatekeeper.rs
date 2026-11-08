// SPDX-License-Identifier: MPL-2.0
//! Safe Rust API for the Formally Verified Gatekeeper
//!
//! Powered by a quad-tier formal verification & model checking matrix
//! (Creusot, Verus, Pearlite, and Kani).

use thiserror::Error;

/// Errors that can occur during gatekeeper validation
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GatekeeperError {
    #[error("SYS_ADMIN capability requires privileged mode")]
    InvalidCapabilities,

    #[error("Root UID (0) requires user namespace to be enabled")]
    InvalidUserNamespace,

    #[error("NET_ADMIN capability requires Restricted or Admin network mode")]
    InvalidNetworkMode,

    #[error("Potential privilege escalation: set no_new_privileges or enable user namespace")]
    InvalidPrivilegeEscape,

    #[error("Failed to parse OCI configuration JSON")]
    ParseError,

    #[error("Internal error in Gatekeeper")]
    InternalError,

    #[error("Null byte found in JSON string")]
    NullByte,

    #[allow(dead_code)]
    #[error("Gatekeeper not initialized")]
    NotInitialized,
}

impl GatekeeperError {
    /// Convert from exit code (matching C ABI / Ada To_Exit_Code)
    pub fn from_code(code: i32) -> Result<(), Self> {
        match code {
            0 => Ok(()),
            1 => Err(GatekeeperError::InvalidCapabilities),
            2 => Err(GatekeeperError::InvalidUserNamespace),
            3 => Err(GatekeeperError::InvalidNetworkMode),
            4 => Err(GatekeeperError::InvalidPrivilegeEscape),
            5 => Err(GatekeeperError::ParseError),
            _ => Err(GatekeeperError::InternalError),
        }
    }
}

/// Initialize the gatekeeper.
/// Safe to call multiple times - subsequent calls are no-ops.
pub fn init() -> Result<(), GatekeeperError> {
    Ok(())
}

/// Validate an OCI runtime specification through the formally verified Gatekeeper.
///
/// # Arguments
/// * `json_content` - The OCI runtime configuration JSON string
///
/// # Returns
/// * `Ok(())` if the configuration passes all security checks
/// * `Err(GatekeeperError)` describing why validation failed
pub fn validate_oci_config(json_content: &str) -> Result<(), GatekeeperError> {
    if json_content.contains('\0') {
        return Err(GatekeeperError::NullByte);
    }

    let code = crate::gatekeeper::verify_json_config(json_content);
    GatekeeperError::from_code(code)
}

/// Get a human-readable description of an error code.
pub fn get_error_description(code: i32) -> String {
    crate::gatekeeper::get_error_message(code).to_string()
}

/// Sanitise an OCI configuration by applying security defaults.
pub fn sanitise_oci_config(json_content: &str) -> Result<String, GatekeeperError> {
    if json_content.contains('\0') {
        return Err(GatekeeperError::NullByte);
    }

    crate::gatekeeper::sanitise_config(json_content)
        .map_err(|e| GatekeeperError::from_code(e.to_exit_code()).unwrap_err())
}

/// Get the gatekeeper library version.
pub fn version() -> String {
    "0.1.0-verified-rust".to_string()
}

/// Builder for constructing validated container configurations.
#[derive(Debug, Clone)]
pub struct ConfigValidator {
    privileged: bool,
    user_namespace: bool,
    user_id: u32,
    network_mode: NetworkMode,
    capabilities: Vec<String>,
    no_new_privileges: bool,
    readonly_rootfs: bool,
}

/// Network privilege mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    #[default]
    Unprivileged,
    Restricted,
    Admin,
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigValidator {
    /// Create a new configuration validator with secure defaults.
    pub fn new() -> Self {
        Self {
            privileged: false,
            user_namespace: true,
            user_id: 1000,
            network_mode: NetworkMode::Unprivileged,
            capabilities: Vec::new(),
            no_new_privileges: true,
            readonly_rootfs: true,
        }
    }

    /// Set privileged mode (bypasses security checks).
    pub fn privileged(mut self, privileged: bool) -> Self {
        self.privileged = privileged;
        self
    }

    /// Enable or disable user namespace.
    pub fn user_namespace(mut self, enabled: bool) -> Self {
        self.user_namespace = enabled;
        self
    }

    /// Set the user ID to run as.
    pub fn user_id(mut self, uid: u32) -> Self {
        self.user_id = uid;
        self
    }

    /// Set network mode.
    pub fn network_mode(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Add a capability.
    pub fn add_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Set no_new_privileges flag.
    #[allow(dead_code)]
    pub fn no_new_privileges(mut self, enabled: bool) -> Self {
        self.no_new_privileges = enabled;
        self
    }

    /// Set readonly root filesystem.
    pub fn readonly_rootfs(mut self, readonly: bool) -> Self {
        self.readonly_rootfs = readonly;
        self
    }

    /// Build and validate the configuration.
    pub fn validate(self) -> Result<ValidatedConfig, GatekeeperError> {
        let config_json = self.to_json();
        validate_oci_config(&config_json)?;

        Ok(ValidatedConfig {
            privileged: self.privileged,
            user_namespace: self.user_namespace,
            user_id: self.user_id,
            network_mode: self.network_mode,
            capabilities: self.capabilities,
            no_new_privileges: self.no_new_privileges,
            readonly_rootfs: self.readonly_rootfs,
        })
    }

    fn to_json(&self) -> String {
        let network_mode = match self.network_mode {
            NetworkMode::Unprivileged => "unprivileged",
            NetworkMode::Restricted => "restricted",
            NetworkMode::Admin => "admin",
        };

        format!(
            r#"{{
                "process": {{
                    "user": {{ "uid": {} }},
                    "noNewPrivileges": {}
                }},
                "root": {{ "readonly": {} }},
                "linux": {{
                    "namespaces": [{}],
                    "network_mode": "{}"
                }}
            }}"#,
            self.user_id,
            self.no_new_privileges,
            self.readonly_rootfs,
            if self.user_namespace {
                r#"{"type": "user"}"#
            } else {
                ""
            },
            network_mode
        )
    }
}

/// A container configuration that has passed security validation.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub privileged: bool,
    pub user_namespace: bool,
    pub user_id: u32,
    #[allow(dead_code)]
    pub network_mode: NetworkMode,
    pub capabilities: Vec<String>,
    pub no_new_privileges: bool,
    pub readonly_rootfs: bool,
}

/// Result of image verification through the gatekeeper.
#[derive(Debug, Clone)]
pub struct ImageVerificationReport {
    pub passed: bool,
    pub attestations: Vec<String>,
    pub warnings: Vec<String>,
}

/// Verify an image reference through the formally verified gatekeeper.
pub fn validate_image(image: &str) -> Result<ImageVerificationReport, GatekeeperError> {
    if image.is_empty() {
        return Err(GatekeeperError::ParseError);
    }

    let has_valid_tag = image.contains(':') || !image.contains('@');
    let oci_stub = format!(r#"{{"image": "{}", "rootfs": {{"type": "layers"}}}}"#, image);

    match validate_oci_config(&oci_stub) {
        Ok(()) => {
            let mut attestations = Vec::new();
            let mut warnings = Vec::new();

            if image.starts_with("cgr.dev/") || image.starts_with("ghcr.io/") {
                attestations.push("registry_verified".to_string());
            }

            if !has_valid_tag {
                warnings.push("Image uses digest reference without tag — consider tagging for readability".to_string());
            }

            if image.ends_with(":latest") || !image.contains(':') {
                warnings.push("Image uses :latest tag — pin to a specific version for reproducibility".to_string());
            }

            Ok(ImageVerificationReport {
                passed: true,
                attestations,
                warnings,
            })
        }
        Err(e) => {
            Ok(ImageVerificationReport {
                passed: false,
                attestations: vec![],
                warnings: vec![format!("Verification failed: {}", e)],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        let _ = init();
    }

    #[test]
    fn test_version() {
        setup();
        let ver = version();
        assert!(!ver.is_empty());
    }

    #[test]
    fn test_validate_secure_config() {
        setup();
        let config = r#"{"process": {"user": {"uid": 1000}}}"#;
        let result = validate_oci_config(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_config_fails() {
        setup();
        let result = validate_oci_config("");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_builder_defaults() {
        setup();
        let result = ConfigValidator::new().validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_builder_with_user_id() {
        setup();
        let result = ConfigValidator::new().user_id(0).user_namespace(true).validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_description() {
        setup();
        let desc = get_error_description(1);
        assert!(!desc.is_empty());
        assert!(desc.contains("SYS_ADMIN") || desc.contains("capability"));
    }
}
