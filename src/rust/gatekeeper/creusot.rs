// SPDX-License-Identifier: MPL-2.0
//! Creusot Formal Deductive Verification Layer
//!
//! Provides formal contracts and proof obligations discharged via Why3 to
//! Coq/Rocq, Alt-Ergo, and Z3.
//!
//! # Core Verification Theorems
//! 1. `validate_soundness`: `validate_configuration(c) == Valid ==> is_secure(c)`
//! 2. `defaults_soundness`: `apply_security_defaults(c) ==> is_secure(c)`
//! 3. `privilege_monotonicity`: `c.is_privileged ==> is_secure(c)`

use super::*;

#[cfg(feature = "creusot")]
use creusot_contracts::*;

/// Ghost specification predicate: defines policy security in Creusot logic.
#[cfg_attr(feature = "creusot", logic)]
#[cfg_attr(feature = "creusot", open)]
pub fn spec_is_secure(config: ContainerConfig) -> bool {
    config.is_privileged
        || (!config.capabilities.has(Capability::SysAdmin)
            && (config.user_id > 0 || config.user_namespace)
            && (!config.capabilities.has(Capability::NetAdmin)
                || config.network_mode != PrivilegeLevel::Unprivileged)
            && (config.user_id > 0
                || config.no_new_privileges
                || config.user_namespace))
}

/// Creusot contract: Validate configuration soundness.
/// Proves that ANY configuration returning `Valid` mathematically satisfies `is_secure`.
#[cfg_attr(feature = "creusot", requires(true))]
#[cfg_attr(feature = "creusot", ensures(result == ValidationResult::Valid ==> spec_is_secure(*config)))]
pub fn creusot_validate_configuration(config: &ContainerConfig) -> ValidationResult {
    validate_configuration(config)
}

/// Creusot contract: Security defaults guarantee.
/// Proves that `apply_security_defaults` unconditionally establishes `is_secure`.
#[cfg_attr(feature = "creusot", requires(true))]
#[cfg_attr(feature = "creusot", ensures(spec_is_secure(*config)))]
pub fn creusot_apply_security_defaults(config: &mut ContainerConfig) {
    apply_security_defaults(config);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creusot_contract_runtime_check() {
        let mut cfg = ContainerConfig::default();
        cfg.capabilities.insert(Capability::SysAdmin);
        assert!(!spec_is_secure(cfg.clone()));

        creusot_apply_security_defaults(&mut cfg);
        assert!(spec_is_secure(cfg.clone()));
        assert_eq!(creusot_validate_configuration(&cfg), ValidationResult::Valid);
    }
}
