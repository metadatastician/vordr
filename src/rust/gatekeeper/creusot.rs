// SPDX-License-Identifier: MPL-2.0
//! Creusot Formal Deductive Verification Layer
//!
//! Candidate formal contracts for Creusot / Why3. No proof run is recorded.
//! Run `cargo creusot --lib --features creusot,creusot-contracts/creusot` from src/rust with the
//! Creusot 0.8 toolchain and Why3 provers installed. Ordinary Cargo tests
//! check runtime agreement only and do not discharge these contracts.
//!
//! # Intended proof obligations
//! 1. `validate_soundness`: `validate_configuration(c) == Valid ==> is_secure(c)`
//! 2. `defaults_soundness`: `apply_security_defaults(c) ==> is_secure(c)`
//! 3. `privilege_monotonicity`: `c.is_privileged ==> is_secure(c)`

use super::*;

#[cfg(feature = "creusot")]
use creusot_contracts::macros::{ensures, requires};

/// Ghost specification predicate: defines policy security in Creusot logic.
#[cfg_attr(
    all(feature = "creusot", creusot),
    creusot_contracts::macros::logic(open)
)]
pub fn spec_is_secure(config: ContainerConfig) -> bool {
    config.is_privileged
        || ((config.capabilities.mask & (1u16 << 15)) == 0
            && (config.user_id > 0 || config.user_namespace)
            && ((config.capabilities.mask & (1u16 << 14)) == 0
                || matches!(
                    config.network_mode,
                    PrivilegeLevel::Restricted | PrivilegeLevel::Admin
                ))
            && (config.user_id > 0 || config.no_new_privileges || config.user_namespace))
}

/// Creusot contract: Validate configuration soundness.
/// Intended obligation: any configuration returning `Valid` mathematically satisfies `is_secure`.
#[cfg_attr(feature = "creusot", requires(true))]
#[cfg_attr(feature = "creusot", ensures(matches!(result, ValidationResult::Valid) ==> spec_is_secure(*config)))]
pub fn creusot_validate_configuration(config: &ContainerConfig) -> ValidationResult {
    validate_configuration(config)
}

/// Creusot contract: Security defaults guarantee.
/// Intended obligation: `apply_security_defaults` unconditionally establishes `is_secure`.
#[cfg_attr(feature = "creusot", requires(true))]
#[cfg_attr(feature = "creusot", ensures(spec_is_secure(^config)))]
pub fn creusot_apply_security_defaults(config: &mut ContainerConfig) {
    apply_security_defaults(config);
}

#[cfg(all(test, not(creusot)))]
mod tests {
    use super::*;

    #[test]
    fn test_creusot_contract_runtime_check() {
        let mut cfg = ContainerConfig::default();
        cfg.capabilities.insert(Capability::SysAdmin);
        assert!(!spec_is_secure(cfg.clone()));

        creusot_apply_security_defaults(&mut cfg);
        assert!(spec_is_secure(cfg.clone()));
        assert_eq!(
            creusot_validate_configuration(&cfg),
            ValidationResult::Valid
        );
    }
}
