// SPDX-License-Identifier: MPL-2.0
//! Unverified Verus specification sketch, excluded from ordinary Rust builds.
//! The sketch calls executable functions in specification positions without a
//! verified correspondence. Its lemmas have not been checked by Verus or Z3.

use super::*;

#[cfg(verus)]
use builtin::*;
#[cfg(verus)]
use builtin_macros::*;

// Conditional macro for non-verus compilation environments
#[cfg(not(verus))]
macro_rules! verus {
    ($($item:tt)*) => {};
}

verus! {

/// Specify the gatekeeper policy, including the privileged-mode bypass.
pub open spec fn verus_spec_is_secure(config: ContainerConfig) -> bool {
    config.is_privileged
        || (!config.capabilities.has(Capability::SysAdmin)
            && (config.user_id > 0 || config.user_namespace)
            && (!config.capabilities.has(Capability::NetAdmin)
                || config.network_mode != PrivilegeLevel::Unprivileged)
            && (config.user_id > 0
                || config.no_new_privileges
                || config.user_namespace))
}

/// State that successful validation implies the security predicate.
pub proof fn lemma_validation_soundness(config: ContainerConfig)
    requires
        validate_configuration(&config) == ValidationResult::Valid,
    ensures
        verus_spec_is_secure(config),
{
    // Intended case analysis (not verified):
    // If config.is_privileged => true
    // If not privileged => sys_admin is false, uid/ns conditions hold, net_admin holds
}

/// State that applying security defaults establishes the security predicate.
pub proof fn lemma_defaults_enforce_security(config: ContainerConfig)
    ensures
        ({
            let mut hardened = config;
            apply_security_defaults(&mut hardened);
            verus_spec_is_secure(hardened)
        }),
{
    // Intended defaults property; executable/spec correspondence remains unverified.
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verus_compatibility_check() {
        let mut cfg = ContainerConfig::default();
        cfg.user_id = 0;
        cfg.user_namespace = false;
        assert_ne!(validate_configuration(&cfg), ValidationResult::Valid);

        apply_security_defaults(&mut cfg);
        assert_eq!(validate_configuration(&cfg), ValidationResult::Valid);
    }
}
