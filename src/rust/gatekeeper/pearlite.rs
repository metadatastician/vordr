// SPDX-License-Identifier: MPL-2.0
//! Pearlite Deductive Verification Specification Layer
//!
//! Provides functional specification contracts for pure bounded verification
//! under Inria's Pearlite engine.

use super::*;

#[cfg(feature = "pearlite")]
use pearlite_syn::*;

/// Functional specification for security policy verification
pub struct PearlitePolicySpec;

impl PearlitePolicySpec {
    /// Pure logical definition of container boundary safety
    /// Privileged mode bypasses all checks. Otherwise, `SysAdmin`, root without a
    /// user namespace, or `NetAdmin` with unprivileged networking returns false.
    #[inline]
    pub fn is_safe_state(
        is_priv: bool,
        has_sys_admin: bool,
        uid: u32,
        has_user_ns: bool,
        has_net_admin: bool,
        net_mode: PrivilegeLevel,
        no_new_priv: bool,
    ) -> bool {
        if is_priv {
            return true;
        }

        if has_sys_admin {
            return false;
        }

        if uid == 0 && !has_user_ns {
            return false;
        }

        if has_net_admin && net_mode == PrivilegeLevel::Unprivileged {
            return false;
        }

        if uid == 0 && !no_new_priv && !has_user_ns {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pearlite_spec_equivalence() {
        let config = ContainerConfig::default();
        let safe = PearlitePolicySpec::is_safe_state(
            config.is_privileged,
            config.capabilities.has(Capability::SysAdmin),
            config.user_id,
            config.user_namespace,
            config.capabilities.has(Capability::NetAdmin),
            config.network_mode,
            config.no_new_privileges,
        );

        assert!(safe);
        assert_eq!(safe, is_secure(&config));
    }
}
