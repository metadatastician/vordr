// SPDX-License-Identifier: MPL-2.0
//! Build script to compile Ada/SPARK and link with Rust
//!
//! This build script handles:
//! 1. Optional SPARK formal verification (can be skipped with SKIP_SPARK_VERIFY=1)
//! 2. Ada static library compilation via gprbuild
//! 3. Linking the resulting library with the Rust binary
//!
//! If GNAT/SPARK tools are not available, a FAIL-CLOSED stub is used: it
//! rejects every input rather than accepting it. A gate that cannot verify
//! must not pretend it did.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Declared on EVERY path so `cfg(gatekeeper_stub)` is always a known cfg,
    // even when the real Ada library is what gets linked.
    println!("cargo:rustc-check-cfg=cfg(gatekeeper_stub)");

    // Ada/SPARK code is in ../ada relative to the Rust crate
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let spark_path = PathBuf::from(&manifest_dir).join("..").join("ada");

    // Check if we should skip SPARK verification
    let skip_verify = env::var("SKIP_SPARK_VERIFY").is_ok();

    // Lets the stub path be exercised on a machine that HAS GNAT, which is the
    // only way to test that the fail-closed behaviour actually fails closed.
    let force_stub = env::var("VORDR_FORCE_STUB").is_ok();

    // Check if GNAT tools are available
    let has_gnat = !force_stub
        && Command::new("gprbuild")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

    let has_gnatprove = Command::new("gnatprove")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !has_gnat {
        if force_stub {
            println!("cargo:warning=VORDR_FORCE_STUB set - using the FAIL-CLOSED stub gatekeeper");
        } else {
            println!("cargo:warning=GNAT not found - using the FAIL-CLOSED stub gatekeeper");
        }
        println!("cargo:warning=The stub REJECTS EVERY CONFIG. Install GNAT for real verification.");
        generate_stub_library();
        return;
    }

    // Create output directories
    let obj_dir = spark_path.join("obj");
    let lib_dir = spark_path.join("lib");
    std::fs::create_dir_all(&obj_dir).ok();
    std::fs::create_dir_all(&lib_dir).ok();

    // 1. Run GNATprove to verify SPARK code (unless skipped)
    if has_gnatprove && !skip_verify {
        println!("cargo:warning=Running SPARK formal verification...");
        let prove_status = Command::new("gnatprove")
            .args(["-P", "policy.gpr", "--level=2", "--prover=all", "-j0"])
            .current_dir(&spark_path)
            .status();

        match prove_status {
            Ok(status) if status.success() => {
                println!("cargo:warning=SPARK verification passed");
            }
            Ok(_) => {
                // Verification failed - this is serious but we'll warn rather than fail
                // to allow development iteration
                println!("cargo:warning=SPARK verification failed! Security properties not proven.");
                println!("cargo:warning=Set SKIP_SPARK_VERIFY=1 to skip verification during development.");

                // In release mode, we should fail
                if env::var("PROFILE").unwrap_or_default() == "release" {
                    panic!("SPARK verification failed in release build!");
                }
            }
            Err(e) => {
                println!("cargo:warning=Failed to run gnatprove: {}", e);
            }
        }
    } else if skip_verify {
        println!("cargo:warning=Skipping SPARK verification (SKIP_SPARK_VERIFY=1)");
    } else {
        println!("cargo:warning=GNATprove not found - skipping SPARK verification");
    }

    // 2. Build the Ada static library
    println!("cargo:warning=Building Ada static library...");
    let build_result = Command::new("gprbuild")
        .args(["-P", "policy.gpr", "-p", "-j0", "-gnatX"])  // -gnatX disables most style checks
        .current_dir(&spark_path)
        .status();

    match build_result {
        Ok(status) if status.success() => {
            println!("cargo:warning=Ada compilation successful");
        }
        _ => {
            // GNAT IS INSTALLED and the Ada still failed to build. Silently
            // substituting the stub here is how a security gate becomes
            // decorative: the toolchain is present, so the only reason to fall
            // back is that the verified code is broken -- exactly when a
            // fallback is least defensible. Fail the build instead.
            panic!(
                "Ada gatekeeper failed to compile while GNAT is installed. \
                 Refusing to substitute the fail-closed stub, because a build \
                 that quietly downgrades its own security layer is worse than \
                 one that stops. Fix the Ada in src/ada/, or set \
                 VORDR_FORCE_STUB=1 to build against the stub deliberately."
            );
        }
    }

    // 3. Link the static library
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=policy");

    // GNAT runtime libraries (platform-specific)
    // These are typically found in the GNAT installation
    if cfg!(target_os = "linux") {
        // On Linux, we need the GNAT runtime
        println!("cargo:rustc-link-lib=gnat");
        println!("cargo:rustc-link-lib=gnarl"); // For tasking support if needed
    } else if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=gnat");
    }

    // 4. Rebuild if Ada sources change
    println!("cargo:rerun-if-changed={}/src", spark_path.display());
    println!("cargo:rerun-if-changed={}/policy.gpr", spark_path.display());
    println!("cargo:rerun-if-env-changed=SKIP_SPARK_VERIFY");
}

/// Generate a stub C library when GNAT is not available.
/// This allows the Rust code to compile and run basic tests
/// without the full Ada/SPARK toolchain.
fn generate_stub_library() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let stub_file = out_dir.join("gatekeeper_stub.c");

    let stub_code = r#"
// Stub implementation of gatekeeper when GNAT is not available
// SPDX-License-Identifier: MPL-2.0 OR PMPL-1.0-or-later

#include <string.h>

// Validation result codes
#define VALID 0
#define INVALID_CAPABILITIES 1
#define INVALID_USER_NAMESPACE 2
#define INVALID_NETWORK_MODE 3
#define INVALID_PRIVILEGE_ESCAPE 4
#define PARSE_ERROR 5
#define INTERNAL_ERROR -1

// Stub gatekeeper: FAILS CLOSED. Rejects every configuration.
//
// This stub provides NO verification. Its predecessor returned VALID for any
// non-empty input, which meant a build without GNAT silently shipped a
// security gate that approved everything -- and 161 tests exercised THAT,
// so the suite was green precisely because nothing was being checked.
//
// INTERNAL_ERROR is deliberate rather than one of the INVALID_* codes: it maps
// to GatekeeperError::InternalError, which no real validation outcome
// produces, so a caller (or a test) can tell "the verifier is absent" apart
// from "this config was judged unsafe".
int verify_json_config(const char* json_str) {
    (void)json_str;
    return INTERNAL_ERROR;
}

static const char* error_messages[] = {
    "Configuration is valid",
    "SYS_ADMIN capability requires privileged mode",
    "Root UID (0) requires user namespace to be enabled",
    "NET_ADMIN capability requires Restricted or Admin network mode",
    "Potential privilege escalation detected",
    "Failed to parse container configuration",
    "Internal error in security validation"
};

const char* get_error_message(int code) {
    if (code >= 0 && code <= 5) {
        return error_messages[code];
    }
    return error_messages[6];
}

// The stub cannot sanitise either: passing input through unchanged while
// reporting success would be the same lie in a different shape.


int sanitise_config(const char* json_str, char* output_buffer, int buffer_size) {
    (void)json_str; (void)output_buffer; (void)buffer_size;
    // NOTE: returns INTERNAL_ERROR (-1), NOT -INTERNAL_ERROR. This function
    // signals success as a non-negative length, so -INTERNAL_ERROR would be
    // +1 -- an error reported as "sanitised, length 1".
    return INTERNAL_ERROR;
}

const char* gatekeeper_version(void) {
    return "0.1.0-stub";
}

int gatekeeper_init(void) {
    return 0;
}
"#;

    std::fs::write(&stub_file, stub_code).expect("Failed to write stub file");

    // Compile the stub
    cc::Build::new()
        .file(&stub_file)
        .compile("policy");

    // Anything linked against this stub is NOT verified. The cfg lets tests
    // that assume a working verifier opt out explicitly instead of failing
    // for a reason unrelated to what they test.
    println!("cargo:rustc-cfg=gatekeeper_stub");
    println!("cargo:warning=LINKED AGAINST THE FAIL-CLOSED STUB: every config will be REJECTED");
    println!("cargo:rerun-if-changed=build.rs");
}
