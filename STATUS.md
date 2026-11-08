<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:6ad56d2e7be5a3331fefe12af3f6efaa6e93c73870aecac4a58aabf5ce8e5562 -->

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Vordr — Measured Status

**Last measured:** 2026-07-28 (Updated: 2026-10-18)  
**Honest completion:** ~50%  
**Languages:** Rust (CLI + MCP + native gatekeeper) · Idris2 (proofs) · Ada/SPARK (legacy gatekeeper) · Elixir · AffineScript / ReScript (LSP)

> This document records **measured** state: every claim below is a file read, a build
> run, or a test executed on the dates shown. Where an existing document in this repo
> contradicts it, this one is correct and the other is stale. Full evidence and
> cross-repo context: `dev-notes/stapeln-ecosystem-COMPREHENSIVE-SITREP-2026-07-28.md`.

## Summary

~50%. The Rust CLI and native security policy engine are implemented; container lifecycle operations and formal verification remain incomplete.

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:0c4d43bbf0f5273a3f6caac65e439df04f390f001ff3f6282b8228d8cb045688 -->

## What works

- Native Rust JSON validation and sanitisation run through `src/rust/ffi/gatekeeper.rs`.
- Review validation (2026-11-08): `VORDR_FORCE_STUB=1 cargo test --lib --features creusot` passed all 60 library tests, including the security parser and sanitiser regressions and the 192-state Pearlite predicate comparison. These are executable tests, not formal proofs.
- Idris2 proof sources and Ada/SPARK annotations are present; they were not compiled or proved in this review.



<!-- /coderabbit-ai-generated:v1 -->## What is broken, missing, or misreported

- **Native gatekeeper and legacy build path:** `src/rust/ffi/gatekeeper.rs` calls the native Rust engine for JSON validation and sanitisation. `build.rs` still compiles a fail-closed C stub when GNAT is unavailable or `VORDR_FORCE_STUB` is set; GNAT build failures abort. The stub is not the Rust bridge’s validation path. Creusot contracts and Kani harnesses are present, but no successful formal verification run is recorded. Pearlite is Creusot’s contract language; the local Pearlite and Verus modules are unverified sketches.
- Root cause is known and small: `a-cofove.ads:36:07 — This package has been moved to the SPARK library shipped with any SPARK release starting with version 23` (plus `-gnatyo`/`-gnatyk` style errors).
- **`gnatprove` has never been run** — no `.spark` artifacts anywhere in the repo. The 'SPARK-verified' claim is unsubstantiated.
- Zig pointer dereferencing was updated for 0.16 compatibility (Next action 5); a current Zig build has not been remeasured here.
- ABI documentation is filled in and describes the current Zig exports, including container stubs and function-specific return values.
- `codemeta.json` repository and issue URLs now point to `github.com/metadatastician/vordr`.
- `.github/workflows/build-test.yml` now declares a Rust build and test gate with the legacy stub forced. It does not establish Ada or formal proof coverage.

## Notes and open rulings

- THREE incompatible definitions of vordr are in circulation: 'BLAKE3 integrity monitor' (boj cartridge), 'formally verified container runtime' (svalinn ecosystem.yaml), 'container runtime wrapper — lifecycle management' (container-stack README). The bundle's `vordr.toml` implies something narrower than all three: health probes + crash detection.
- OPEN RULING R3: adopt the bundle's definition. Note the one working integration in the whole ecosystem is `svalinn_gateway.ts` calling `Deno.Command("vordr")` — read what that does before narrowing.

## Next actions

1. DONE — `build.rs` aborts on Ada compilation failure when GNAT is present. It uses the announced fail-closed C stub when GNAT is absent or `VORDR_FORCE_STUB` is set.
2. DONE (implementation, 2026-10-18) — Added native Rust gatekeeper and routed the Rust bridge through it. Formal verification remains pending: Creusot contracts, Kani harnesses, and unverified Pearlite/Verus sketches are not evidence of discharged proofs.
3. Fix the legacy SPARK library import error (a-cofove.ads) if retaining Ada as secondary target
4. RULING NEEDED (R3): confirm vordr = health monitoring + crash detection
5. DONE (2026-10-18) — Migrated `ffi/zig` pointer dereferencing for Zig 0.16 compatibility (`for (&threads) |*thread| thread.join();`).
6. DONE (2026-10-18) — Filled in `ABI-FFI-README.md` completely with authoritative Vörðr Idris2 -> Zig documentation; updated `codemeta.json` repo and issue URLs.

## CI/CD status

As of 2026-07-28, post-merge: **3/3 workflows parse clean**, with zero
illegal `timeout-minutes` on reusable-call jobs and zero phantom `codeql-action` SHAs.
(Three sweep-introduced fault classes were repaired and merged on this date — see the
ecosystem sitrep for the taxonomy.)

**Gates that genuinely enforce something:**

- Rust build and test jobs are declared in `.github/workflows/build-test.yml`; no CI execution was observed in this review.

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:b3a9043c408c1765080466c0d47926797b024b8b256a84a603bbbf89112539ba -->

**Historical GitLab gate limitations (2026-07-28; not remeasured here):**

<!-- /coderabbit-ai-generated:v1 -->
- GitLab: 13 of 19 jobs `allow_failure: true`, including *every* proof job
- `idris2-check` uses the fake per-file `--check` form (exits 0 on error) and omits `Proofs.idr` and `SBOM.idr`
- `spark-prove` is `allow_failure: true` with the comment `# SPARK proofs are aspirational for now`

> A gate is not done until it has been observed to **fail** on a deliberate defect.
> Every fake gate listed above passed its own review.

## Ecosystem position

This repo is part of the six-repo container stack designed by `stapeln`. The canonical
integration contract is the 8-file `container/stapeln/` bundle, in which each satellite
consumes its own file:

| File | Consumer |
|---|---|
| `compose.toml` | selur |
| `vordr.toml` | vordr |
| `rokur.toml` | rokur |
| `.gatekeeper.yaml` | svalinn |
| `manifest.toml` + `ct-build.sh` | cerro-torre |
| `deploy.k9.ncl` | K9 / k9-svc |

Runtime chain: `svalinn (443/80) -> rokur (8081) -> app`, with vordr watching all three,
cerro-torre signing each as a `.ctp`, and selur as the network driver.

**As of this measurement no repo emits or consumes that bundle**; five mutually
incompatible ad-hoc contracts exist instead, of which exactly one works.



<!-- /coderabbit-ai-generated:v1 -->