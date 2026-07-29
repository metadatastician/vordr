<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Vordr — Measured Status

**Last measured:** 2026-07-28  
**Honest completion:** ~40%  
**Languages:** Rust (CLI + MCP) · Idris2 (proofs) · Ada/SPARK (gatekeeper) · Elixir · ReScript (LSP)

> This document records **measured** state: every claim below is a file read, a build
> run, or a test executed on the dates shown. Where an existing document in this repo
> contradicts it, this one is correct and the other is stale. Full evidence and
> cross-repo context: `dev-notes/stapeln-ecosystem-COMPREHENSIVE-SITREP-2026-07-28.md`.

## Summary

~40%. Best proofs and most working Rust in the ecosystem — and its security layer does not exist at runtime.

## What genuinely works

- 17,643 lines of Rust; `cargo check --all-targets` passes; 143 tests pass across 370 functions with zero `todo!()`/`unimplemented!()`
- **The best formal proofs in the estate**: 8 `.idr` files, 84 top-level definitions, `vordr.ipkg` with `opts = "--total"`, and ZERO `believe_me`/`assert_total`/holes in code
- Genuine SPARK annotations: `SPARK_Mode (On)` in 4 of 5 spec files, 22 `Pre =>`/`Post =>` contracts, with `policy_interface.ads` correctly marked `Off` (FFI cannot be proven)
- All 10 Ada source files are syntactically valid (`gcc -gnats`)
- The README is the most honest self-assessment in the estate — it volunteers 'No real container runtime', 'zero BPF bytecode', 'Ada/SPARK never compiled with GNAT; C stubs used at runtime'

## What is broken, missing, or misreported

- **FAIL-OPEN SECURITY BYPASS.** `src/rust/build.rs` attempts `gprbuild -P policy.gpr` and, on failure, SILENTLY substitutes `gatekeeper_stub.c` and continues. The stub's own comment reads `// WARNING: This provides NO security guarantees!` and it returns `VALID` for every input. All 143 passing tests exercise the stub, not the Ada. A `cargo build` emitting only a `warning:` produces a binary whose policy gate is a no-op.
- Root cause is known and small: `a-cofove.ads:36:07 — This package has been moved to the SPARK library shipped with any SPARK release starting with version 23` (plus `-gnatyo`/`-gnatyk` style errors).
- **`gnatprove` has never been run** — no `.spark` artifacts anywhere in the repo. The 'SPARK-verified' claim is unsubstantiated.
- `ffi/zig` fails to build on Zig 0.16 (`method invocation only supports up to one level of implicit pointer dereferencing`) — a mechanical 0.15->0.16 migration.
- `ABI-FFI-README.md` is an UNFILLED TEMPLATE — line 2 is literally `{{~ Aditionally delete this line and fill out the template below ~}}`, and it is byte-identical to cerro-torre's.
- `codemeta.json` claims `gitlab.com/hyperpolymath/vordr` — wrong host and wrong owner.
- No build or test gate on GitHub; on GitLab 13 of 19 jobs are `allow_failure: true`, including every proof job and `spark-prove`.

## Notes and open rulings

- THREE incompatible definitions of vordr are in circulation: 'BLAKE3 integrity monitor' (boj cartridge), 'formally verified container runtime' (svalinn ecosystem.yaml), 'container runtime wrapper — lifecycle management' (container-stack README). The bundle's `vordr.toml` implies something narrower than all three: health probes + crash detection.
- OPEN RULING R3: adopt the bundle's definition. Note the one working integration in the whole ecosystem is `svalinn_gateway.ts` calling `Deno.Command("vordr")` — read what that does before narrowing.

## Next actions

1. Make the Ada failure HARD in build.rs — fail unless VORDR_ALLOW_STUB_GATEKEEPER=1 is set explicitly
2. Fix the SPARK library import error (a-cofove.ads) so the real gatekeeper compiles
3. Run gnatprove at least once, or drop the SPARK-verified claim
4. RULING NEEDED (R3): confirm vordr = health monitoring + crash detection
5. Migrate build.zig to Zig 0.16
6. Fill in ABI-FFI-README.md or delete it

## CI/CD status

As of 2026-07-28, post-merge: **3/3 workflows parse clean**, with zero
illegal `timeout-minutes` on reusable-call jobs and zero phantom `codeql-action` SHAs.
(Three sweep-introduced fault classes were repaired and merged on this date — see the
ecosystem sitrep for the taxonomy.)

**Gates that genuinely enforce something:**

- **None.** This repo has no build or test gate that can fail.

**Gates that run but cannot fail (or check nothing):**

- `codeql.yml` pinned to `language: actions` — zero application source analysed
- **no build or test gate on GitHub at all**
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

