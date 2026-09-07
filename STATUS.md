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

- **The gatekeeper stub is FAIL-CLOSED; the real Ada gatekeeper still does not build.** (Corrected 2026-09-07: this entry previously asserted the exact opposite — a silently-substituted stub that accepted every input. That described the OLD stub and has been false since the fail-closed stub landed; the superseded wording is in this file's git history.) `src/rust/build.rs` does not substitute silently on any path: with GNAT absent it links the stub and announces it on three `cargo:warning=` lines (`src/rust/build.rs:51`, `:53`, `:231`); with GNAT present and the Ada failing to compile it aborts the build rather than downgrade the security layer (`src/rust/build.rs:114`–`120`); the stub is otherwise reachable only by setting `VORDR_FORCE_STUB=1` deliberately (`src/rust/build.rs:31`, `:34`, `:48`–`49`). The stub rejects everything: `verify_json_config` returns `INTERNAL_ERROR` (-1) for every input (`src/rust/build.rs:164`, `:177`–`180`), `sanitise_config` returns the same (`src/rust/build.rs:203`–`209`), and its own comment reads `Stub gatekeeper: FAILS CLOSED. Rejects every configuration.` (`src/rust/build.rs:166`). Linking against it sets `cfg(gatekeeper_stub)` (`src/rust/build.rs:20`, `:230`), and the three acceptance-path tests that need a real verifier carry `#[cfg_attr(gatekeeper_stub, ignore)]` (`src/rust/ffi/gatekeeper.rs:412`, `:432`, `:444`), so under the stub they are skipped rather than passing against it — the 143-test figure recorded elsewhere here was measured 2026-07-28 and has not been re-measured. **Still not done:** the real Ada/SPARK gatekeeper does not compile — GNAT error E0015 (a function may not have a parameter of mode `in out`/`out`) in `oci_parser.ads`, owner task #39, parked (`src/ada/test/test_failopen.adb:12`, `src/ada/test/test_parser_failopen.adb:8`); `gnatprove` cannot be run locally (not on PATH), so no SPARK proof has been verified and the repo still contains zero `.spark` artifacts; and there is no `watch --config` subcommand — the CLI is `src/rust/cli/` (there is no `src/cli`), its `Commands` enum has no `Watch` variant (`src/rust/cli/mod.rs:72`–`181`), and its global flags are `--verbose`, `--db-path`, `--runtime`, `--root` with no `--config` (`src/rust/cli/mod.rs:35`–`69`).
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

1. DONE — build.rs now aborts when GNAT is present and the Ada fails to compile (src/rust/build.rs:114-120); the stub is reachable only by setting VORDR_FORCE_STUB=1 (src/rust/build.rs:31), which forces the stub rather than permitting it. VORDR_ALLOW_STUB_GATEKEEPER, the variable this action named, was never implemented.
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

