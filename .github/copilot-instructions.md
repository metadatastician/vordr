# Copilot Instructions for Vörðr

These instructions guide GitHub Copilot (Cloud Agent, PR Reviewer, CLI, and IDE extensions) when working across this repository.

---

## 1. Project Overview & Architectural Role

**Vörðr** (Old Norse: *guardian* / *watcher*, ASCII: `vordr`) is a formally verified container orchestration and verification system. It acts as the reference runtime for Container Package (`.ctp`) bundles under the verified-container-spec.

---

## 2. Estate Language Policy (STRICT)

This repository follows the **Hyperpolymath Estate Language Policy (1.2)**:

| Language | Extension | Role in Repo | Guidelines |
| :--- | :--- | :--- | :--- |
| **AffineScript** | `*.affine`, `*.afs` | **MCP adapter, runtime, browser UI** (replaces ReScript). | Canonical repo: `hyperpolymath/affinescript`. Standard modules: `affinescript-libraries`. Syntax is TypeScript-shaped surface over a checked affine core (resources consumed at most once) compiling to typed WebAssembly. |
| **Ephapax** | `*.eph` | **Linear security core** | Owns lifecycle invariants, exactly-once capabilities, and zero-copy IPC (`selur` bridge). |
| **Idris2** | `*.idr`, `*.ipkg` | **Formal verification & ABI layout** (`src/idris2/`, `src/abi/`) | Must compile with `opts = "--total"`. **Never** introduce `believe_me`, `assert_total`, or unproven holes (`?hole`). |
| **Rust** | `*.rs` | **CLI, MCP server, local state engine** (`src/rust/`) | Memory-safe, zero-cost systems code. Respect the fail-closed security architecture in `src/rust/build.rs`. |
| **Elixir** | `*.ex`, `*.exs` | **Container orchestration & reversibility** (`src/elixir/`) | `gen_statem` lifecycle, Bennett-reversible journal, temporal isolation. |
| **Ada/SPARK** | `*.ads`, `*.adb` | **High-integrity security gatekeeper** (`src/ada/`) | Specs enforce `SPARK_Mode (On)` with explicit `Pre =>` and `Post =>` contracts. Untrusted FFI boundaries use `SPARK_Mode (Off)`. |
| **Zig** | `*.zig` | **FFI implementation layer** (`ffi/zig/`) | Direct Idris2->Zig FFI; C-compatible ABI exports without C headers. |

> **Legacy Retirement Note:** ReScript (`.res`) is deprecated and grandfathered only via `.hypatia-baseline.json`. **Do not write new `.res` code**; new adapter/UI code must be written in **AffineScript** (`.affine`).

---

## 3. Working With First-Party Languages

### AffineScript (`.affine`, `.afs`)
- **Semantics:** Affine type system (variables/resources can be used *at most once* unless explicitly marked cloneable/shared).
- **Surface:** TypeScript-like syntax tokens and expression structure.
- **Imports:** Standard libraries and interfaces reside in `hyperpolymath/affinescript-libraries`.
- **Target:** Typed WebAssembly (Wasm).

### Ephapax (`.eph`)
- **Semantics:** Strictly linear type system (resources *must* be consumed *exactly once*).
- **Use:** Security token handoffs, revocable capabilities, and kernel ring-buffer boundaries.

---

## 4. Engineering & Tooling Invariants

1. **Task Automation via `just`:**
   - All tasks are managed through `Justfile` and `build/just/`.
   - Run `just` to view available recipes.
   - Run `just validate` or `just doctor` to check repository health.
2. **Byte & Line-Ending Hygiene:**
   - All text files must use strict Unix `LF` line endings (`* text=auto eol=lf`).
   - Binary files must be flagged `binary` to prevent corruption.
3. **Receipts & Honest Status:**
   - Consult `docs/EXPLAINME.adoc` and `STATUS.md` before claiming features work. If a subsystem is a specification or prototype, acknowledge it honestly rather than generating fake or mocked passing tests.
