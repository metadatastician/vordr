<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:e7086b794fb19b26d723ee7a35b8da1527bc58ddc1754d16f3e9060a696fa73c -->

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Vörðr ABI/FFI Documentation

## Overview

Vörðr follows the **Hyperpolymath RSR Standard** for ABI and FFI design:

- **ABI (Application Binary Interface)** defined in **Idris2** (`src/abi/`) with formal proofs
- **FFI (Foreign Function Interface)** implemented in **Zig** (`ffi/zig/`) for native C compatibility
- **Direct C ABI**: Zig exports C-compatible symbols directly. No generated header or header-generation step is provided; consumers must supply compatible declarations.
- **Cross-language consumption** across Rust, Elixir, AffineScript, and CLI tooling

## Architecture

```
┌─────────────────────────────────────────────┐
│  ABI Definitions (Idris2)                   │
│  src/abi/                                   │
│  - Types.idr      (Result codes & proofs)   │
│  - Foreign.idr    (FFI declarations)        │
└─────────────────┬───────────────────────────┘
                  │
                  │ generates (at compile time)
                  ▼
┌─────────────────────────────────────────────┐
│  C Headers (auto-generated)                 │
│  generated/abi/vordr.h                      │
└─────────────────┬───────────────────────────┘
                  │
                  │ imported by
                  ▼
┌─────────────────────────────────────────────┐
│  FFI Implementation (Zig)                   │
│  ffi/zig/src/main.zig                       │
│  - Implements C-compatible functions        │
│  - Zero-cost abstractions                   │
│  - Memory-safe by default                   │
└─────────────────┬───────────────────────────┘
                  │
                  │ compiled to libvordr.so/.a
                  ▼
┌─────────────────────────────────────────────┐
│  Any Language via C ABI                     │
│  - Rust CLI, Elixir NIF, AffineScript Wasm  │
└─────────────────────────────────────────────┘
```

## Directory Structure

```
vordr/
├── src/
│   ├── abi/                    # ABI definitions (Idris2)
│   │   ├── Types.idr           # Core result codes and total proofs
│   │   └── Foreign.idr         # FFI function declarations (total)
│   └── idris2/                 # Verification proofs (Container, SBOM, Attestation)
│
├── ffi/
│   └── zig/                    # FFI implementation (Zig)
│       ├── build.zig           # Build configuration
│       ├── src/
│       │   └── main.zig        # C-compatible FFI implementation
│       └── test/
│           └── integration_test.zig
│
└── src/rust/                   # Rust CLI, MCP server, and runtime
```

## Core ABI Types & Invariants (Idris2)

### Result Codes (`src/abi/Types.idr`)
The C ABI integer mapping matches `ffi/zig/src/main.zig` exactly:

| Result Code | C ABI Int | Meaning |
| :--- | :---: | :--- |
| `Ok` | `0` | Operation succeeded |
| `Error` | `1` | General error |
| `InvalidParam` | `2` | Bad argument or empty identifier |
| `OutOfMemory` | `3` | Allocation failed |
| `NullPointer` | `4` | Null handle or pointer passed |

`vordr_process` does not use the result codes above: denial returns zero, success returns the granted-capability mask, and an empty request returns `0xFFFF_FFFF`. Callers must interpret its return value using this function-specific contract.

All proofs in `Types.idr` and `Foreign.idr` are compiled with `%default total` with **zero `believe_me` escapes, zero `assert_total`, and zero holes**.

## Exported Functions (`ffi/zig/src/main.zig`)

| Function | Signature | Purpose |
| :--- | :--- | :--- |
| `vordr_init` | `() -> ?*anyopaque` | Allocate and initialize Vörðr context |
| `vordr_free` | `(?*anyopaque) -> void` | Free context (sets dead sentinel) |
| `vordr_process` | `(?*anyopaque, u32) -> u32` | Evaluate capability bitmask: zero on denial, granted mask on success, `0xFFFF_FFFF` for an empty request; not a result code |
| `vordr_process_array` | `(?*anyopaque, ?[*]const u8, u32) -> u32` | Validate binary policy document (`VPOL`) |
| `vordr_get_string` | `(?*anyopaque) -> ?[*:0]const u8` | Retrieve context status string |
| `vordr_free_string` | `(?[*:0]const u8) -> void` | Free string allocated by library |
| `vordr_last_error` | `() -> ?[*:0]const u8` | Get only thread-local errors, never errors stored in a valid context. Context failures (e.g. denied `vordr_process`) may yield null or a stale thread-local error; not a universal failure diagnostic |
| `vordr_version` | `() -> [*:0]const u8` | Return library version string |
| `vordr_is_initialized` | `(?*anyopaque) -> u32` | Check initialization; pass only a live handle or null. After `vordr_free`, discard the handle and never use it for validity checks |
| `vordr_create_container` | `(?*anyopaque, ?[*:0]const u8, ?[*:0]const u8) -> u32` | Stub: validates inputs but stores no container record |
| `vordr_start_container` | `(?*anyopaque, ?[*:0]const u8) -> u32` | Stub: validates inputs but changes no state |
| `vordr_stop_container` | `(?*anyopaque, ?[*:0]const u8) -> u32` | Stub: validates inputs but changes no state |
| `vordr_list_containers` | `(?*anyopaque, ?*[*:0]u8) -> u32` | Stub: always returns an empty JSON list. On success allocates the output string; caller must release it with `vordr_free_string` |

Successful return codes from the container stubs do not indicate completed container lifecycle operations.

## Building & Testing

### Build Zig FFI Library
```bash
cd ffi/zig
zig build
zig build test
```

### Integration Tests
```bash
cd ffi/zig
zig build test-integration
```

### Idris2 ABI Check
```bash
cd src/abi
idris2 --check Types.idr
idris2 --check Foreign.idr
```

## License

MPL-2.0


<!-- /coderabbit-ai-generated:v1 -->