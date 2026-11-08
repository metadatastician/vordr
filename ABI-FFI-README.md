<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Vörðr ABI/FFI Documentation

## Overview

Vörðr follows the **Hyperpolymath RSR Standard** for ABI and FFI design:

- **ABI (Application Binary Interface)** defined in **Idris2** (`src/abi/`) with formal proofs
- **FFI (Foreign Function Interface)** implemented in **Zig** (`ffi/zig/`) for native C compatibility
- **Generated C headers** (`generated/abi/vordr.h`) bridge the Idris2 ABI to Zig FFI
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
├── generated/                  # Auto-generated files
│   └── abi/
│       └── vordr.h             # Generated from Idris2 ABI
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

All proofs in `Types.idr` and `Foreign.idr` are compiled with `%default total` with **zero `believe_me` escapes, zero `assert_total`, and zero holes**.

## Exported Functions (`ffi/zig/src/main.zig`)

| Function | Signature | Purpose |
| :--- | :--- | :--- |
| `vordr_init` | `() -> ?*anyopaque` | Allocate and initialize Vörðr context |
| `vordr_free` | `(?*anyopaque) -> void` | Free context (sets dead sentinel) |
| `vordr_process` | `(?*anyopaque, u32) -> u32` | Evaluate capability bitmask against policy |
| `vordr_process_array` | `(?*anyopaque, ?[*]const u8, u32) -> u32` | Validate binary policy document (`VPOL`) |
| `vordr_get_string` | `(?*anyopaque) -> ?[*:0]const u8` | Retrieve context status string |
| `vordr_free_string` | `(?[*:0]const u8) -> void` | Free string allocated by library |
| `vordr_last_error` | `() -> ?[*:0]const u8` | Get thread-local error string |
| `vordr_version` | `() -> [*:0]const u8` | Return library version string |
| `vordr_is_initialized` | `(?*anyopaque) -> u32` | Check if handle is valid and active |
| `vordr_create_container` | `(?*anyopaque, ?[*:0]const u8, ?[*:0]const u8) -> u32` | Create container entry |
| `vordr_start_container` | `(?*anyopaque, ?[*:0]const u8) -> u32` | Start container |
| `vordr_stop_container` | `(?*anyopaque, ?[*:0]const u8) -> u32` | Stop container |
| `vordr_list_containers` | `(?*anyopaque, ?*[*:0]u8) -> u32` | List containers in JSON |

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
