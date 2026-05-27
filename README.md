# NativeLift

> Formerly `c2j-native-deobfuscator`

**NativeLift** reverse-engineers JNI-native-obfuscated JARs back into readable Java bytecode. It targets [`native-obfuscator`](https://github.com/radioegor146/native-obfuscator) and its derivatives (e.g. j2cc) — anything that transpiles JVM bytecode to C++ then re-invokes Java through the JNI from a packaged `.dll` / `.so`.

License: **GPLv3**

---

## What It Does

Java obfuscators like `native-obfuscator` and `j2cc` convert JVM bytecode into C++ native methods, then package those as a shared library (`.dll` / `.so`). NativeLift reverses this process and produces a clean `out.jar` where every native stub has been replaced with real JVM bytecode — and all loader / native-blob entries have been stripped.

### Two Recovery Paths

| Path | What you need | How it works |
|------|--------------|--------------|
| **Dynamic** | Obfuscated JAR + a runnable command | Attaches a JVMTI agent, observes the live JNI call stream, and lifts it back to JVM bytecode |
| **Static** | Obfuscated JAR + Ghidra | Locates JNI method tables in the native binary, decompiles each function, and lifts pseudo-C to JVM bytecode |

Both paths produce the same output format and can be combined — dynamic recovery handles what runs, static handles what doesn't.

---

## What's New (Upgraded Version)

### StackTracker — fewer stubs on the static path
The Ghidra-path lifter now runs a Python `StackTracker` post-pass that maintains an operand-stack depth model after every emitted instruction. It inserts corrective placeholder pushes (`ACONST_NULL`, `ICONST_0`, etc.) before any instruction that would underflow the stack. This eliminates most "stack-imbalanced → stub" fallbacks that the previous version suffered, dramatically improving static-path coverage on real binaries. Disable with `--disable use_stack_tracker`.

### AArch64 / ARM64 support
`binary_introspect` now includes an AArch64 (AAPCS64) ABI module (`arch/aarch64_sysv.py`) supporting:
- Android `arm64-v8a` `.so` libraries
- Linux AArch64 and Apple Silicon macOS binaries
- ADRP + ADD / LDR two-instruction PC-relative addressing
- `LDR + BLR` indirect vtable call pattern

Previously only `amd64-windows` and `amd64-sysv` were supported.

### Multi-run trace merging
Supply `--run-cmd` multiple times to run the target with different inputs and merge all resulting traces for better branch coverage. `bind` events are deduplicated; `enter`/`exit` events accumulate across all runs.

### HTML recovery report
Pass `--report report.html` to generate a self-contained, interactive HTML report showing overall recovery rate, per-class breakdown, lifter warnings per method, and a confidence badge per method.

### Schema version enforcement
Every pipeline stage now validates the `schemaVersion` of its inputs. Version mismatches produce a clear warning instead of silently producing wrong output. Opt out with `--no-validate-schemas`.

### Docker CI for Ghidra
`docker/Dockerfile.ci` and `docker/docker-compose.ci.yml` containerise the Ghidra headless invocation so static-path e2e tests can run in CI without a host Ghidra installation.

### Ghidra-free unit tests
`tests/unit/test_nativelift.py` + `tests/fixtures/ghidra-dump-snake.json` let the AST-matcher half of the pipeline be tested without re-running Ghidra.

---

---

## Architecture Overview

The pipeline is composed of independent stages, each consuming and producing versioned JSON artifacts:

```
in.jar ──┬──▶ jar-parser ──▶ classes.json ────────────────┐
         │                                                 │
.dll/.so ┴──▶ binary-introspect ──▶ binary.json ──────────▼
                                               manifest-merge ──▶ manifest.json
                                                       │
                        ┌──────────────────────────────┴──────────────────────────────┐
                        │ Dynamic path                              Static path        │
                        ▼                                                              ▼
              JVMTI agent (native/)                              Ghidra headless
              → trace.jsonl                                      → ghidra-dump.json
                        │                                                              │
                        ▼                                                              ▼
              trace-to-bytecode                                 ast-matcher
                        │                                                              │
                        └────────────────── recovered/*.json ──────────────────────────┘
                                                    │
                                                    ▼
                                             class-rebuilder
                                                    │
                                                    ▼
                                                 out.jar
```

### Module Summary

| Module | Language | Input | Output | Role |
|--------|----------|-------|--------|------|
| `jvm/jar-parser` | Kotlin + ASM | `input.jar` | `classes.json` | Walk classes, find loader, flag obfuscated natives |
| `py/binary_introspect` | Python + LIEF + capstone | `.dll` / `.so` | `binary.json` | Disassembly-driven discovery of native-method tables |
| `py/manifest_merge` | Python | `classes.json` + `binary.json` | `manifest.json` | Cross-check and bind function addresses to (class, method, desc) |
| `native/` | C++ + JVMTI | runnable jar | `trace.jsonl` | Hook `RegisterNatives` + 80+ JNI functions at runtime |
| `jvm/trace-to-bytecode` | Kotlin + ASM | `manifest.json` + `trace.jsonl` | `recovered/*.json` | Translate JNI call sequences back to JVM bytecode |
| `ghidra/scripts/` | Java (Ghidra API) | native blob + manifest | `ghidra-dump.json` | Decompile each function address to pseudo-C |
| `py/ast_matcher` | Python + tree-sitter | `ghidra-dump.json` + manifest | `recovered/*.json` | Lift pseudo-C to JVM bytecode |
| `jvm/class-rebuilder` | Kotlin + ASM | `input.jar` + `recovered/` + manifest | `output.jar` | Replace stubs, strip loader |
| `py/j2c_dumper_cli` | Python + typer | — | — | Top-level orchestrator CLI |

---

## Runtime Requirements

| Component | Minimum Version |
|-----------|----------------|
| JDK | 21 |
| Python | 3.11 |
| `lief` | 0.14+ |
| `capstone` | 5.x |
| `tree-sitter-c` | 0.21+ |
| Ghidra (static path only) | 11.x |
| zig (native agent build) | 0.16+ |
| uv (Python workspace) | latest |

---

## Supported Obfuscator Profiles

NativeLift ships with three built-in profiles that are auto-detected:

| Profile | Description |
|---------|-------------|
| `native_obfuscator` | radioegor146/native-obfuscator + compatible derivatives |
| `j2cc` | me.x150.j2cc — single shared `initClass` dispatch |
| `generic` | Fallback using pure JNI-spec knowledge only |

Custom profiles can be added without modifying the core pipeline. See [`docs/adding-obfuscator-profile.md`](docs/adding-obfuscator-profile.md).

---

## CLI Reference

All commands are run via:
```bash
python -m j2c_dumper_cli.main <command> [options]
```

### `recover` (one-shot orchestration)
```
recover JAR -o OUTPUT [options]
  --run-cmd CMD         Command to run the jar (repeat for multiple runs)
  --lib PATH            Native library (auto-extracted from jar if omitted)
  --ghidra-dump PATH    Pre-generated Ghidra dump JSON (skip Ghidra invocation)
  --report PATH         Write an HTML recovery report after rebuild
  --workdir PATH        Working directory for intermediate files
  --no-dynamic          Skip dynamic trace
  --no-static           Skip static reverse
  --no-validate-schemas Disable schema version enforcement
```

### Individual stage commands
```
parse-jar        JAR -o classes.json
inspect-binary   LIB -o binary.json
merge-manifest   classes.json [binary.json] -o manifest.json
dynamic-trace    --run CMD -o trace.jsonl
trace-to-bc      trace.jsonl --manifest manifest.json -o recovered/
static-reverse   ghidra-dump.json -o recovered/ [--manifest manifest.json]
rebuild          --input in.jar --recovered recovered/ -o out.jar [--manifest manifest.json]
```

---

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Pipeline design, module boundaries, extension points
- [ROADMAP.md](docs/ROADMAP.md) — Known limitations and planned work
- [adding-obfuscator-profile.md](docs/adding-obfuscator-profile.md) — How to add a new obfuscator variant
- [static-reverse-approach.md](docs/static-reverse-approach.md) — Deep-dive on the static analysis path
- [manual-restoration.md](docs/manual-restoration.md) — Manual recovery techniques

---

## License

Released under **GPL v3**. See [LICENSE](LICENSE).
