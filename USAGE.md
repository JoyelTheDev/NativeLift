# NativeLift — Step-by-Step Usage Guide

This guide walks through every way to use NativeLift, from first-time setup to advanced workflows.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation & Build](#2-installation--build)
3. [Quick Start — Dynamic Recovery (Recommended)](#3-quick-start--dynamic-recovery-recommended)
4. [Dynamic Recovery — Multi-Run for Better Coverage](#4-dynamic-recovery--multi-run-for-better-coverage)
5. [Static Recovery with Ghidra](#5-static-recovery-with-ghidra)
6. [Combined Dynamic + Static Recovery](#6-combined-dynamic--static-recovery)
7. [Generating a Recovery Report](#7-generating-a-recovery-report)
8. [Running Tests](#8-running-tests)
9. [CI with Docker](#9-ci-with-docker)
10. [Advanced: Running Individual Pipeline Stages](#10-advanced-running-individual-pipeline-stages)
11. [Advanced: Adding a Custom Obfuscator Profile](#11-advanced-adding-a-custom-obfuscator-profile)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

Before anything else, make sure you have the following installed on your system.

**Required for all paths:**

| Tool | Minimum Version | How to check |
|------|----------------|--------------|
| JDK | 21 | `java -version` |
| Python | 3.11 | `python --version` |
| uv (Python package manager) | latest | `uv --version` |
| zig (C++ compiler) | 0.16+ | `zig version` |

**Required for the static path only:**

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| Ghidra | 11.x | Must have headless support |

**Install uv** (if not already installed):
```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Install zig** (for building the native agent):
```bash
# Download from https://ziglang.org/download/
# Extract and add to PATH, or set ZIG=/path/to/zig in your shell
```

---

## 2. Installation & Build

Clone the repository and build all three components. Run these from the root of the `nativelift/` directory.

### Step 2a — Build the JVM modules (Kotlin/ASM)

```bash
cd jvm
./gradlew installDist
cd ..
```

On Windows, use `gradlew.bat` instead:
```cmd
cd jvm
gradlew.bat installDist
cd ..
```

This builds `jar-parser`, `trace-to-bytecode`, `class-rebuilder`, and `common`. The binaries are placed under `jvm/<module>/build/install/<module>/bin/`.

### Step 2b — Set up the Python workspace

```bash
cd py
uv sync --all-packages
cd ..
```

This installs all Python packages (`j2c_dumper_cli`, `binary_introspect`, `manifest_merge`, `ast_matcher`, `snippet_importer`) into a shared virtual environment at `py/.venv/`.

### Step 2c — Build the native JVMTI agent (dynamic path only)

```bash
cd native
JDK_HOME="$JAVA_HOME" bash build.sh
cd ..
```

On Windows (PowerShell):
```powershell
cd native
$env:JDK_HOME = $env:JAVA_HOME
bash build.sh
cd ..
```

The output is placed at:
- `native/build/lib/j2c_agent.so` (Linux)
- `native/build/lib/j2c_agent.dylib` (macOS)
- `native/build/lib/j2c_agent.dll` (Windows)

> **Note:** If `JAVA_HOME` is not set, export it first:
> ```bash
> export JAVA_HOME=/path/to/your/jdk
> ```

---

## 3. Quick Start — Dynamic Recovery (Recommended)

This is the simplest and most reliable path. It runs your obfuscated JAR with the JVMTI agent attached, captures what Java calls the native methods make, and lifts those calls back to bytecode.

**You need:** the obfuscated JAR, and a command to run it.

```bash
python -m j2c_dumper_cli.main recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

**What happens internally:**
1. `jar-parser` scans the JAR and extracts class skeletons → `classes.json`
2. `binary-introspect` disassembles the embedded native library → `binary.json`
3. `manifest-merge` pairs class data with native function addresses → `manifest.json`
4. The JVMTI agent runs attached to your `--run-cmd`, recording every JNI call → `trace.jsonl`
5. `trace-to-bytecode` lifts the trace back to JVM bytecode → `recovered/*.json`
6. `class-rebuilder` stitches recovered bytecode into a new clean JAR → `clean.jar`

**To keep intermediate files** (for inspection or re-use):
```bash
python -m j2c_dumper_cli.main recover \
    obfuscated.jar \
    -o clean.jar \
    --run-cmd "java -jar obfuscated.jar" \
    --workdir ./workdir
```

---

## 4. Dynamic Recovery — Multi-Run for Better Coverage

If your JAR has multiple modes or code paths, run it multiple times with different inputs. NativeLift merges all traces automatically, so every branch you exercised gets recovered.

```bash
python -m j2c_dumper_cli.main recover \
    obfuscated.jar \
    -o clean.jar \
    --run-cmd "java -jar obfuscated.jar --mode login" \
    --run-cmd "java -jar obfuscated.jar --mode register" \
    --run-cmd "java -jar obfuscated.jar --benchmark" \
    --workdir ./workdir
```

**How merging works:**
- `bind` events (which function maps to which native method) are deduplicated
- `enter` / `exit` events accumulate from all runs
- Any code path that executed in any run is included in the recovered output

> **Tip:** The more code paths you exercise, the better the recovery. Cover as many features of the target application as possible.

---

## 5. Static Recovery with Ghidra

The static path decompiles the native library using Ghidra without running the JAR at all. This is useful when the JAR cannot be executed (missing dependencies, locked environment, etc.).

**You need:** the obfuscated JAR, the native `.dll` / `.so`, and a Ghidra installation.

### Step 5a — Parse the JAR

```bash
python -m j2c_dumper_cli.main parse-jar \
    obfuscated.jar \
    -o classes.json
```

### Step 5b — Introspect the native binary

```bash
python -m j2c_dumper_cli.main inspect-binary \
    natives.dll \
    -o binary.json
```

> **Note:** On Linux/macOS use the `.so` file. The file is usually embedded in the JAR itself — extract it with `unzip -p obfuscated.jar path/to/library.so > natives.so` if needed.

### Step 5c — Merge into a manifest

```bash
python -m j2c_dumper_cli.main merge-manifest \
    classes.json binary.json \
    -o manifest.json
```

### Step 5d — Run Ghidra headless to decompile functions

On Linux/macOS:
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra-project MyProj \
    -import natives.dll \
    -scriptPath path/to/nativelift/ghidra/scripts \
    -postScript DumpFromManifest.java manifest.json ghidra-dump.json
```

On Windows:
```cmd
%GHIDRA_HOME%\support\analyzeHeadless.bat C:\ghidra-project MyProj ^
    -import natives.dll ^
    -scriptPath path\to\nativelift\ghidra\scripts ^
    -postScript DumpFromManifest.java manifest.json ghidra-dump.json
```

> Replace `$GHIDRA_HOME` / `%GHIDRA_HOME%` with the path to your Ghidra installation.

### Step 5e — Lift pseudo-C to JVM bytecode

```bash
python -m j2c_dumper_cli.main static-reverse \
    ghidra-dump.json \
    --manifest manifest.json \
    -o recovered/
```

### Step 5f — Rebuild the clean JAR

```bash
python -m j2c_dumper_cli.main rebuild \
    --input obfuscated.jar \
    --recovered recovered/ \
    --manifest manifest.json \
    -o clean.jar
```

---

## 6. Combined Dynamic + Static Recovery

For maximum coverage, run dynamic tracing first, then supplement with static analysis for any methods that weren't exercised at runtime. The `recover` command handles this automatically when both `--run-cmd` and `--ghidra-dump` are provided.

```bash
# First produce the Ghidra dump (steps 5a–5d above), then:
python -m j2c_dumper_cli.main recover \
    obfuscated.jar \
    -o clean.jar \
    --run-cmd "java -jar obfuscated.jar" \
    --ghidra-dump ghidra-dump.json \
    --workdir ./workdir
```

Dynamic recovery fills in methods that executed; static recovery fills in the rest. The `class-rebuilder` merges both recovered sets before writing the output JAR.

---

## 7. Generating a Recovery Report

Add `--report report.html` to any `recover` command to get a self-contained HTML report:

```bash
python -m j2c_dumper_cli.main recover \
    obfuscated.jar \
    -o clean.jar \
    --run-cmd "java -jar obfuscated.jar" \
    --report report.html
```

Open `report.html` in any browser. It shows:
- Overall recovery rate (recovered methods vs. stubs)
- Per-class breakdown with expandable method rows
- Lifter warnings per method
- Confidence badge (high / low) and source (dynamic / static) per method

---

## 8. Running Tests

### Unit tests (no Ghidra required)

These test the AST-matcher and lifter using a pre-recorded Ghidra dump fixture. They run in seconds with no external dependencies.

```bash
cd py
uv run pytest ../tests/unit/test_nativelift.py -v
```

### End-to-end tests

The e2e test runs the full pipeline on a real obfuscated JAR. You need to provide a test JAR at `../e2e-test/out/Hello.jar` (obfuscate a simple "Hello World" jar with native-obfuscator first).

```bash
bash tests/e2e/test_pipeline.sh
```

The test builds all modules, runs `recover`, verifies the output JAR executes correctly, and checks that all intermediate artifacts were produced.

---

## 9. CI with Docker

If you don't have Ghidra installed locally, use Docker to run the full pipeline including Ghidra headless:

```bash
docker compose -f docker/docker-compose.ci.yml run --rm e2e
```

This uses `docker/Dockerfile.ci` which bundles all dependencies including Ghidra, Python, JDK 21, and zig. No host installation is needed beyond Docker.

---

## 10. Advanced: Running Individual Pipeline Stages

Each stage can be run independently. This is useful for debugging, inspecting intermediate artifacts, or integrating NativeLift into custom workflows.

### Parse a JAR into class skeletons
```bash
python -m j2c_dumper_cli.main parse-jar input.jar -o classes.json
```

### Introspect a native binary
```bash
python -m j2c_dumper_cli.main inspect-binary library.so -o binary.json
```

### Merge class + binary data into a manifest
```bash
python -m j2c_dumper_cli.main merge-manifest classes.json binary.json -o manifest.json

# Without a binary (dynamic-only workflow)
python -m j2c_dumper_cli.main merge-manifest classes.json -o manifest.json
```

### Capture a dynamic trace only (don't lift yet)
```bash
python -m j2c_dumper_cli.main dynamic-trace \
    --run "java -jar obfuscated.jar" \
    -o trace.jsonl
```

### Lift a trace to bytecode
```bash
python -m j2c_dumper_cli.main trace-to-bc \
    trace.jsonl \
    --manifest manifest.json \
    -o recovered/
```

### Lift a Ghidra dump to bytecode
```bash
python -m j2c_dumper_cli.main static-reverse \
    ghidra-dump.json \
    --manifest manifest.json \
    -o recovered/
```

### Rebuild the final JAR
```bash
python -m j2c_dumper_cli.main rebuild \
    --input obfuscated.jar \
    --recovered recovered/ \
    --manifest manifest.json \
    -o clean.jar
```

### Lifter feature flags

The static-path lifter has fine-grained toggles for every inference step. List all available flags:
```bash
python -m ast_matcher.cli --list-flags
```

Enable or disable individual flags:
```bash
python -m ast_matcher.cli ghidra-dump.json \
    --manifest manifest.json \
    -o recovered/ \
    --disable use_stack_tracker \
    --enable resolve_lookup_tables
```

---

## 11. Advanced: Adding a Custom Obfuscator Profile

If your target uses an obfuscator variant not covered by the built-in profiles, you can add a custom profile without modifying core source files.

### Minimal profile (change error string format only)

```python
# my_profiles/my_obfuscator.py
import re
from binary_introspect.profile import Profile, register_profile

register_profile(Profile(
    name="my_obfuscator",
    description="MyObfuscator (custom throw-format)",
    arch_filter=("x86_64",),
    invoke_error_re=re.compile(
        r"^Failed\s+to\s+call\s+"
        r"(?P<owner>[\w.$]+)\.(?P<name>[\w$<>]+)"
        r"\((?P<args>[^)]*)\)$"
    ),
    skip_if_patterns=[],
))
```

Use it:
```bash
PYTHONPATH=./my_profiles python -c "import my_obfuscator" && \
python -m j2c_dumper_cli.main inspect-binary mylib.dll \
    -o binary.json \
    --profile my_obfuscator
```

### Force a specific profile
```bash
python -m j2c_dumper_cli.main inspect-binary mylib.dll \
    -o binary.json \
    --profile generic
```

### List all registered profiles
```bash
python -m binary_introspect.cli introspect --list-profiles
```

---

## 12. Troubleshooting

### "JVM module not built" error
```
FileNotFoundError: JVM module 'jar-parser' not built.
```
**Fix:** Run `./gradlew installDist` inside the `jvm/` directory.

### "native agent not built" error
```
FileNotFoundError: native agent not built. Run native/build.sh first.
```
**Fix:** Run `JDK_HOME="$JAVA_HOME" bash build.sh` inside the `native/` directory.

### "Could not locate j2c-dumper project root" error
This means the CLI cannot find the project root. Run commands from inside the `nativelift/` directory, or make sure `jvm/settings.gradle.kts` exists.

### Low recovery rate on static path
- Try running the dynamic path first to supplement static results.
- Check if `StackTracker` is enabled (it is by default). If not, re-enable with `--enable use_stack_tracker`.
- Use `--report report.html` to see exactly which methods are stubbed and why.

### Schema version warnings
```
schema warning: schemaVersion mismatch
```
This means an intermediate artifact was generated by a different version of NativeLift. Re-run the pipeline from scratch with a `--workdir` pointing to a fresh directory, or pass `--no-validate-schemas` to suppress the warning.

### The target JAR won't run with the agent
Some JARs check for attached agents or instrument their own class loading. Try:
```bash
# Add -Djvmtiagent.suppress=true or similar JVM flags your target needs
--run-cmd "java -Dsome.flag=true -jar obfuscated.jar"
```

### AArch64 binary not recognised
Make sure you are using the upgraded version of NativeLift that includes `arch/aarch64_sysv.py`. Verify with:
```bash
python -m binary_introspect.cli introspect --list-profiles
```
The output should mention AArch64 support.

### Ghidra headless hangs
Ensure Ghidra's headless mode has write access to the project directory, and that no other Ghidra instance is using the same project path. Use a fresh temp directory per run:
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra-$(date +%s) MyProj \
    -import natives.dll ...
```

---

## Full Example: End-to-End Dynamic Recovery

Below is a complete walkthrough from a fresh clone to a recovered JAR.

```bash
# 1. Clone and enter the project
git clone <repo-url> nativelift
cd nativelift

# 2. Build JVM modules
cd jvm && ./gradlew installDist && cd ..

# 3. Set up Python workspace
cd py && uv sync --all-packages && cd ..

# 4. Build the native JVMTI agent
cd native && JDK_HOME="$JAVA_HOME" bash build.sh && cd ..

# 5. Run recovery (single command, all steps automated)
python -m j2c_dumper_cli.main recover \
    obfuscated.jar \
    -o clean.jar \
    --run-cmd "java -jar obfuscated.jar" \
    --report report.html \
    --workdir ./workdir

# 6. Inspect the results
java -jar clean.jar                  # verify it runs
open report.html                     # see recovery statistics
ls workdir/                          # inspect intermediate artifacts
```

That's it. The output `clean.jar` has real JVM bytecode in place of every native stub.
