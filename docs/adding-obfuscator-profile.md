# Adapt new native obfuscator 变体

j2c-dumper's static analysis path: **profile** Description of each type of mixer's variation.
Built-in two:

- `native_obfuscator` – radioegor146/native-obfuscator + any compatible 
Derived from (reserve `"Cannot invoke 
RegisterNatives）
- `j2cc` — me.x150.j2cc single share `initClass` 派发

Any native-obfuscator-family-compatible binary can be used for **openbox** automatic detection.
To handle a new variant (eg BiscuitObfuscator, future obfuscator-X), just
Create a profile.

## 1、profile what does it contain

`py/binary_introspect/binary_introspect/profile.py`
`Profile` data categories defined All settings knobs:

| field | 干嘛
|---|---|
| `name` | CLI 名字 (`--profile <name>`) |
| `arch_filter` / `os_filter` | 只在动性性数/系统 (e.g. `("x86_64",") / ("windows")`) |
| `register_natives_index` | JNI vtable 里 RegisterNatives index of index, default 215 |
| `harvest_strategy` | `"per_class"` (性命类次性 RegisterNatives) 或 `"shared_dispatch"` (j2cc 家定公司 dispatch) |
| `invoke_error_re` | Error string definition, definition name set `owner` / `name` / `args` |
| `skip_if_patterns` | Group `(cond_re, body_re)` — matching if statement 被 lifter 丢弃 (see native-side bookkeeping) |
| `detector` | Selectable callable, given 0..1 fraction to indicate whether current binary matches this profile.
| `helper_fingerprints` | 把 Ghidra output デロト`FUN_xxxx` 助按按 (parameter shape → 语义) 性回去 |

## 2、Minimum change: Only change the error string format

Suppose there is an obfuscator-X, error message format, `"Cannot invoke X.Y.Z(args)"`
Change became `"Failed to call
profile change one field:

``python
# my_profiles/obfuscator_x.py
import again
from binary_introspect.profile import Profile, register_profile

register_profile(Profile( 
name="obfuscator_x", 
description="ObfuscatorX (custom throw-format)", 
arch_filter=("x86_64",), 
invoke_error_re=re.compile( 
r"^Failed\s+to\s+call\s+" 
r"(?P<owner>[\w.$]+)\.(?P<name>[\w$<>]+)" 
r"\((?P<args>[^)]*)\)$" 
), 
skip_if_patterns=[], # 中国 if guards
))
```

Place it on `PYTHONPATH` and `import` at startup. Just like this:

```bash
PYTHONPATH=./my_profiles python -c "import obfuscator_x" \ 
binary-introspect introspect ./mybin.dll -o binary.json --profile obfuscator_x
```

## 2nd、depth change：new harvest strategy

If the new variant RegisterNatives is not "each category at once" not "j2cc shared dispatch",
And for example ** each class method table is .rdata 里an array、由init function direct input**——
You need to add one `harvest_strategy` value and implement the corresponding function in `jni_tables.py`.

Steps：

1. On `profile.py` of `harvest_strategy` field document field and add new strategy
2. On `jni_tables.py` of `find_jni_method_tables` 里Add new branch: 
``python 
if profile.harvest_strategy == "rdata_table": 
branches = _harvest_rdata_table(cs, site, exec_rngs, profile) 
#... 
```
3. Implement `_harvest_rdata_table` function

## 四、Custom test

`detector` is `Callable[[lief.Binary], float]`：

``python
def my_detect(b): 
# check obfuscator - 
if b.format != lief.Binary.FORMATS.PE: return 0.0 
if any("__obfx_init" in s.name for s in b.exported_symbols): return 0.9 
return 0.0

register_profile(Profile(..., detector=my_detect))
```

When auto-checking, the score of all profiles takes the maximum value. Let your profile win in the mixed scene,
Returns ≥0.9 high score.

## 五、Forced selection at runtime

You can use `--profile <name>` in any scenario. Auto-detect:

```bash
binary-introspect introspect mybin.dll -o binary.json --profile obfuscator_x
binary-introspect introspect mybin.dll -o binary.json --profile generic
```

`binary-introspect introspect --list-profiles` Lists all registered profiles.

## 六、Current parameter 化、Require PR to be able to expand part

The following are currently hard coded/hidden, requiring changes to support new variants:

1. ** Architecture / ABI **：`mov r9d, imm` 拿 nMethods 是 **Windows x64** exclusive. 
Linux SysV x64 is `rcx`,ARM64 是 `w3`. 在 `jni_tables.py:_harvest_call` 
/ Register of `_harvest_dispatch`.
2. **`call qword ptr [reg + 0x6B8]` command mode**: default Intel syntax x64 format. 
ARM 反汇编 is completely different.
3. **`(**(code **)(*reg + 0xN))(...)` of vtable rewrite**：写死了 Ghidra 
x64 Output format: Other cross-compilers (IDA Hex-Rays、Binary Ninja) may use other syntax.
4. **Ghidra `local_X` / `lVarN` variable 命名**：lifter 里没显式 发用但 regex 
Form implicit dependence.

If you want to access an ARM64/Linux binary version, please post a PR to add the ABI. profile
Configuration item；These four points above are the access to the new architecture that must be resolved.
