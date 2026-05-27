"""AArch64 (ARM64) System V / AAPCS64 ABI.

Used by Android arm64-v8a ``.so`` libraries, Linux AArch64, and Apple
Silicon macOS / iOS.  This is the architecture most commonly found in
Android APK native libraries — the primary real-world target for
deobfuscating JARs that ship arm64 native blobs.

Calling convention — AAPCS64
------------------------------
Integer / pointer arguments: x0, x1, x2, x3, x4, x5, x6, x7.

``JNIEnv *RegisterNatives(JNIEnv *env, jclass clazz,
                           const JNINativeMethod *methods, jint nMethods)``

maps to:

  - x0 = env      (JNIEnv *)
  - x1 = clazz    (jclass)
  - x2 = methods  (JNINativeMethod *)
  - x3 = nMethods (jint)   ← this is what we scan for

PC-relative addressing
-----------------------
AArch64 uses a two-instruction sequence:

  ADRP  xN, <page>      ; load page-aligned PC + disp21 into xN
  ADD   xN, xN, #imm12  ; add low-12-bit offset

or for loads:

  ADRP  xN, <page>
  LDR   xN, [xN, #imm12]

We track the ADRP result and fold the ADD/LDR in the next instruction.

Indirect vtable call
---------------------
Ghidra / native-obfuscator translates ``env->RegisterNatives(...)`` to:

  LDR  x8, [x0]          ; load function table pointer from JNIEnv
  LDR  x9, [x8, #0x6B8]  ; load fn ptr at vtable offset
  BLR  x9                ; call it

We detect the ``LDR  reg, [reg, #offset]`` + ``BLR  reg`` pattern.
"""

from __future__ import annotations

from typing import Any

import lief

from .base import Abi, register_abi

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM
    from capstone import arm64_const as _a64
    _CAPSTONE_OK = True
except ImportError:
    _CAPSTONE_OK = False
    CS_ARCH_ARM64 = 0
    CS_MODE_ARM = 0

# lief AARCH64 machine constants
_ELF_AARCH64  = 0xB7          # EM_AARCH64
_MACHO_ARM64  = 0x0100000C    # CPU_TYPE_ARM64


class _AArch64Abi(Abi):
    """AArch64 AAPCS64 implementation."""

    # ADRP result cache: reg_id -> absolute page address.
    # Populated while scanning instructions; consumed by the next ADD/LDR.
    _adrp_cache: dict[int, int]

    def __init__(self) -> None:
        # We defer capstone constants to runtime so the import is optional.
        if not _CAPSTONE_OK:
            raise ImportError(
                "capstone is required for AArch64 support.  "
                "Install it with: pip install capstone"
            )
        n_methods_reg = (_a64.ARM64_REG_X3, _a64.ARM64_REG_W3)
        super().__init__(
            name="aarch64-sysv",
            description=(
                "AArch64 AAPCS64 (Android arm64-v8a, Linux AArch64, Apple Silicon). "
                "nMethods passed in x3 / w3."
            ),
            pointer_size=8,
            cs_arch=CS_ARCH_ARM64,
            cs_mode=CS_MODE_ARM,
            n_methods_arg_regs=n_methods_reg,
            pc_register=0,  # AArch64 has no explicit "PC" reg in capstone operands
            binary_matches=[
                ("ELF",   _ELF_AARCH64),
                ("MachO", _MACHO_ARM64),
            ],
        )
        self._adrp_cache = {}

    # ------------------------------------------------------------------
    # Vtable-call recognition
    # ------------------------------------------------------------------

    def is_indirect_vtable_call(self, ins: Any) -> int | None:
        """Detect ``LDR  xN, [xM, #offset]`` which loads a function pointer
        from a vtable at *offset* bytes.  The following ``BLR xN`` is the
        actual call; we return the offset from the LDR.

        We also accept ``BLR xN`` directly when a previous LDR loaded from
        an offset that we recorded in the pending-call cache.
        """
        if ins.mnemonic == "ldr" and len(ins.operands) == 2:
            dst = ins.operands[0]
            src = ins.operands[1]
            if (dst.type == _a64.ARM64_OP_REG and
                    src.type == _a64.ARM64_OP_MEM and
                    src.mem.disp != 0 and src.mem.index == 0):
                # Store for potential BLR on the next instruction.
                self._pending_ldr_offset = src.mem.disp
                self._pending_ldr_dst   = dst.reg
                return None  # don't emit yet; wait for BLR

        if ins.mnemonic == "blr" and len(ins.operands) == 1:
            target_reg = ins.operands[0].reg
            offset = getattr(self, "_pending_ldr_offset", None)
            pending_dst = getattr(self, "_pending_ldr_dst", None)
            if offset is not None and pending_dst == target_reg:
                self._pending_ldr_offset = None
                self._pending_ldr_dst    = None
                return offset
        else:
            # Any non-BLR instruction after an LDR clears the pending state.
            if ins.mnemonic != "ldr":
                self._pending_ldr_offset = None
                self._pending_ldr_dst    = None

        return None

    # ------------------------------------------------------------------
    # PC-relative LEA (ADRP + ADD or ADRP + LDR)
    # ------------------------------------------------------------------

    def decode_pc_relative_lea(self, ins: Any) -> int | None:
        """Handle AArch64's two-instruction PC-relative addressing.

        - On ``ADRP xN, page``: record ``{reg: page_va}`` in the cache.
        - On ``ADD  xN, xN, #imm``: if src matches a cached ADRP, return
          ``page_va + imm`` (the absolute address of the constant).
        - On ``LDR  xN, [xN, #imm]``: same, but the target is a pointer
          table so we return the load address for callers that want to
          follow it.
        """
        if ins.mnemonic == "adrp" and len(ins.operands) == 2:
            dst = ins.operands[0]
            imm = ins.operands[1]
            if (dst.type == _a64.ARM64_OP_REG and
                    imm.type == _a64.ARM64_OP_IMM):
                # ADRP computes (PC & ~0xFFF) + (imm << 12).
                # Capstone resolves this for us and stores the page VA in imm.value.
                self._adrp_cache[dst.reg] = imm.imm
            return None

        if ins.mnemonic in ("add", "ldr") and len(ins.operands) >= 2:
            dst = ins.operands[0]
            src = ins.operands[1]
            # ADD xN, xN, #imm
            if (ins.mnemonic == "add" and
                    dst.type == _a64.ARM64_OP_REG and
                    src.type == _a64.ARM64_OP_REG and
                    len(ins.operands) == 3 and
                    ins.operands[2].type == _a64.ARM64_OP_IMM):
                page = self._adrp_cache.pop(src.reg, None)
                if page is not None:
                    return page + ins.operands[2].imm
            # LDR xN, [xN, #imm]
            if (ins.mnemonic == "ldr" and
                    dst.type == _a64.ARM64_OP_REG and
                    src.type == _a64.ARM64_OP_MEM and
                    src.mem.index == 0):
                page = self._adrp_cache.pop(src.mem.base, None)
                if page is not None:
                    return page + src.mem.disp

        return None

    # ------------------------------------------------------------------
    # Stack store recognition
    # ------------------------------------------------------------------

    def is_stack_store(self, ins: Any) -> tuple[int, int] | None:
        """Detect ``STR  xN, [sp, #disp]`` or ``STR  xN, [x29, #disp]``
        (frame-pointer or stack-pointer based stores).
        """
        if ins.mnemonic not in ("str", "stp"):
            return None
        if not ins.operands:
            return None
        # For STR: operands are [src_reg, mem]
        if ins.mnemonic == "str" and len(ins.operands) == 2:
            src = ins.operands[0]
            mem = ins.operands[1]
            if (src.type == _a64.ARM64_OP_REG and
                    mem.type == _a64.ARM64_OP_MEM and
                    mem.mem.index == 0 and
                    mem.mem.base in (_a64.ARM64_REG_SP, _a64.ARM64_REG_X29)):
                return (mem.mem.disp, src.reg)
        return None

    # ------------------------------------------------------------------
    # nMethods immediate load recognition
    # ------------------------------------------------------------------

    def is_n_methods_load(self, ins: Any) -> int | None:
        """Detect ``MOV  w3, #imm`` or ``MOV  x3, #imm`` which sets nMethods."""
        if ins.mnemonic in ("mov", "movz") and len(ins.operands) == 2:
            dst = ins.operands[0]
            src = ins.operands[1]
            if (dst.type == _a64.ARM64_OP_REG and
                    src.type == _a64.ARM64_OP_IMM and
                    dst.reg in self.n_methods_arg_regs):
                return src.imm
        return None

    def applies_to(self, binary: lief.Binary) -> bool:
        fmt = self._fmt_str(binary)
        machine = self._machine_id(binary)
        return (fmt, machine) in [("ELF", _ELF_AARCH64), ("MachO", _MACHO_ARM64)]


# Register the ABI if capstone supports AArch64.
if _CAPSTONE_OK:
    register_abi(_AArch64Abi())
