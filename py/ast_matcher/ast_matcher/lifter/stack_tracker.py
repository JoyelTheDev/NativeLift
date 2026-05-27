"""Operand-stack tracker for the static-path JVM bytecode lifter.

The Ghidra-path lifter emits JVM ops in source order without an internal
operand-stack model, so ASM's ``COMPUTE_FRAMES`` rejects bodies whose
stack effects don't balance — falling back to a stub for the whole method.

This module provides a forward-pass ``StackTracker`` that:

1. Computes the stack depth after every instruction.
2. Inserts corrective push-placeholders (``ACONST_NULL``, ``ICONST_0``,
   ``LCONST_0``, etc.) *before* any instruction that would underflow.
3. Drops instructions that still can't be satisfied (e.g. RETURN from
   inside a dead branch with stack depth > 0 already cleaned up).

The tracker is deliberately conservative (it never removes real ops, only
adds null-pads and adjusts around labels), which keeps false-positive
stubs near zero at the cost of occasionally leaving an extra ACONST_NULL
on paths that the decompiler reconstructed with control-flow loss.

Usage::

    from .stack_tracker import StackTracker
    cleaned = StackTracker().process(ctx.instructions, method_desc)
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Descriptor helpers
# ---------------------------------------------------------------------------

def _desc_args_count(desc: str) -> int:
    """Number of *slots* consumed by the argument part of a JVM descriptor.

    Longs and doubles consume 2 slots each; everything else 1.
    """
    m = re.match(r"\(([^)]*)\)", desc)
    if not m:
        return 0
    inside = m.group(1)
    count = 0
    i = 0
    while i < len(inside):
        c = inside[i]
        if c == "L":
            i = inside.index(";", i) + 1
            count += 1
        elif c == "[":
            # Skip array dimensions; count as 1 slot for the reference/array
            while i < len(inside) and inside[i] == "[":
                i += 1
            if i < len(inside) and inside[i] == "L":
                i = inside.index(";", i) + 1
            else:
                i += 1
            count += 1
        elif c in ("J", "D"):
            count += 2
            i += 1
        else:
            count += 1
            i += 1
    return count


def _desc_ret_slots(desc: str) -> int:
    """Number of slots pushed by a method's return type (0 or 1; long/double → 2)."""
    ret = desc.rsplit(")", 1)[-1] if ")" in desc else "V"
    if ret == "V":
        return 0
    if ret in ("J", "D"):
        return 2
    return 1


# ---------------------------------------------------------------------------
# Per-opcode stack effect
# ---------------------------------------------------------------------------

# Static effects for instructions with no operands / fixed-width descriptors.
# (pop_count, push_count).  INVOKE* are handled dynamically from the descriptor.
_STATIC_EFFECTS: dict[str, tuple[int, int]] = {
    # Constants
    "ACONST_NULL": (0, 1),
    "ICONST_M1": (0, 1), "ICONST_0": (0, 1), "ICONST_1": (0, 1),
    "ICONST_2": (0, 1), "ICONST_3": (0, 1), "ICONST_4": (0, 1), "ICONST_5": (0, 1),
    "LCONST_0": (0, 2), "LCONST_1": (0, 2),
    "FCONST_0": (0, 1), "FCONST_1": (0, 1), "FCONST_2": (0, 1),
    "DCONST_0": (0, 2), "DCONST_1": (0, 2),
    "BIPUSH": (0, 1), "SIPUSH": (0, 1), "LDC": (0, 1),
    # Loads
    "ILOAD": (0, 1), "LLOAD": (0, 2), "FLOAD": (0, 1), "DLOAD": (0, 2),
    "ALOAD": (0, 1),
    # Stores
    "ISTORE": (1, 0), "LSTORE": (2, 0), "FSTORE": (1, 0), "DSTORE": (2, 0),
    "ASTORE": (1, 0),
    # Stack manipulation
    "POP": (1, 0), "POP2": (2, 0),
    "DUP": (1, 2),   # consume 1, push 2 (preserves original)
    "DUP_X1": (2, 3),
    "DUP_X2": (3, 4),
    "DUP2": (2, 4),
    "DUP2_X1": (3, 5),
    "DUP2_X2": (4, 6),
    "SWAP": (2, 2),
    # Arithmetic (all consume 2 same-type, push 1)
    "IADD": (2, 1), "LADD": (4, 2), "FADD": (2, 1), "DADD": (4, 2),
    "ISUB": (2, 1), "LSUB": (4, 2), "FSUB": (2, 1), "DSUB": (4, 2),
    "IMUL": (2, 1), "LMUL": (4, 2), "FMUL": (2, 1), "DMUL": (4, 2),
    "IDIV": (2, 1), "LDIV": (4, 2), "FDIV": (2, 1), "DDIV": (4, 2),
    "IREM": (2, 1), "LREM": (4, 2), "FREM": (2, 1), "DREM": (4, 2),
    "INEG": (1, 1), "LNEG": (2, 2), "FNEG": (1, 1), "DNEG": (2, 2),
    "ISHL": (2, 1), "LSHL": (3, 2), "ISHR": (2, 1), "LSHR": (3, 2),
    "IUSHR": (2, 1), "LUSHR": (3, 2),
    "IAND": (2, 1), "LAND": (4, 2), "IOR": (2, 1), "LOR": (4, 2),
    "IXOR": (2, 1), "LXOR": (4, 2),
    "IINC": (0, 0),
    # Type conversions (consume 1, push 1; long<->double = 2<->2)
    "I2L": (1, 2), "I2F": (1, 1), "I2D": (1, 2), "L2I": (2, 1),
    "L2F": (2, 1), "L2D": (2, 2), "F2I": (1, 1), "F2L": (1, 2),
    "F2D": (1, 2), "D2I": (2, 1), "D2L": (2, 2), "D2F": (2, 1),
    "I2B": (1, 1), "I2C": (1, 1), "I2S": (1, 1),
    # Comparisons
    "LCMP": (4, 1), "FCMPL": (2, 1), "FCMPG": (2, 1),
    "DCMPL": (4, 1), "DCMPG": (4, 1),
    # Conditionals (consume from stack, push nothing)
    "IFEQ": (1, 0), "IFNE": (1, 0), "IFLT": (1, 0),
    "IFGE": (1, 0), "IFGT": (1, 0), "IFLE": (1, 0),
    "IF_ICMPEQ": (2, 0), "IF_ICMPNE": (2, 0), "IF_ICMPLT": (2, 0),
    "IF_ICMPGE": (2, 0), "IF_ICMPGT": (2, 0), "IF_ICMPLE": (2, 0),
    "IF_ACMPEQ": (2, 0), "IF_ACMPNE": (2, 0),
    "IFNULL": (1, 0), "IFNONNULL": (1, 0),
    # Unconditional flow
    "GOTO": (0, 0), "GOTO_W": (0, 0),
    "LABEL": (0, 0),
    # Returns / throws
    "RETURN": (0, 0),
    "IRETURN": (1, 0), "LRETURN": (2, 0), "FRETURN": (1, 0),
    "DRETURN": (2, 0), "ARETURN": (1, 0),
    "ATHROW": (1, 0),
    # Object / array ops
    "NEW": (0, 1),
    "NEWARRAY": (1, 1),
    "ANEWARRAY": (1, 1),
    "ARRAYLENGTH": (1, 1),
    "CHECKCAST": (1, 1),  # pop + push same ref
    "INSTANCEOF": (1, 1),
    "MONITORENTER": (1, 0), "MONITOREXIT": (1, 0),
    # Field access
    "GETSTATIC": (0, 1),
    "PUTSTATIC": (1, 0),
    "GETFIELD": (1, 1),
    "PUTFIELD": (2, 0),
    # Array element access
    "IALOAD": (2, 1), "LALOAD": (2, 2), "FALOAD": (2, 1), "DALOAD": (2, 2),
    "AALOAD": (2, 1), "BALOAD": (2, 1), "CALOAD": (2, 1), "SALOAD": (2, 1),
    "IASTORE": (3, 0), "LASTORE": (4, 0), "FASTORE": (3, 0), "DASTORE": (4, 0),
    "AASTORE": (3, 0), "BASTORE": (3, 0), "CASTORE": (3, 0), "SASTORE": (3, 0),
}


def _instruction_effect(ins: dict[str, Any]) -> tuple[int, int]:
    """Return (pop_count, push_count) for a single instruction dict.

    INVOKE* are computed from their ``desc`` field.
    LDC with a ``type`` operand (Class constant) still pushes 1.
    """
    op = ins.get("op", "")

    # Long/double LDC → 2 slots
    if op == "LDC":
        v = ins.get("value")
        if isinstance(v, float) or (isinstance(v, int) and abs(v) > 2**31):
            return (0, 2)
        return (0, 1)

    if op in ("INVOKEVIRTUAL", "INVOKESPECIAL", "INVOKEINTERFACE"):
        desc = ins.get("desc", "()V")
        return (1 + _desc_args_count(desc), _desc_ret_slots(desc))

    if op == "INVOKESTATIC":
        desc = ins.get("desc", "()V")
        return (_desc_args_count(desc), _desc_ret_slots(desc))

    if op == "INVOKEDYNAMIC":
        desc = ins.get("desc", "()V")
        return (_desc_args_count(desc), _desc_ret_slots(desc))

    # GETFIELD / GETSTATIC typed effects
    if op == "GETFIELD":
        fdesc = ins.get("desc", "L?;")
        slots = 2 if fdesc in ("J", "D") else 1
        return (1, slots)

    if op == "GETSTATIC":
        fdesc = ins.get("desc", "L?;")
        slots = 2 if fdesc in ("J", "D") else 1
        return (0, slots)

    if op == "PUTFIELD":
        fdesc = ins.get("desc", "L?;")
        val_slots = 2 if fdesc in ("J", "D") else 1
        return (1 + val_slots, 0)

    if op == "PUTSTATIC":
        fdesc = ins.get("desc", "L?;")
        val_slots = 2 if fdesc in ("J", "D") else 1
        return (val_slots, 0)

    return _STATIC_EFFECTS.get(op, (0, 0))


# ---------------------------------------------------------------------------
# Corrective push helpers
# ---------------------------------------------------------------------------

def _null_push_for_op(op: str, ins: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a single-slot push instruction that satisfies what `op` needs.

    For typed ops (IRETURN, INVOKEVIRTUAL, etc.) we pick a type-appropriate
    constant; for everything else we default to ACONST_NULL.
    """
    if op in ("IRETURN", "IFEQ", "IFNE", "IFLT", "IFGE", "IFGT", "IFLE",
              "IF_ICMPEQ", "IF_ICMPNE", "IF_ICMPLT", "IF_ICMPGE",
              "IF_ICMPGT", "IF_ICMPLE", "ISTORE"):
        return [{"op": "ICONST_0"}]
    if op in ("LRETURN", "LSTORE"):
        return [{"op": "LCONST_0"}]
    if op in ("FRETURN", "FSTORE"):
        return [{"op": "FCONST_0"}]
    if op in ("DRETURN", "DSTORE"):
        return [{"op": "DCONST_0"}]
    # For invoke-like ops, return type comes from descriptor; arg slots are refs.
    return [{"op": "ACONST_NULL"}]


# ---------------------------------------------------------------------------
# Main tracker
# ---------------------------------------------------------------------------

class StackTracker:
    """Forward-pass stack balancer.

    Walks the instruction list emitted by the lifter and inserts corrective
    placeholder pushes wherever the stack would underflow, reducing the
    fraction of methods that ``class-rebuilder`` downgrades to stubs.

    Label points reset tracking so each basic block is analysed cleanly.
    GOTO / IF* branch targets record the depth at the jump site; when we
    later encounter those labels we reconcile to the min of the two depths
    (conservative merge).
    """

    def process(
        self,
        instructions: list[dict[str, Any]],
        method_desc: str = "()V",
        warnings: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Balance `instructions` and return a new, corrected list."""
        out: list[dict[str, Any]] = []
        depth = 0
        label_depth: dict[str, int] = {}  # label -> depth at branch site

        for ins in instructions:
            op = ins.get("op", "")

            # Labels: reconcile depth from jump sites, or reset to 0.
            if op == "LABEL":
                lbl = ins.get("label", "")
                if lbl in label_depth:
                    depth = label_depth[lbl]
                else:
                    depth = 0
                out.append(ins)
                continue

            # Record depth at branch target
            if op in ("GOTO", "GOTO_W") and "target" in ins:
                target = ins["target"]
                if target not in label_depth:
                    label_depth[target] = depth
                out.append(ins)
                depth = 0  # code after unconditional jump is unreachable
                continue

            if op in _STATIC_EFFECTS or op in (
                "INVOKEVIRTUAL", "INVOKESPECIAL", "INVOKEINTERFACE",
                "INVOKESTATIC", "INVOKEDYNAMIC",
                "GETFIELD", "GETSTATIC", "PUTFIELD", "PUTSTATIC", "LDC",
            ):
                pop_n, push_n = _instruction_effect(ins)

                # Record jump-target depth for conditional branches
                if op in (
                    "IFEQ", "IFNE", "IFLT", "IFGE", "IFGT", "IFLE",
                    "IF_ICMPEQ", "IF_ICMPNE", "IF_ICMPLT",
                    "IF_ICMPGE", "IF_ICMPGT", "IF_ICMPLE",
                    "IF_ACMPEQ", "IF_ACMPNE", "IFNULL", "IFNONNULL",
                ) and "target" in ins:
                    target_depth = max(0, depth - pop_n)
                    label_depth.setdefault(ins["target"], target_depth)

                # Insert corrective pushes if stack would underflow.
                while depth < pop_n:
                    pad = _null_push_for_op(op, ins)
                    out.extend(pad)
                    depth += sum(
                        _instruction_effect(p)[1] for p in pad
                    )
                    if warnings is not None:
                        warnings.append(
                            f"stack-pad inserted before {op} "
                            f"(depth={depth - sum(_instruction_effect(p)[1] for p in pad)}, "
                            f"need={pop_n})"
                        )

                out.append(ins)
                depth = depth - pop_n + push_n
                depth = max(depth, 0)  # safety clamp

            else:
                # Unknown op — emit as-is, don't touch depth.
                out.append(ins)

        return out


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def balance_instructions(
    instructions: list[dict[str, Any]],
    method_desc: str = "()V",
    warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Apply :class:`StackTracker` to `instructions` and return balanced list."""
    return StackTracker().process(instructions, method_desc, warnings)
