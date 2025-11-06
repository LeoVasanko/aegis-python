#!/usr/bin/env python3
"""
Regenerate aegis*.py modules from the canonical template aegis256x4.py.

Changes per variant:
- Replace module name (aegis256x4 -> target)
- Replace label (AEGIS-256X4 -> target label like AEGIS-128L)
- Replace only the ALIGNMENT = <int> value
- Replace only the RATE = <int> value

We do not touch alloc_aligned(...) calls or any code formatting. Blank lines
after ALIGNMENT are preserved.
"""

import pathlib
import re
import sys

# Template and target locations
ROOT = (
    pathlib.Path(__file__).resolve().parents[2]
    if (pathlib.Path(__file__).resolve().parents[0].name == "tools")
    else pathlib.Path.cwd()
)
PY_DIR = ROOT / "python"
AEGIS_DIR = PY_DIR / "aegis"
TEMPLATE = AEGIS_DIR / "aegis256x4.py"

# Variants to generate (template excluded) and their ALIGNMENT values
VARIANT_ALIGN = {
    "aegis256": 16,
    "aegis256x2": 32,
    "aegis256x4": 64,
    "aegis128l": 32,
    "aegis128x2": 64,
    "aegis128x4": 64,
}

# Variants and their RATE values
VARIANT_RATE = {
    "aegis256": 16,
    "aegis256x2": 32,
    "aegis256x4": 64,
    "aegis128l": 32,
    "aegis128x2": 64,
    "aegis128x4": 128,
}

TEMPLATE_NAME = "aegis256x4"
TEMPLATE_LABEL = "AEGIS-256X4"

ALIGNMENT_LINE_RE = re.compile(r"^(ALIGNMENT\s*=\s*)(\d+)(\s*)$", re.MULTILINE)
RATE_LINE_RE = re.compile(r"^(RATE\s*=\s*)(\d+)(\s*)$", re.MULTILINE)


def set_alignment_only(text: str, value: int) -> str:
    """Replace only the numeric ALIGNMENT value, preserving surrounding whitespace and lines.

    This preserves any empty lines following the ALIGNMENT assignment because
    the line ending is not part of the match; we keep any trailing spaces too.
    """

    def _sub(m: re.Match[str]) -> str:
        prefix, _num, suffix = m.group(1), m.group(2), m.group(3)
        return f"{prefix}{value}{suffix}"

    return ALIGNMENT_LINE_RE.sub(_sub, text)


def set_rate_only(text: str, value: int) -> str:
    """Replace only the numeric RATE value, preserving surrounding whitespace and lines.

    This preserves any empty lines following the RATE assignment because
    the line ending is not part of the match; we keep any trailing spaces too.
    """

    def _sub(m: re.Match[str]) -> str:
        prefix, _num, suffix = m.group(1), m.group(2), m.group(3)
        return f"{prefix}{value}{suffix}"

    return RATE_LINE_RE.sub(_sub, text)


def algo_label(name: str) -> str:
    """Return the canonical label like AEGIS-256X4 for a module name like aegis256x4."""
    if not name.startswith("aegis"):
        raise ValueError(f"Unexpected algorithm name: {name}")
    return "AEGIS-" + name[5:].upper()


def generate_variant(template_src: str, variant: str) -> str:
    # 1) replace lowercase template name
    s = template_src.replace(TEMPLATE_NAME, variant)
    # 2) replace uppercase label
    s = s.replace(TEMPLATE_LABEL, algo_label(variant))
    # 3) set ALIGNMENT constant value using fallback map
    align_value = VARIANT_ALIGN.get(variant, 64)
    s = set_alignment_only(s, align_value)
    # 4) set RATE constant value using fallback map
    rate_value = VARIANT_RATE.get(variant, 64)
    s = set_rate_only(s, rate_value)
    return s


def main() -> int:
    if not TEMPLATE.exists():
        print(f"Template not found: {TEMPLATE}", file=sys.stderr)
        return 2
    template_src = TEMPLATE.read_text(encoding="utf-8")

    # Safety: ensure we are working from an up-to-date template that contains expected tokens
    if TEMPLATE_NAME not in template_src or TEMPLATE_LABEL not in template_src:
        print(
            "Template file does not contain expected identifiers; aborting.",
            file=sys.stderr,
        )
        return 3

    wrote = []
    for variant in VARIANT_ALIGN.keys():
        # Skip the template itself; recreate all other modules
        if variant == TEMPLATE_NAME:
            continue
        dst = AEGIS_DIR / f"{variant}.py"
        content = generate_variant(template_src, variant)
        dst.write_text(content, encoding="utf-8")
        wrote.append(dst.relative_to(ROOT))

    print("Generated modules:")
    for p in wrote:
        print(" -", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
