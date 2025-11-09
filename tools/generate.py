"""Generate CFFI cdef and Python modules from libaegis C sources."""

import pathlib
import re
import sys
from typing import Dict, Tuple


def preprocess_content(content: str) -> str:
    content = re.sub(r"/\*.*?\*/", " ", content, flags=re.DOTALL)
    content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
    content = re.sub(r"^\s*#.*$", "", content, flags=re.MULTILINE)
    content = re.sub(r'extern\s+"C"\s*\{', "", content)
    content = re.sub(r"(?:^|\n)\s*\}\s*(?:\n|$)", "\n", content, flags=re.MULTILINE)
    return content


def clean_declaration(text: str) -> str:
    while "__attribute__" in text:
        old = text
        text = re.sub(r"__attribute__\s*\(\([^()]*\)\)", "", text)
        if text == old:
            break

    if "CRYPTO_ALIGN" in text and "typedef struct" in text:
        text = re.sub(
            r"CRYPTO_ALIGN\s*\(\s*\d+\s*\)\s+uint8_t\s+opaque\[\d+\];", "...;", text
        )
    else:
        text = re.sub(r"CRYPTO_ALIGN\s*\(\s*\d+\s*\)", "", text)

    lines = [
        re.sub(r"\s+", " ", line).strip() for line in text.split("\n") if line.strip()
    ]
    return " ".join(lines)


def extract_declarations(header_path: pathlib.Path) -> list[str]:
    content = preprocess_content(header_path.read_text(encoding="utf-8"))
    declarations = []

    typedef_pattern = r"typedef\s+struct\s+\w+\s*\{[^}]+\}\s*\w+\s*;"
    for match in re.finditer(typedef_pattern, content, re.DOTALL):
        if decl := clean_declaration(match.group(0)):
            declarations.append(decl)

    func_pattern = r"((?:const\s+)?(?:int|void|size_t)\s+\w+\s*\([^;]+?\)\s*;)"
    for match in re.finditer(func_pattern, content, re.DOTALL):
        if (decl := clean_declaration(match.group(0))) and "aegis" in decl.lower():
            declarations.append(decl)

    return declarations


def format_declaration(decl: str, max_width: int = 100) -> str:
    if len(decl) <= max_width:
        return decl

    if "(" in decl and ")" in decl:
        if match := re.match(r"(.*?\s+\w+\s*)\((.*)\)(.*)", decl):
            prefix, params, suffix = match.groups()
            if len(prefix) + len(params) + 2 > max_width:
                param_list = [p.strip() for p in params.split(",")]
                if len(param_list) > 1:
                    formatted_params = (",\n" + " " * (len(prefix) + 1)).join(
                        param_list
                    )
                    return f"{prefix}({formatted_params}){suffix}"

    return decl


def generate_cdef(include_dir: pathlib.Path) -> str:
    lines = [
        "/* This file is generated with tools/generate.py. Do not edit. */",
        "",
        "typedef unsigned char uint8_t;",
        "typedef unsigned long size_t;",
        "",
    ]

    headers = [
        "aegis.h",
        "aegis128l.h",
        "aegis128x2.h",
        "aegis128x4.h",
        "aegis256.h",
        "aegis256x2.h",
        "aegis256x4.h",
    ]

    for header_name in headers:
        header_path = include_dir / header_name
        if not header_path.exists():
            print(f"Warning: {header_name} not found", file=sys.stderr)
            continue

        lines.append(f"/* {header_name} */")
        for decl in extract_declarations(header_path):
            lines.append(format_declaration(decl))
        lines.append("")

    return "\n".join(lines)


def extract_constants(
    common_h_path: pathlib.Path, header_path: pathlib.Path
) -> Dict[str, int]:
    """Extract constants from common.h (ALIGNMENT, RATE) and main header (KEYBYTES, NPUBBYTES, ABYTES_*)."""
    constants = {}

    # Extract from common.h
    common_content = common_h_path.read_text(encoding="utf-8")
    align_match = re.search(
        r"^\s*#define\s+ALIGNMENT\s+(\d+)", common_content, re.MULTILINE
    )
    rate_match = re.search(r"^\s*#define\s+RATE\s+(\d+)", common_content, re.MULTILINE)

    if not align_match or not rate_match:
        raise ValueError(
            f"Could not extract ALIGNMENT and/or RATE from {common_h_path}"
        )

    constants["ALIGNMENT"] = int(align_match.group(1))
    constants["RATE"] = int(rate_match.group(1))

    # Extract from main header
    header_content = header_path.read_text(encoding="utf-8")
    variant = header_path.stem  # e.g., "aegis256x4"

    for const_name in ["KEYBYTES", "NPUBBYTES", "ABYTES_MIN", "ABYTES_MAX"]:
        pattern = rf"^\s*#define\s+{variant}_{const_name}\s+(\d+)"
        match = re.search(pattern, header_content, re.MULTILINE)
        if not match:
            raise ValueError(f"Could not extract {const_name} from {header_path}")
        constants[const_name] = int(match.group(1))

    return constants


def extract_all_constants(
    libaegis_src_dir: pathlib.Path, include_dir: pathlib.Path
) -> Dict[str, Dict[str, int]]:
    variants = [
        "aegis128l",
        "aegis128x2",
        "aegis128x4",
        "aegis256",
        "aegis256x2",
        "aegis256x4",
    ]
    constants = {}

    for variant in variants:
        common_h = libaegis_src_dir / variant / f"{variant}_common.h"
        header_h = include_dir / f"{variant}.h"

        if not common_h.exists():
            print(f"Warning: {common_h} not found, skipping {variant}", file=sys.stderr)
            continue

        if not header_h.exists():
            print(f"Warning: {header_h} not found, skipping {variant}", file=sys.stderr)
            continue

        try:
            constants[variant] = extract_constants(common_h, header_h)
        except Exception as e:
            print(f"Error extracting constants from {variant}: {e}", file=sys.stderr)

    return constants


ALIGNMENT_RE = re.compile(r"^(ALIGNMENT\s*=\s*)(\d+)(\s*)$", re.MULTILINE)
RATE_RE = re.compile(r"^(RATE\s*=\s*)(\d+)(\s*)$", re.MULTILINE)


def replace_constant(pattern: re.Pattern, text: str, value: int) -> str:
    return pattern.sub(lambda m: f"{m.group(1)}{value}{m.group(3)}", text)


def algo_label(name: str) -> str:
    return "AEGIS-" + name[5:].upper()


def generate_variant(template_src: str, variant: str, constants: Dict[str, int]) -> str:
    """Generate a variant module from the template with substituted constants."""
    s = template_src.replace("aegis256x4", variant).replace(
        "AEGIS-256X4", algo_label(variant)
    )
    # Fix the comment to reference the template, not the variant itself
    s = re.sub(
        r"# All modules are generated from \w+\.py by tools/generate\.py!",
        "# All modules are generated from aegis256x4.py by tools/generate.py!",
        s,
    )
    s = replace_constant(ALIGNMENT_RE, s, constants["ALIGNMENT"])
    s = replace_constant(RATE_RE, s, constants["RATE"])

    # Replace the constant assignments
    s = re.sub(r"KEYBYTES = \d+", f"KEYBYTES = {constants['KEYBYTES']}", s)
    s = re.sub(
        r"NONCEBYTES = \d+",
        f"NONCEBYTES = {constants['NPUBBYTES']}",
        s,
    )
    s = re.sub(
        r"MACBYTES = \d+",
        f"MACBYTES = {constants['ABYTES_MIN']}",
        s,
    )
    s = re.sub(
        r"MACBYTES_LONG = \d+",
        f"MACBYTES_LONG = {constants['ABYTES_MAX']}",
        s,
    )

    return s


def generate_python_modules(
    template_path: pathlib.Path,
    output_dir: pathlib.Path,
    constants: Dict[str, Dict[str, int]],
) -> Tuple[list[pathlib.Path], list[pathlib.Path]]:
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")

    template_src = template_path.read_text(encoding="utf-8")
    if "aegis256x4" not in template_src or "AEGIS-256X4" not in template_src:
        raise ValueError("Template file does not contain expected identifiers")

    updated = []
    unchanged = []
    for variant, const_dict in constants.items():
        dst = output_dir / f"{variant}.py"
        if variant == "aegis256x4":
            # Update template in place with its own constants
            new_content = replace_constant(
                ALIGNMENT_RE, template_src, const_dict["ALIGNMENT"]
            )
            new_content = replace_constant(RATE_RE, new_content, const_dict["RATE"])
            # Replace the constant assignments for the template itself
            new_content = re.sub(
                r"KEYBYTES = \d+",
                f"KEYBYTES = {const_dict['KEYBYTES']}",
                new_content,
            )
            new_content = re.sub(
                r"NONCEBYTES = \d+",
                f"NONCEBYTES = {const_dict['NPUBBYTES']}",
                new_content,
            )
            new_content = re.sub(
                r"MACBYTES = \d+",
                f"MACBYTES = {const_dict['ABYTES_MIN']}",
                new_content,
            )
            new_content = re.sub(
                r"MACBYTES_LONG = \d+",
                f"MACBYTES_LONG = {const_dict['ABYTES_MAX']}",
                new_content,
            )
        else:
            new_content = generate_variant(template_src, variant, const_dict)

        if dst.exists() and dst.read_text(encoding="utf-8") == new_content:
            unchanged.append(dst)
        else:
            dst.write_text(new_content, encoding="utf-8")
            updated.append(dst)

    return updated, unchanged


def main() -> int:
    root = pathlib.Path(__file__).parent.parent
    libaegis_src_dir = root / "libaegis" / "src"
    include_dir = libaegis_src_dir / "include"
    pyaegis_dir = root / "pyaegis"

    if not include_dir.exists():
        print(f"Include directory not found: {include_dir}", file=sys.stderr)
        return 1

    if not libaegis_src_dir.exists():
        print(f"Source directory not found: {libaegis_src_dir}", file=sys.stderr)
        return 1

    print("Step 1: Extracting constants from C sources...", file=sys.stderr)
    constants = extract_all_constants(libaegis_src_dir, include_dir)
    if not constants:
        print("Error: No constants extracted", file=sys.stderr)
        return 1

    print("Step 2: Generating CFFI cdef header...", file=sys.stderr)
    pyaegis_dir.mkdir(exist_ok=True)
    cdef_path = pyaegis_dir / "aegis_cdef.h"
    cdef_content = generate_cdef(include_dir)

    if cdef_path.exists() and cdef_path.read_text(encoding="utf-8") == cdef_content:
        print(f"  - No changes to {cdef_path}", file=sys.stderr)
    else:
        cdef_path.write_text(cdef_content, encoding="utf-8")
        print(f"  - Updated {cdef_path}", file=sys.stderr)

    print("Step 3: Generating Python modules...", file=sys.stderr)
    try:
        updated, unchanged = generate_python_modules(
            pyaegis_dir / "aegis256x4.py", pyaegis_dir, constants
        )
        if updated:
            for p in updated:
                print(f"  - {p.relative_to(root)}", file=sys.stderr)
        if unchanged:
            print(
                "  - No changes to",
                f"{len(unchanged)} modules"
                if len(unchanged) > 1
                else unchanged[0].name,
                file=sys.stderr,
            )
    except Exception as e:
        print(f"Error generating Python modules: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
