#!/usr/bin/env python3
"""Generate CFFI cdef string from libaegis headers.

This script parses the C header files and extracts function declarations,
typedefs, and struct definitions to generate the cdef() string needed by CFFI.
"""

import pathlib
import re
import sys


def preprocess_content(content: str) -> str:
    """Remove comments, preprocessor directives, and extern "C" blocks."""
    # Remove multi-line comments
    content = re.sub(r"/\*.*?\*/", " ", content, flags=re.DOTALL)
    # Remove line comments
    content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
    # Remove preprocessor directives
    content = re.sub(r"^\s*#.*$", "", content, flags=re.MULTILINE)
    # Remove extern "C" blocks
    content = re.sub(r'extern\s+"C"\s*\{', "", content)
    content = re.sub(r"(?:^|\n)\s*\}\s*(?:\n|$)", "\n", content, flags=re.MULTILINE)

    return content


def clean_declaration(text: str) -> str:
    """Clean up a C declaration for CFFI consumption."""
    # Remove __attribute__(...) with proper nesting
    while "__attribute__" in text:
        old = text
        text = re.sub(r"__attribute__\s*\(\([^()]*\)\)", "", text)
        if text == old:
            break

    # Remove CRYPTO_ALIGN(...)
    text = re.sub(r"CRYPTO_ALIGN\s*\(\s*\d+\s*\)", "", text)

    # Normalize whitespace but preserve structure
    lines = []
    for line in text.split("\n"):
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)

    return " ".join(lines)


def extract_declarations(header_path: pathlib.Path) -> list[str]:
    """Extract function declarations and typedefs from a header file."""
    content = header_path.read_text(encoding="utf-8")
    content = preprocess_content(content)
    declarations = []

    # Extract typedefs (including structs)
    typedef_pattern = r"typedef\s+struct\s+\w+\s*\{[^}]+\}\s*\w+\s*;"
    for match in re.finditer(typedef_pattern, content, re.DOTALL):
        decl = clean_declaration(match.group(0))
        if decl:
            declarations.append(decl)

    # Extract function declarations - more permissive pattern
    func_pattern = r"((?:const\s+)?(?:int|void|size_t)\s+\w+\s*\([^;]+?\)\s*;)"
    for match in re.finditer(func_pattern, content, re.DOTALL):
        decl = clean_declaration(match.group(0))
        if decl and "aegis" in decl.lower():
            declarations.append(decl)

    return declarations


def format_declaration(decl: str, max_width: int = 100) -> str:
    """Format a declaration for readability, with intelligent line breaking."""
    # If it's short enough, return as-is
    if len(decl) <= max_width:
        return decl

    # For function declarations, try to break at parameter boundaries
    if "(" in decl and ")" in decl:
        # Find the function name and opening paren
        match = re.match(r"(.*?\s+\w+\s*)\((.*)\)(.*)", decl)
        if match:
            prefix, params, suffix = match.groups()
            # Break parameters if they're too long
            if len(prefix) + len(params) + 2 > max_width:
                # Split parameters
                param_list = [p.strip() for p in params.split(",")]
                if len(param_list) > 1:
                    formatted_params = (",\n" + " " * (len(prefix) + 1)).join(
                        param_list
                    )
                    return f"{prefix}({formatted_params}){suffix}"

    return decl


def generate_cdef(include_dir: pathlib.Path) -> str:
    """Generate the complete CFFI cdef string from all aegis headers."""

    lines = [
        "/* This file is generated with tools/gen_cdef.py. Do not edit. */",
        "",
        "typedef unsigned char uint8_t;",
        "typedef unsigned long size_t;",
        "",
    ]

    # Header files in order, skipping aegis.h as it might be included elsewhere
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
        declarations = extract_declarations(header_path)

        for decl in declarations:
            formatted = format_declaration(decl)
            lines.append(formatted)

        lines.append("")

    return "\n".join(lines)


def main() -> int:
    # Find the include directory
    root = pathlib.Path(__file__).parent.parent
    include_dir = root / "libaegis" / "src" / "include"

    if not include_dir.exists():
        print(f"Include directory not found: {include_dir}", file=sys.stderr)
        return 1

    cdef_string = generate_cdef(include_dir)

    # Write to a file in the pyaegis directory
    output_dir = root / "pyaegis"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "aegis_cdef.h"
    output_path.write_text(cdef_string, encoding="utf-8")
    print(f"Generated: {output_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
