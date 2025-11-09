# Building pyaegis

This document contains instructions for developers who want to build pyaegis from source.

## Prerequisites

- **Python 3.12 or later** (CPython only)
- **Zig compiler** (required for building the libaegis static library)
- **C compiler** (gcc, clang, or MSVC) with development headers
- **uv** (recommended for dependency management) or **pip**

### Installing Zig

pyaegis uses Zig to build the underlying libaegis C library. Install Zig from [ziglang.org/download](https://ziglang.org/download/) or using your package manager:

- **macOS**: `brew install zig`
- **Linux**: See [Zig installation guide](https://github.com/ziglang/zig/wiki/Install-Zig-from-a-Package-Manager)
- **Windows**: `choco install zig` or `scoop install zig`

## Getting the Source

Clone the repository with submodules:

```fish
git clone --recursive https://github.com/LeoVasanko/pyaegis.git
cd pyaegis
```

If you already cloned without `--recursive`, initialize submodules:

```fish
git submodule update --init --recursive
```

## Development Setup

### Installing in the development tree

```fish
uv sync
uv run setup.py build_ext --inplace
```

The latter command is necessary for building the C code into the source tree, as normal `uv build` does not place it there (only in wheels).

## Building libaegis Separately (Optional)

The build process automatically builds libaegis, but you can build it manually:

```fish
cd libaegis
zig build -Drelease
```

This creates the static library in `libaegis/zig-out/lib/`, and the Python CFFI build will find it from there.

## Running Tests

Run the test suite:

```fish
uv run pytest
```

## Building Distributions

Build source and wheel distributions:

```fish
uv build
```

This creates files in the `dist/` directory.

## Code Generation

The Python modules and CFFI definitions are generated from C sources and templates. If you modify the core implementation in `pyaegis/aegis256x4.py` or update libaegis headers, regenerate all files:

```fish
python tools/generate.py
```

## Troubleshooting

### Zig Not Found

If you see an error about Zig not being found, ensure it's installed and in your PATH:

```fish
zig version
```

If you cannot install Zig, you may manually compile in the libaegis folder (Zig, CMake) or simply place a libaegis.a in there if you can get it from elsewhere as a binary.

### Build Failures

- Ensure you have a C compiler installed
- On macOS, you may need Xcode command line tools: `xcode-select --install`
- On Linux, install development packages (e.g., `build-essential` on Ubuntu)

## Project Structure

- `pyaegis/` - Python package source
- `libaegis/` - C library source (submodule)
- `tests/` - Test suite
- `tools/` - Code generation scripts and `build_backend.py` used to build libaegis
