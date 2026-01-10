#!/usr/bin/env -S uv run
"""Build wheels for all supported Python versions using uv."""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from packaging.version import Version

# Import generate module from same directory
sys.path.insert(0, str(Path(__file__).parent))
import generate

# Minimum macOS deployment target for compatibility
MACOS_DEPLOYMENT_TARGET = "11.0"

# ABI3 wheel: built once, works for all GIL-enabled Python versions
# We use a recent Python to build since it doesn't affect the wheel compatibility
ABI3_BUILD_VERSION = "3.14+gil"

# All GIL-enabled Python versions covered by the ABI3 wheel
ABI3_COVERED_VERSIONS = [
    "3.10",
    "3.11",
    "3.12",
    "3.13+gil",
    "3.14+gil",
    "3.15+gil",
]

# Non-ABI3 wheels: each needs its own build (free-threaded and PyPy)
NON_ABI3_VERSIONS = [
    "3.14t",
    "3.15t",
    "pypy3.10",
    "pypy3.11",
]

# All versions for testing and benchmarking
ALL_PYTHON_VERSIONS = ABI3_COVERED_VERSIONS + NON_ABI3_VERSIONS


def get_version_from_scm():
    """Get version from setuptools-scm (git tags)."""
    try:
        result = subprocess.run(
            ["uv", "run", "-m", "setuptools_scm"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).parent.parent,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"✗ Error getting version from setuptools-scm: {e}", file=sys.stderr)
        return None


def is_release_version(version):
    """Check if version is a clean release (no dev/post/local identifiers)."""
    # A release version is just x.y.z with optional alpha/beta/rc suffixes
    # No +local or .devN or .postN
    if not version:
        return False
    return not any(marker in version for marker in ["+", ".dev", ".post"])


def get_next_version(current_version):
    """Get the next release version from a dev version."""
    # Parse base version (strips dev/local parts)
    try:
        v = Version(current_version)
        return f"{v.major}.{v.minor}.{v.micro}"
    except Exception:
        return current_version


def is_working_copy_clean():
    """Check if git working copy is clean."""
    result = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True
    )
    return result.returncode == 0 and not result.stdout.strip()


def make_release_message(version):
    """Generate message for making a release."""
    next_version = get_next_version(version)
    is_clean = is_working_copy_clean()

    msg = "\n⚠️  This is not a clean release version; upload to PyPI skipped.\n\n"
    msg += f"To create a release (e.g. {next_version}) and upload to PyPI:\n"

    if not is_clean:
        msg += "  1. Add and commit changes on the working copy\n"
        msg += f"  2. Tag the commit: git tag v{next_version}\n"
        msg += "  3. Run this script again\n"
        msg += f"  4. Push the tag: git push origin v{next_version}\n"
    else:
        msg += f"  1. Tag the current commit: git tag v{next_version}\n"
        msg += "  2. Run this script again\n"
        msg += f"  3. Push the tag: git push origin v{next_version}\n"

    msg += (
        f"\nIf the build didn't work, delete the tag with git tag -d v{next_version}\n"
    )
    return msg


def run_command(cmd, description=None, env=None):
    """Run a command and handle errors. If description is None, only print the command."""
    if description:
        print(f"\n{'=' * 70}")
        print(f"{description}")
        print(f"{'=' * 70}")
    print(f">>> {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, env=env)
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Command failed with exit code {e.returncode}", file=sys.stderr)
        return False


def get_build_env():
    """Get environment variables for building wheels."""
    env = os.environ.copy()
    if platform.system() == "Darwin":
        env["MACOSX_DEPLOYMENT_TARGET"] = MACOS_DEPLOYMENT_TARGET
    return env


def normalize_line_endings(repo_root: Path):
    """Normalize all text files to LF line endings."""
    # Patterns for files to normalize
    patterns = [
        "src/aeg/**/*.py",
        "src/aeg/**/*.h",
        "tests/**/*.py",
        "tools/**/*.py",
        "*.py",
        "*.md",
        "*.txt",
        "*.toml",
        "*.in",
    ]
    for pattern in patterns:
        for file_path in repo_root.glob(pattern):
            if file_path.is_file():
                content = file_path.read_bytes()
                if b"\r\n" in content:
                    content = content.replace(b"\r\n", b"\n")
                    file_path.write_bytes(content)


def get_wheel_pattern(py_version: str, abi3: bool = False) -> str:
    """Get the glob pattern for finding a wheel file."""
    if abi3:
        # ABI3 wheels always use cp310-abi3 tag (minimum supported version)
        # regardless of which Python version was used to build
        return "aeg-*-cp310-abi3-*.whl"
    elif py_version.startswith("pypy"):
        # PyPy wheels use pp3XX format
        return f"aeg-*-pp{py_version.replace('pypy', '').replace('.', '')}-*.whl"
    elif py_version.endswith("t"):
        # Free-threaded Python wheels use cpXXX-cpXXXt format (e.g., cp314-cp314t)
        base_version = py_version.replace(".", "").replace("t", "")
        return f"aeg-*-cp{base_version}-cp{base_version}t-*.whl"
    else:
        # Regular CPython wheels use cpXXX-cpXXX format
        # Strip +gil suffix used to force non-free-threaded build
        base_version = py_version.replace(".", "").replace("+gil", "")
        return f"aeg-*-cp{base_version}-cp{base_version}-*.whl"


def build_abi3_wheel(dist_dir: Path, py_version: str) -> Path | None:
    """Build the ABI3 wheel using the specified Python version."""
    cmd = ["uv", "build", "--python", py_version, "--wheel", "--quiet"]

    if not run_command(cmd, env=get_build_env()):
        return None

    # Find the ABI3 wheel (always tagged cp310-abi3 regardless of build Python version)
    wheel_pattern = get_wheel_pattern(py_version, abi3=True)
    wheels = list(dist_dir.glob(wheel_pattern))
    if not wheels:
        print(f"✗ Could not find ABI3 wheel matching {wheel_pattern}", file=sys.stderr)
        return None

    wheel = wheels[0]

    # Repair wheel with auditwheel for manylinux compatibility (Linux only)
    if platform.system() == "Linux":
        wheel = repair_wheel_linux(dist_dir, wheel, py_version, abi3=True)
        if not wheel:
            return None

    return wheel


def build_wheel_for_version(dist_dir: Path, py_version: str) -> Path | None:
    """Build a wheel for a specific Python version (non-ABI3)."""
    cmd = ["uv", "build", "--python", py_version, "--wheel", "--quiet"]

    if not run_command(cmd, env=get_build_env()):
        return None

    # Find the wheel for this version
    wheel_pattern = get_wheel_pattern(py_version, abi3=False)
    wheels = list(dist_dir.glob(wheel_pattern))
    if not wheels:
        print(f"✗ Could not find wheel for Python {py_version}", file=sys.stderr)
        return None

    wheel = wheels[0]

    # Repair wheel with auditwheel for manylinux compatibility (Linux only)
    if platform.system() == "Linux":
        wheel = repair_wheel_linux(dist_dir, wheel, py_version, abi3=False)
        if not wheel:
            return None

    return wheel


def repair_wheel_linux(
    dist_dir: Path, wheel: Path, py_version: str, abi3: bool
) -> Path | None:
    """Repair a wheel with auditwheel for manylinux compatibility (Linux only)."""
    repair_cmd = [
        "uv",
        "run",
        "auditwheel",
        "repair",
        str(wheel),
        "-w",
        str(dist_dir),
    ]
    if not run_command(repair_cmd):
        return None

    # Find the repaired wheel (it will have a different name)
    wheel_pattern = get_wheel_pattern(py_version, abi3=abi3)
    all_wheels = list(dist_dir.glob(wheel_pattern))
    repaired_wheels = [w for w in all_wheels if "linux_x86_64" not in str(w)]
    if not repaired_wheels:
        print(
            f"✗ Could not find repaired (manylinux) wheel for Python {py_version}",
            file=sys.stderr,
        )
        return None

    repaired_wheel = repaired_wheels[0]

    # Remove the unrepaired linux_x86_64 wheels
    for w in all_wheels:
        if "linux_x86_64" in str(w):
            w.unlink()

    return repaired_wheel


def test_wheel(wheel: Path, py_version: str) -> bool:
    """Test a wheel with pytest."""
    # --isolated: avoid .venv conflicts
    # --no-project: don't build from source in current directory, use the wheel
    # --refresh-package: force uv to not use cached old versions
    test_cmd = [
        "uv",
        "run",
        "--isolated",
        "--no-project",
        "--refresh-package",
        "aeg",
        "--python",
        py_version,
        "--with",
        str(wheel),
        "--with",
        "pytest",
        "pytest",
        "tests/",
    ]
    return run_command(test_cmd)


def run_benchmark(wheel: Path, py_version: str) -> bool:
    """Run benchmark for a wheel."""
    # --isolated: avoid .venv conflicts
    # --no-project: don't build from source in current directory, use the wheel
    # --refresh-package: force uv to not use cached old versions
    bench_cmd = [
        "uv",
        "run",
        "--isolated",
        "--no-project",
        "--refresh-package",
        "aeg",
        "--python",
        py_version,
        "--with",
        str(wheel),
        "-m",
        "aeg.benchmark",
    ]
    return run_command(bench_cmd)
    return True


def main():
    """Build wheels for all supported Python versions."""
    repo_root = Path(__file__).parent.parent
    dist_dir = repo_root / "dist"

    # Generate CFFI definitions and Python modules
    print(f"\n{'=' * 70}")
    print("Code generation from C headers (tools/generate.py)")
    print(f"{'=' * 70}")
    if generate.main() != 0:
        print("✗ Code generation failed", file=sys.stderr)
        return 1

    # Run ruff to check and fix any issues
    print(f"\n{'=' * 70}")
    print("Linting and formatting")
    print(f"{'=' * 70}")
    if not run_command(["uv", "run", "ruff", "check", "--fix", "."]):
        print("✗ Ruff check failed", file=sys.stderr)
        return 1

    # Run ruff format
    if not run_command(["uv", "run", "ruff", "format", "."]):
        print("✗ Ruff format failed", file=sys.stderr)
        return 1

    # Normalize all line endings to LF (important for consistent builds)
    normalize_line_endings(repo_root)

    # Get version from git repo
    version = get_version_from_scm()
    if not version:
        return 1
    is_release = is_release_version(version)

    # Main header for the packaging process
    print(f"\n{'=' * 70}")
    print(
        f"Packaging aeg-{version}"
        + (" for release" if is_release else " (not release)")
    )
    print(f"Building: 1 ABI3 wheel (for Python {', '.join(ABI3_COVERED_VERSIONS)})")
    print(
        f"        + {len(NON_ABI3_VERSIONS)} non-ABI3 wheels ({', '.join(NON_ABI3_VERSIONS)})"
    )
    print(f"Testing/benchmarking: {len(ALL_PYTHON_VERSIONS)} Python versions")
    print(f"Output directory: {dist_dir}", end=" ")

    # Clean dist directory
    if dist_dir.exists():
        print("(wiped)")
        shutil.rmtree(dist_dir)
    else:
        print("(created)")

    # Clean build directory to remove stale CFFI-generated C code and .so files
    build_dir = repo_root / "build"
    if build_dir.exists():
        print(f"Cleaning build directory: {build_dir}")
        shutil.rmtree(build_dir)

    # Build distributions
    print(f"\n{'=' * 70}")
    print("Building distributions")
    print(f"{'=' * 70}")

    # Build source distribution first
    if not run_command(["uv", "build", "--sdist", "--quiet"], env=get_build_env()):
        print("✗ Source distribution build failed", file=sys.stderr)
        return 1

    failed_builds = []
    failed_tests = []
    successful_wheels = []
    wheel_for_version = {}  # Map Python version to wheel path

    # Build ABI3 wheel (once, works for all GIL-enabled versions)
    abi3_wheel = build_abi3_wheel(dist_dir, ABI3_BUILD_VERSION)
    if abi3_wheel:
        successful_wheels.append(abi3_wheel)
        # This wheel works for all ABI3-covered versions
        for py_version in ABI3_COVERED_VERSIONS:
            wheel_for_version[py_version] = abi3_wheel
    else:
        failed_builds.append(f"abi3 (built with {ABI3_BUILD_VERSION})")

    # Build non-ABI3 wheels (free-threaded and PyPy)
    for py_version in NON_ABI3_VERSIONS:
        wheel = build_wheel_for_version(dist_dir, py_version)
        if wheel:
            successful_wheels.append(wheel)
            wheel_for_version[py_version] = wheel
        else:
            failed_builds.append(py_version)

    # Test and benchmark each Python version with its appropriate wheel
    print(f"\n{'=' * 70}")
    print("Testing and benchmarking")
    print(f"{'=' * 70}")

    for py_version in ALL_PYTHON_VERSIONS:
        wheel = wheel_for_version.get(py_version)
        if not wheel:
            # No wheel available for this version (build failed)
            continue

        # Test the wheel with pytest
        if not test_wheel(wheel, py_version):
            failed_tests.append(py_version)
            continue

        # Run benchmark
        if not run_benchmark(wheel, py_version):
            failed_tests.append(py_version)
            continue

    # Summary
    print(f"\n{'=' * 70}")
    print("BUILD SUMMARY")
    print(f"{'=' * 70}")
    print(
        f"Successful builds: sdist and {len(successful_wheels)} wheels "
        f"(1 abi3 + {len(NON_ABI3_VERSIONS)} non-abi3)"
    )
    print(
        f"Tests/benchmarks passed: {len(ALL_PYTHON_VERSIONS) - len(failed_tests) - len(failed_builds)}/{len(ALL_PYTHON_VERSIONS)} Python versions"
    )

    if failed_builds:
        print(f"\nFailed builds: {len(failed_builds)}")
        for failed_version in failed_builds:
            print(f"  ✗ {failed_version}")

    if failed_tests:
        print(f"\nFailed tests/benchmarks: {len(failed_tests)}")
        for failed_version in failed_tests:
            print(f"  ✗ Python {failed_version}")

    if not successful_wheels:
        print("\n✗ No successful wheels to upload")
        return 1

    # List files to upload
    sdist = list(dist_dir.glob("*.tar.gz"))
    upload_files = sdist + successful_wheels

    for file in upload_files:
        print(f"  - {file.name}")

    # Only upload if this is a clean release version
    if not is_release:
        print(make_release_message(version))
        return 0

    # Upload with twine
    upload_cmd = ["uvx", "twine", "upload"] + [str(f) for f in upload_files]
    if not run_command(upload_cmd, "Uploading to PyPI with twine"):
        print("\n✗ Upload failed")
        return 1

    print(f"\n{'=' * 70}")
    print("All builds and upload completed successfully!")
    print(f"{'=' * 70}")
    print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
