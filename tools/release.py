#!/usr/bin/env python3
"""Build wheels for all supported Python versions using uv."""

import subprocess
import sys
import tomllib
from pathlib import Path
import shutil
from packaging.specifiers import SpecifierSet
from packaging.version import Version

# Import generate module from same directory
sys.path.insert(0, str(Path(__file__).parent))
import generate


def get_python_versions():
    """Get supported Python versions."""
    pyproject_toml = Path(__file__).parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject_toml.read_text(encoding="utf-8"))
    spec = SpecifierSet(data["project"]["requires-python"])
    # Generate versions that match the specifier (up to Python 3.14)
    return [f"3.{minor}" for minor in range(10, 15) if f"3.{minor}" in spec]


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


PYTHON_VERSIONS = get_python_versions()


def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"\n{'=' * 70}")
    print(f"{description}")
    print(f"{'=' * 70}")
    print(f">>> {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed with exit code {e.returncode}", file=sys.stderr)
        return False


def normalize_line_endings(repo_root: Path):
    """Normalize all text files to LF line endings."""
    # Patterns for files to normalize
    patterns = [
        "pyaegis/**/*.py",
        "pyaegis/**/*.h",
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
    if not run_command(
        ["uv", "run", "ruff", "check", "--fix", "."], "Running ruff check --fix"
    ):
        print("✗ Ruff check failed", file=sys.stderr)
        return 1

    # Run ruff format
    if not run_command(["uv", "run", "ruff", "format", "."], "Running ruff format"):
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
        f"Packaging pyaegis-{version}"
        + (" for release" if is_release else " (not release)")
    )
    print(f"Building wheels for Python versions: {', '.join(PYTHON_VERSIONS)}")
    print(f"Output directory: {dist_dir}", end=" ")

    # Clean dist directory
    if dist_dir.exists():
        print("(wiped)")
        shutil.rmtree(dist_dir)
    else:
        print("(created)")
    print(f"{'=' * 70}")

    # Build source distribution first
    if not run_command(
        ["uv", "build", "--sdist", "--quiet"], "Building source distribution"
    ):
        print("✗ Source distribution build failed", file=sys.stderr)
        return 1

    failed_builds = []
    successful_wheels = []

    for py_version in PYTHON_VERSIONS:
        # Build wheel
        description = f"Building wheel for Python {py_version}"
        cmd = ["uv", "build", "--python", py_version, "--wheel", "--quiet"]

        if not run_command(cmd, description):
            failed_builds.append(py_version)
            continue

        # Find the wheel for this version
        wheel_pattern = f"pyaegis-*-cp{py_version.replace('.', '')}-*.whl"
        wheels = list(dist_dir.glob(wheel_pattern))
        if not wheels:
            print(f"✗ Could not find wheel for Python {py_version}", file=sys.stderr)
            failed_builds.append(py_version)
            continue

        wheel = wheels[0]

        # Test the wheel with pytest (use --isolated to avoid .venv conflicts)
        test_cmd = [
            "uv",
            "run",
            "--isolated",
            "--python",
            py_version,
            "--with",
            str(wheel),
            "--with",
            "pytest",
            "pytest",
        ]
        if not run_command(
            test_cmd, f"Testing wheel for Python {py_version} with pytest"
        ):
            print(f"✗ Tests failed for Python {py_version}", file=sys.stderr)
            failed_builds.append(py_version)
            continue

        # Run benchmark (use --isolated to avoid .venv conflicts)
        bench_cmd = [
            "uv",
            "run",
            "--isolated",
            "--python",
            py_version,
            "--with",
            str(wheel),
            "-m",
            "pyaegis.benchmark",
        ]
        if not run_command(bench_cmd, f"Running benchmark for Python {py_version}"):
            print(f"✗ Benchmark failed for Python {py_version}", file=sys.stderr)
            failed_builds.append(py_version)
            continue

        successful_wheels.append(wheel)

    # Summary
    print(f"\n{'=' * 70}")
    print("BUILD SUMMARY")
    print(f"{'=' * 70}")
    print(
        f"Successful builds: sdist and {len(successful_wheels)}/{len(PYTHON_VERSIONS)} wheels"
    )

    if failed_builds:
        print(f"\nFailed builds: {len(failed_builds)}")
        for version in failed_builds:
            print(f"  ✗ Python {version}")

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
    sys.exit(main())
