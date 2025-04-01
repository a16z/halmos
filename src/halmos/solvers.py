import hashlib
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests

from halmos.logs import debug, error, info, warn

# Define the cache directory for solvers
SOLVER_CACHE_DIR = Path.home() / ".halmos" / "solvers"
SOLVER_CACHE_DIR.mkdir(parents=True, exist_ok=True)

YICES_BASE_URL = "https://github.com/SRI-CSL/yices2/releases/download/Yices-2.6.5"


@dataclass(frozen=True, eq=True, order=False, slots=True, kw_only=True)
class MachineInfo:
    system: str
    machine: str


@dataclass(frozen=True, eq=False, order=False, slots=True)
class DownloadInfo:
    base_url: str
    filename: str
    checksum: str
    binary_name_in_archive: str


@dataclass(frozen=True, eq=False, order=False, slots=True)
class SolverInfo:
    name: str

    # maps (system, machine) tuples to download URLs
    downloads: dict[MachineInfo, DownloadInfo]

    # options/arguments/flags needed for this solver
    arguments: list[str]

    # name of the final binary file in the cache
    binary_name_in_cache: str = ""  # defaults to binary_name_in_archive if empty


macos_intel = MachineInfo(system="Darwin", machine="x86_64")
macos_arm64 = MachineInfo(system="Darwin", machine="arm64")
linux_intel = MachineInfo(system="Linux", machine="x86_64")
windows_intel = MachineInfo(system="Windows", machine="x86_64")

# define known solvers
SUPPORTED_SOLVERS: dict[str, SolverInfo] = {
    "yices": SolverInfo(
        name="yices",
        downloads={
            macos_intel: DownloadInfo(
                base_url=YICES_BASE_URL,
                filename="yices-2.6.5-x86_64-apple-darwin21.6.0-static-gmp.tar.gz",
                checksum="831094681703173cb30657e9a9d690bd6139f435ff44afdcf81f8e761f9ed0c4",
                binary_name_in_archive="yices-2.6.5/bin/yices-smt2",
            ),
            macos_arm64: DownloadInfo(
                base_url=YICES_BASE_URL,
                filename="yices-2.6.5-arm-apple-darwin22.6.0-static-gmp.tar.gz",
                checksum="b75f2881859fb91c1e8fae121595091b89c07421f35db0e7cddc8a43cba13507",
                binary_name_in_archive="yices-2.6.5/bin/yices-smt2",
            ),
            linux_intel: DownloadInfo(
                base_url=YICES_BASE_URL,
                filename="yices-2.6.5-x86_64-pc-linux-gnu-static-gmp.tar.gz",
                checksum="d6c9465c261e4f4eabd240d0dd9dff5e740fca2beb0042de15f67954bbc70cce",
                binary_name_in_archive="yices-2.6.5/bin/yices-smt2",
            ),
            windows_intel: DownloadInfo(
                base_url=YICES_BASE_URL,
                filename="yices-2.6.5-x86_64-unknown-mingw32-static-gmp.zip",
                checksum="189aaa5515bb71c18996b87d7eceb8cfa037a7b2114f6b46abf5c6f4f07072af",
                binary_name_in_archive="yices-2.6.5/bin/yices-smt2.exe",
            ),
        },
        binary_name_in_archive="yices-2.6.5/bin/yices-smt2",
        binary_name_in_cache="yices",
        arguments=["--smt2-model-format"],
    ),
    # for z3 we just rely on PATH/venv
    "z3": SolverInfo(
        name="z3",
        downloads={},
        binary_name_in_archive="z3",
        arguments=[],
    ),
}


def get_platform_arch() -> MachineInfo:
    """Gets the current OS platform and architecture."""

    system = platform.system()  # e.g., 'Linux', 'Darwin', 'Windows'
    machine = platform.machine()  # e.g., 'x86_64', 'arm64', 'AMD64'

    return MachineInfo(system=system, machine=machine)


def _verify_checksum(file_path: Path, expected_checksum: str) -> bool:
    """Verifies the SHA256 checksum of a file."""

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    calculated_checksum = sha256_hash.hexdigest()
    if calculated_checksum != expected_checksum:
        warn(
            f"Checksum mismatch for {file_path}: Expected {expected_checksum}, Got {calculated_checksum}"
        )
        return False
    debug(f"Checksum verified for {file_path}")
    return True


def _download(
    download_info: DownloadInfo, output_dir: Path, timeout_seconds: int = 10
) -> Path | None:
    """
    Downloads the solver archive.

    May throw requests.exceptions.RequestException
    """

    url = download_info.base_url + "/" + download_info.filename
    response = requests.get(url, stream=True, timeout=timeout_seconds)
    response.raise_for_status()
    archive_path = output_dir / download_info.filename

    with open(archive_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    return archive_path


def _list_archive(archive_path: Path) -> None:
    """Lists the contents of the solver archive."""

    if archive_path.name.endswith(".tar.gz"):
        with tarfile.open(archive_path, "r:gz") as tar:
            # list contents
            for member in tar.getmembers():
                # locate executable files
                executable = (
                    member.mode & stat.S_IXUSR != 0 and member.type == tarfile.REGTYPE
                )

                print(f"{'* ' if executable else '  '}{member.name}")

    elif archive_path.name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zip:
            # list contents
            for member in zip.infolist():
                filemode = member.external_attr >> 16
                executable = filemode & stat.S_IXUSR != 0 and member.file_size > 0
                print(f"{'* ' if executable else '  '}{member.filename}")

    else:
        error(f"Unsupported archive format: {archive_path.suffix}")
        return None


def _download_and_extract_solver(
    solver_info: SolverInfo, url: str, expected_checksum: str
) -> Path | None:
    """Downloads, verifies, and extracts the solver archive."""
    binary_path_in_cache = SOLVER_CACHE_DIR / (
        solver_info.binary_name_in_cache or solver_info.binary_name_in_archive
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / Path(url).name
        info(f"Downloading {solver_info.name} from {url}...")
        try:
            response = requests.get(url, stream=True, timeout=300)  # 5 min timeout
            response.raise_for_status()
            with open(archive_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            info(f"Downloaded to {archive_path}")

            # Verify checksum
            if not _verify_checksum(archive_path, expected_checksum):
                # Keep the downloaded file for inspection if checksum fails? For now, let's delete.
                error(
                    f"Checksum verification failed for {archive_path}. Aborting installation."
                )
                return None

            # Extract the archive
            info(f"Extracting {archive_path}...")
            if url.endswith(".tar.gz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    # Find the binary member
                    # Search within common parent directories too (e.g., yices-2.6.5-..../bin/yices-smt2)
                    member_to_extract = None
                    for member in tar.getmembers():
                        if member.name.endswith(
                            f"/{solver_info.binary_name_in_archive}"
                        ):
                            member_to_extract = member
                            break

                    if not member_to_extract:
                        error(
                            f"Could not find binary '{solver_info.binary_name_in_archive}' in {archive_path}"
                        )
                        return None

                    # Extract just the binary to the temp dir first
                    member_to_extract.name = Path(
                        member_to_extract.name
                    ).name  # Extract without full path
                    tar.extract(member_to_extract, path=tmpdir)
                    extracted_binary_path = Path(tmpdir) / member_to_extract.name

                    # Move to cache and make executable
                    shutil.move(str(extracted_binary_path), str(binary_path_in_cache))
                    binary_path_in_cache.chmod(
                        binary_path_in_cache.stat().st_mode
                        | stat.S_IXUSR
                        | stat.S_IXGRP
                        | stat.S_IXOTH
                    )
                    info(
                        f"Solver '{solver_info.name}' installed to {binary_path_in_cache}"
                    )
                    return binary_path_in_cache
            # Add handling for other archive types (e.g., .zip) if needed
            else:
                error(f"Unsupported archive format for URL: {url}")
                return None

        except requests.exceptions.RequestException as e:
            error(f"Failed to download {solver_info.name}: {e}")
            return None
        except tarfile.TarError as e:
            error(f"Failed to extract {archive_path}: {e}")
            return None
        except Exception as e:
            error(f"An unexpected error occurred during solver installation: {e}")
            return None

    return None  # Should not be reached if successful


def find_solver_binary(solver_name: str) -> Path | None:
    """
    Finds the solver binary path.
    Checks cache first, then PATH, then venv (for z3).
    """
    if solver_name not in SUPPORTED_SOLVERS:
        warn(f"Solver '{solver_name}' is not explicitly supported by halmos.")
        # Still try PATH as a fallback
        return shutil.which(solver_name)

    solver_info = SUPPORTED_SOLVERS[solver_name]
    binary_name = solver_info.binary_name_in_cache or solver_info.binary_name_in_archive
    cached_binary_path = SOLVER_CACHE_DIR / binary_name

    # 1. Check cache
    if cached_binary_path.exists() and os.access(cached_binary_path, os.X_OK):
        debug(f"Found {solver_name} binary in cache: {cached_binary_path}")
        return cached_binary_path

    # 2. Check PATH (using the cached name first, then the base name)
    path_binary = shutil.which(binary_name) or shutil.which(
        solver_info.binary_name_in_archive
    )
    if path_binary:
        debug(f"Found {solver_name} binary in PATH: {path_binary}")
        return Path(path_binary)

    # 3. Special check for z3 in venv (using logic from config.py)
    if solver_name == "z3":
        venv_z3 = find_z3_path_in_venv()  # We'll need to define or import this helper
        if venv_z3:
            debug(f"Found z3 binary in venv: {venv_z3}")
            return venv_z3

    debug(f"Solver binary '{binary_name}' not found in cache or PATH.")
    return None


def ensure_solver_available(solver_name: str) -> Path | None:
    """
    Ensures the specified solver is available, downloading it if necessary.
    Returns the path to the executable binary or None if unavailable/installation fails.
    """
    binary_path = find_solver_binary(solver_name)
    if binary_path:
        return binary_path

    # If not found, attempt download for supported solvers with URLs
    if solver_name not in SUPPORTED_SOLVERS:
        warn(f"Cannot automatically install unsupported solver: {solver_name}")
        return None

    solver_info = SUPPORTED_SOLVERS[solver_name]
    system, machine = get_platform_arch()
    platform_key = (system, machine)

    if not solver_info.download_urls:
        warn(
            f"No download URLs configured for solver '{solver_name}'. Please install it manually and ensure it's in PATH."
        )
        return None

    if platform_key not in solver_info.download_urls:
        error(
            f"No download URL configured for solver '{solver_name}' on platform {system}/{machine}."
        )
        return None

    url = solver_info.download_urls[platform_key]
    expected_checksum = solver_info.checksums.get(url)

    if not expected_checksum or expected_checksum.startswith("EXPECTED_CHECKSUM"):
        # For now, proceed without checksum if not defined or placeholder, but warn
        warn(
            f"Checksum not defined for {solver_name} URL: {url}. Cannot verify integrity."
        )
        # In a stricter mode, we might return None here
        expected_checksum = None  # Or set to None to skip verification

    # Attempt download and installation
    installed_path = _download_and_extract_solver(solver_info, url, expected_checksum)
    return installed_path


def get_solver_command(solver_name: str) -> list[str] | None:
    """
    Gets the full command list (binary path + arguments) for the specified solver.
    Ensures the solver is available first.
    """
    solver_binary_path = ensure_solver_available(solver_name)
    if not solver_binary_path:
        error(f"Solver '{solver_name}' could not be found or installed.")
        return None

    if solver_name not in SUPPORTED_SOLVERS:
        # For unsupported solvers found in PATH, return just the binary path
        return [str(solver_binary_path)]

    solver_info = SUPPORTED_SOLVERS[solver_name]
    command = [str(solver_binary_path)] + solver_info.arguments
    debug(f"Solver command for '{solver_name}': {' '.join(command)}")
    return command


# Helper function to find z3 in venv (similar to the one in config.py)
# Consider moving the original `find_venv_root` and `find_z3_path` to a common utils module
# For now, let's duplicate/adapt it here.
def find_venv_root() -> Path | None:
    if "VIRTUAL_ENV" in os.environ:
        return Path(os.environ["VIRTUAL_ENV"])
    # Simplified check - assumes if running within Python env, sys.prefix is relevant
    if (
        hasattr(sys, "prefix")
        and hasattr(sys, "base_prefix")
        and sys.prefix != sys.base_prefix
    ):
        return Path(sys.prefix)
    return None


def find_z3_path_in_venv() -> Path | None:
    venv_path = find_venv_root()
    if venv_path:
        z3_bin = "z3.exe" if platform.system() == "Windows" else "z3"
        # Check common bin locations
        for bin_dir in ["bin", "Scripts"]:  # Scripts for Windows venv
            z3_path = venv_path / bin_dir / z3_bin
            if z3_path.exists() and os.access(z3_path, os.X_OK):
                return z3_path
    return None


if __name__ == "__main__":
    import sys
    import time

    if not len(sys.argv) > 1:
        print("Usage: python solvers.py <solver_name>")
        print("Supported:", list(SUPPORTED_SOLVERS.keys()))
        sys.exit(1)

    solver_to_test = sys.argv[1]
    solver_info: SolverInfo = SUPPORTED_SOLVERS[solver_to_test]

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        for download_info in solver_info.downloads.values():
            print(f"Downloading {download_info.base_url}/{download_info.filename}")
            archive_path = _download(download_info, Path(tmpdir))

            print(f"Downloaded to {archive_path}")
            _verify_checksum(archive_path, download_info.checksum)

            print("Listing archive contents:")
            _list_archive(archive_path)

            print()

            # avoid rate limiting
            time.sleep(1)

    # confirm deletion
    if input(f"Delete the temp dir {tmpdir}? (y/N) ") == "y":
        shutil.rmtree(tmpdir)
