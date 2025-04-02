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

from halmos.logs import debug, error, info
from halmos.utils import format_size

# Define the cache directory for solvers
SOLVER_CACHE_DIR = Path.home() / ".halmos" / "solvers"
SOLVER_CACHE_DIR.mkdir(parents=True, exist_ok=True)

YICES_BASE_URL = "https://github.com/SRI-CSL/yices2/releases/download/Yices-2.6.5"


@dataclass(frozen=True, eq=True, order=False, slots=True, kw_only=True)
class MachineInfo:
    system: str
    machine: str

    def __str__(self) -> str:
        return f"{self.system}-{self.machine}"


@dataclass(frozen=True, eq=False, order=False, slots=True)
class DownloadInfo:
    base_url: str
    filename: str
    checksum: str
    binary_name_in_archive: str


@dataclass(frozen=True, eq=False, order=False, slots=True)
class SolverInfo:
    # descriptive name, e.g., "yices" or "bitwuzla-abstraction"
    name: str

    # name of the executable, e.g., "yices-smt2" or "bitwuzla"
    binary_name: str

    # options/arguments/flags needed for this solver
    arguments: list[str]

    # maps (system, machine) tuples to download URLs
    downloads: dict[MachineInfo, DownloadInfo]


macos_intel = MachineInfo(system="Darwin", machine="x86_64")
macos_arm64 = MachineInfo(system="Darwin", machine="arm64")
linux_intel = MachineInfo(system="Linux", machine="x86_64")
windows_intel = MachineInfo(system="Windows", machine="x86_64")

# define known solvers
SUPPORTED_SOLVERS: dict[str, SolverInfo] = {
    "yices": SolverInfo(
        name="yices",
        binary_name="yices-smt2",
        arguments=["--smt2-model-format"],
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
    ),
    # for z3 we just rely on PATH/venv
    "z3": SolverInfo(
        name="z3",
        binary_name="z3",
        downloads={},
        arguments=[],
    ),
}


def get_platform_arch() -> MachineInfo:
    """Gets the current OS platform and architecture."""

    system = platform.system()  # e.g., 'Linux', 'Darwin', 'Windows'
    machine = platform.machine()  # e.g., 'x86_64', 'arm64', 'AMD64'

    # AMD64 is basically an alias for x86_64, let's use x86_64 as the canonical name
    machine = "x86_64" if machine == "AMD64" else machine

    return MachineInfo(system=system, machine=machine)


def binary_path_in_cache(solver: SolverInfo) -> Path:
    """
    Gets the (expected) path to the binary in the cache.

    Does not check if the file exists.
    """

    suffix = ".exe" if platform.system() == "Windows" else ""
    return SOLVER_CACHE_DIR / f"{solver.binary_name}{suffix}"


def verify_checksum(file_path: Path, expected_checksum: str) -> bool:
    """
    Verifies the SHA256 checksum of a file.

    Raises a ValueError if the checksum does not match.
    """

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    actual = sha256_hash.hexdigest().lower()
    expected = expected_checksum.lower()
    if actual != expected:
        raise ValueError(f"{expected=}, {actual=}")

    return True


def download(
    download_info: DownloadInfo, output_dir: Path, timeout_seconds: int = 10
) -> Path | None:
    """Downloads the solver archive."""

    url = download_info.base_url + "/" + download_info.filename
    response = requests.get(url, stream=True, timeout=timeout_seconds)
    response.raise_for_status()
    archive_path = output_dir / download_info.filename

    with open(archive_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    return archive_path


def list_archive(archive_path: Path) -> None:
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


def extract_file(archive_path: Path, filename: str) -> bytes | None:
    """Extracts a file from the archive."""

    if archive_path.name.endswith(".tar.gz"):
        with tarfile.open(archive_path, "r:gz") as tar:
            # may raise KeyError
            member = tar.getmember(filename)
            return tar.extractfile(member).read()
    elif archive_path.name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zip:
            # may raise KeyError
            member = zip.getinfo(filename)
            return zip.read(member)
    else:
        raise RuntimeError(f"Unsupported archive format: {archive_path.suffix}")


def install_solver(solver: SolverInfo) -> Path:
    """
    Downloads, verifies, and extracts the solver archive.

    The caller is responsible for handling exceptions.
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        machine_tuple = get_platform_arch()
        download_info = solver.downloads.get(machine_tuple)
        if not download_info:
            raise RuntimeError(
                f"No download URL configured {solver.name=}, {machine_tuple=}"
            )

        # Download the archive
        url = download_info.base_url + "/" + download_info.filename
        info(f"Downloading from {url}...")
        archive_path = download(download_info, Path(tmpdir))

        if not archive_path:
            raise RuntimeError(f"Failed to download {solver.name} from {url}")

        # Verify checksum
        info(f"Verifying sha256 hash for {archive_path}... ")
        verify_checksum(archive_path, download_info.checksum)

        # Extract the binary from the archive
        binary_filename = download_info.binary_name_in_archive
        info(f"Extracting {binary_filename} from {archive_path}...")
        content = extract_file(archive_path, binary_filename)
        if not content:
            raise RuntimeError(
                f"Failed to extract {binary_filename} from {archive_path}"
            )

        # Write the binary to the cache
        install_path = binary_path_in_cache(solver)
        if install_path.exists():
            raise RuntimeError(f"File already exists: {install_path}")

        install_path.write_bytes(content)
        info(f"Wrote {install_path} ({format_size(len(content))})")

        # Make the binary executable
        install_path.chmod(install_path.stat().st_mode | stat.S_IXUSR)

        return install_path


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


def find_solver_binary(solver: SolverInfo) -> Path | None:
    """
    Finds the solver binary path.
    Checks cache first, then PATH, then venv (for z3).
    """

    cache_bin = binary_path_in_cache(solver)

    # 1. Check cache
    if cache_bin.exists() and os.access(cache_bin, os.X_OK):
        debug(f"Found {solver.name} binary in cache: {cache_bin}")
        return cache_bin

    # 2. Check PATH
    path_bin = shutil.which(solver.binary_name)
    if path_bin:
        debug(f"Found {solver.name} binary in PATH: {path_bin}")
        return Path(path_bin)

    # 3. Special check for z3 in venv
    if solver.name == "z3":
        venv_z3 = find_z3_path_in_venv()
        if venv_z3:
            debug(f"Found z3 binary in venv: {venv_z3}")
            return venv_z3

    debug(f"Solver binary '{solver.name}' not found in cache or PATH.")
    return None


def ensure_solver_available(solver: SolverInfo) -> Path:
    """
    Ensures the specified solver is available, downloading it if necessary.
    Returns the path to the executable binary or None if unavailable/installation fails.
    """

    binary_path = find_solver_binary(solver)
    if binary_path:
        return binary_path

    # If not found, attempt download
    installed_path = install_solver(solver)
    return installed_path


# this is the public entrypoint for this module
def get_solver_command(solver_name: str) -> list[str]:
    """
    Gets the full command list (binary path + arguments) for the specified solver.
    Ensures the solver is available first.
    """

    solver_info: SolverInfo | None = SUPPORTED_SOLVERS.get(solver_name)
    if not solver_info:
        # should have been caught by the config parsing:
        #   `--solver <solver_name>` is a high level command that expects a supported solver
        # solvers not managed by halmos can be accessed with the low-level
        #   `--solver-command "solver_binary <args>"`
        raise ValueError(f"Unsupported solver: {solver_name}")

    solver_binary_path = ensure_solver_available(solver_info)
    if not solver_binary_path:
        raise RuntimeError(f"Solver '{solver_name}' could not be found or installed.")

    command = [str(solver_binary_path)] + solver_info.arguments
    debug(f"Solver command for '{solver_name}': {' '.join(command)}")
    return command


# python -m halmos.solvers <solver_name>
# useful when adding a new solver:
# - tests the download for all platforms
# - prints the checksums,
# - lists the archive contents
# - verifies that we can extract the binary from the archive
if __name__ == "__main__":
    import sys
    import time

    if not len(sys.argv) > 1:
        print("Usage: python solvers.py <solver_name>")
        print("Supported:", list(SUPPORTED_SOLVERS.keys()))
        sys.exit(1)

    solver_name = sys.argv[1]
    solver_info: SolverInfo = SUPPORTED_SOLVERS[solver_name]

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        for machine_tuple, download_info in solver_info.downloads.items():
            print(f"Downloading {download_info.base_url}/{download_info.filename}")
            archive_path = download(download_info, Path(tmpdir))

            print(f"Downloaded to {archive_path}")
            verify_checksum(archive_path, download_info.checksum)

            print("Listing archive contents:")
            list_archive(archive_path)

            filename = download_info.binary_name_in_archive
            print(f"\nExtracting {filename} from {archive_path}")
            content = extract_file(archive_path, filename)

            if not content:
                print(f"Failed to extract {filename} from {archive_path}")
                continue

            output_path = Path(tmpdir) / f"{machine_tuple}-{solver_name}"
            output_path.write_bytes(content)
            output_path.chmod(output_path.stat().st_mode | stat.S_IXUSR)

            print(f"Wrote {format_size(len(content))} to {output_path}")

            # avoid rate limiting
            time.sleep(1)

    # confirm deletion
    if input(f"Delete the temp dir {tmpdir}? (y/N) ") == "y":
        shutil.rmtree(tmpdir)
