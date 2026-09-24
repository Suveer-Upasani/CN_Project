"""Nmap dependency manager and execution engine."""

import os
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

from utils.logger import get_logger


class NmapError(Exception):
    """Base exception for Nmap operations."""
    pass


class NmapNotFoundError(NmapError):
    """Raised when Nmap executable is not installed or not found in PATH."""
    pass


class NmapExecutionError(NmapError):
    """Raised when Nmap execution returns a non-zero exit code or fails."""
    def __init__(self, message: str, return_code: int = -1, stderr: str = ""):
        super().__init__(message)
        self.return_code = return_code
        self.stderr = stderr


class NmapTimeoutError(NmapError):
    """Raised when an Nmap scan exceeds the configured timeout."""
    pass


class NmapManager:
    """Manages discovery and safe execution of Nmap subprocesses."""

    # Common fallback paths if not directly on system PATH
    KNOWN_PATHS = [
        "/opt/homebrew/bin/nmap",
        "/usr/local/bin/nmap",
        "/usr/bin/nmap",
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe",
    ]

    def __init__(self, custom_path: Optional[str] = None):
        self.logger = get_logger()
        self.nmap_path = self._find_nmap(custom_path)

    def _find_nmap(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Locate the Nmap binary."""
        if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
            return custom_path

        which_path = shutil.which("nmap")
        if which_path:
            return which_path

        for candidate in self.KNOWN_PATHS:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def is_available(self) -> bool:
        """Check if Nmap is detected and executable."""
        return self.nmap_path is not None

    def get_version(self) -> Tuple[bool, str]:
        """Retrieve Nmap version string.

        Returns:
            Tuple of (success_bool, version_string_or_error)
        """
        if not self.nmap_path:
            return False, "Nmap is not installed or not available in PATH."

        try:
            self.logger.debug(f"Checking Nmap version using binary: {self.nmap_path}")
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                match = re.search(r"Nmap version\s+([^\s]+)", result.stdout)
                if match:
                    version = match.group(1)
                    return True, version
                # Fallback to first line
                first_line = result.stdout.strip().splitlines()[0]
                return True, first_line
            else:
                return False, f"Failed to query Nmap version (exit code {result.returncode})"
        except Exception as exc:
            self.logger.error(f"Error querying Nmap version: {exc}")
            return False, str(exc)

    def run_scan(self, args: List[str], timeout: Optional[int] = 300) -> str:
        """Execute Nmap with the specified arguments and return stdout.

        Args:
            args: Command line arguments for Nmap (e.g. ['-sT', '-Pn', '-oX', '-', '127.0.0.1'])
            timeout: Maximum execution time in seconds.

        Returns:
            Raw stdout string (usually XML formatted when '-oX -' is requested).

        Raises:
            NmapNotFoundError: If Nmap binary is missing.
            NmapTimeoutError: If execution exceeds timeout.
            NmapExecutionError: If Nmap fails with an error or permission issue.
        """
        if not self.nmap_path:
            raise NmapNotFoundError("Nmap is not installed or not available in PATH.")

        cmd = [self.nmap_path] + args
        cmd_str = " ".join(cmd)
        self.logger.info(f"Executing Nmap command: {cmd_str}")

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            if process.returncode != 0:
                stderr_clean = process.stderr.strip()
                self.logger.error(
                    f"Nmap command failed (exit code {process.returncode}): {stderr_clean}"
                )
                # Check for common permission error messages
                if "requires root privileges" in stderr_clean.lower() or "permission denied" in stderr_clean.lower():
                    raise NmapExecutionError(
                        "Insufficient permissions for this scan configuration.",
                        return_code=process.returncode,
                        stderr=stderr_clean,
                    )
                raise NmapExecutionError(
                    f"Nmap returned an error: {stderr_clean or 'Unknown error'}",
                    return_code=process.returncode,
                    stderr=stderr_clean,
                )

            self.logger.debug(f"Nmap command completed successfully. Output size: {len(process.stdout)} bytes")
            return process.stdout

        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timed out after {timeout} seconds: {cmd_str}")
            raise NmapTimeoutError(f"Scan timed out after {timeout} seconds.")
        except FileNotFoundError:
            raise NmapNotFoundError("Nmap binary not found.")
        except NmapError:
            raise
        except Exception as exc:
            self.logger.error(f"Unexpected error executing Nmap: {exc}")
            raise NmapExecutionError(f"Execution error: {exc}")
