"""Manager for selecting and applying safe NSE script profiles."""

from typing import List, Optional
from nse.profiles import NSE_PROFILES
from utils.logger import get_logger


class ScriptManager:
    """Manages safe NSE script selection and Nmap argument generation."""

    def __init__(self):
        self.logger = get_logger()

    def get_available_profiles(self) -> List[str]:
        """Return list of valid profile names."""
        return list(NSE_PROFILES.keys())

    def get_script_args(self, profile_name: Optional[str]) -> List[str]:
        """Generate Nmap command line arguments for the requested NSE profile.

        Args:
            profile_name: Name of profile (e.g. 'none', 'basic', 'service-info', 'safe').

        Returns:
            List of CLI flags to pass to Nmap (e.g. ['--script', 'safe']).
        """
        if not profile_name or profile_name.lower() in ("none", "off", "disabled"):
            return []

        profile_key = profile_name.lower().strip()
        if profile_key not in NSE_PROFILES:
            self.logger.warning(
                f"Unknown NSE profile '{profile_name}'. Defaulting to 'basic'."
            )
            profile_key = "basic"

        scripts = NSE_PROFILES[profile_key]["scripts"]
        if not scripts:
            return []

        script_str = ",".join(scripts)
        self.logger.info(f"Applying safe NSE profile '{profile_key}': {script_str}")
        return ["--script", script_str]
