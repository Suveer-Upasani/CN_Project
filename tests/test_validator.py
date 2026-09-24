"""Unit tests for target validation and DNS resolution."""

import unittest
from utils.validator import validate_target, ValidationResult


class TestTargetValidator(unittest.TestCase):
    """Test suite for target input validation."""

    def test_valid_ipv4_addresses(self):
        """Test standard valid IPv4 inputs."""
        res = validate_target("127.0.0.1")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.resolved_ip, "127.0.0.1")
        self.assertTrue(res.is_ip)

        res2 = validate_target("192.168.1.100")
        self.assertTrue(res2.is_valid)
        self.assertEqual(res2.resolved_ip, "192.168.1.100")

    def test_valid_localhost(self):
        """Test localhost hostname resolution."""
        res = validate_target("localhost")
        self.assertTrue(res.is_valid)
        self.assertIn(res.resolved_ip, ["127.0.0.1", "::1"])

    def test_invalid_ips(self):
        """Test malformed IP addresses."""
        res = validate_target("999.999.999.999")
        self.assertFalse(res.is_valid)
        self.assertIn("Invalid IPv4 address format", res.error_message)

        res2 = validate_target("192.168.1.500")
        self.assertFalse(res2.is_valid)
        self.assertIn("Invalid IPv4 address format", res2.error_message)

    def test_empty_or_whitespace_targets(self):
        """Test rejection of empty strings."""
        res = validate_target("")
        self.assertFalse(res.is_valid)

        res2 = validate_target("   ")
        self.assertFalse(res2.is_valid)

    def test_injection_characters(self):
        """Test rejection of suspicious shell injection characters."""
        disallowed = [
            "127.0.0.1; ls",
            "localhost && rm -rf",
            "192.168.1.1 | cat",
            "target`whoami`",
            "$(uname -a)",
        ]
        for item in disallowed:
            res = validate_target(item)
            self.assertFalse(res.is_valid, f"Target '{item}' should be marked invalid")


if __name__ == "__main__":
    unittest.main()
