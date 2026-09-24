"""Unit tests for service categorization logic."""

import unittest
from utils.categorizer import categorize_service


class TestServiceCategorizer(unittest.TestCase):
    """Test suite for service categorization."""

    def test_remote_access_categories(self):
        self.assertEqual(categorize_service("ssh", "OpenSSH"), "Remote Access")
        self.assertEqual(categorize_service("telnet"), "Remote Access")
        self.assertEqual(categorize_service("ms-wbt-server", "Microsoft Terminal Services"), "Remote Access")

    def test_web_categories(self):
        self.assertEqual(categorize_service("http", "Apache httpd"), "Web")
        self.assertEqual(categorize_service("https", "nginx"), "Web")
        self.assertEqual(categorize_service("http-proxy"), "Web")

    def test_database_categories(self):
        self.assertEqual(categorize_service("mysql", "MySQL"), "Database")
        self.assertEqual(categorize_service("postgresql"), "Database")
        self.assertEqual(categorize_service("redis"), "Database")

    def test_file_sharing_categories(self):
        self.assertEqual(categorize_service("ftp", "vsftpd"), "File Sharing")
        self.assertEqual(categorize_service("microsoft-ds", "Samba"), "File Sharing")

    def test_unknown_service(self):
        self.assertEqual(categorize_service("some-obscure-custom-service"), "Unknown")
        self.assertEqual(categorize_service(""), "Unknown")


if __name__ == "__main__":
    unittest.main()
