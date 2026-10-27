"""Automated tests for Flask application initialization, configuration, and security headers."""

import unittest
from app import create_app


class TestFlaskApp(unittest.TestCase):
    """Test suite for Flask core application initialization."""

    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "DB_PATH": ":memory:",
            "OUTPUT_DIR": "output",
        })
        self.client = self.app.test_client()

    def test_app_created(self):
        """Verify Flask app factory creates valid instance with config."""
        self.assertTrue(self.app.config["TESTING"])
        self.assertIn("SCAN_SERVICE", self.app.config)

    def test_security_headers_present(self):
        """Verify required security headers are attached to responses."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_root_redirect(self):
        """Verify root URL / redirects to /dashboard."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/dashboard", res.headers.get("Location", ""))

    def test_404_error_page(self):
        """Verify custom 404 page is rendered for invalid page routes."""
        res = self.client.get("/non-existent-page-url")
        self.assertEqual(res.status_code, 404)
        self.assertIn(b"Page Not Found", res.data)

    def test_404_json_for_api(self):
        """Verify JSON error returned for non-existent API routes."""
        res = self.client.get("/api/non-existent-endpoint")
        self.assertEqual(res.status_code, 404)
        self.assertTrue(res.is_json)
        self.assertIn("error", res.get_json())

    def test_default_config_security(self):
        """Verify security defaults in app creation."""
        app = create_app({"DB_PATH": ":memory:"})
        self.assertFalse(app.config.get("DEBUG", False))
        self.assertEqual(app.config["MAX_CONTENT_LENGTH"], 1024 * 1024)
        self.assertEqual(app.config["MAX_CONCURRENT_SCANS"], 2)

    def test_405_method_not_allowed(self):
        """Verify 405 handler returns JSON for API routes."""
        res = self.client.post("/api/health")
        self.assertEqual(res.status_code, 405)
        self.assertTrue(res.is_json)
        self.assertIn("error", res.get_json())


if __name__ == "__main__":
    unittest.main()
