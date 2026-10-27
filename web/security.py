"""Security helpers for CSRF protection and input sanitization."""

import secrets
from flask import current_app, request, session


def get_csrf_token() -> str:
    """Retrieve or generate a CSRF token for the current session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf() -> bool:
    """Verify CSRF token for state-changing requests."""
    # Allow test suite to bypass if explicitly configured
    if current_app.config.get("TESTING") and not current_app.config.get("WTF_CSRF_ENABLED", False):
        return True

    expected = session.get("_csrf_token")
    if not expected:
        return False

    # Check header first (common for AJAX/Fetch), then form field
    received = request.headers.get("X-CSRF-Token")
    if not received and request.form:
        received = request.form.get("csrf_token")

    if not received:
        # Check JSON payload if present
        if request.is_json:
            json_data = request.get_json(silent=True) or {}
            received = json_data.get("csrf_token")

    if not received:
        return False

    return secrets.compare_digest(expected, received)
