"""PortSentinel - Flask Web Application Entrypoint.

Starts the professional cybersecurity dashboard and background scanning engine.
"""

import os
import sys
from typing import Optional

from flask import Flask, jsonify, render_template, request

from services.scan_service import ScanService
from utils.logger import setup_logger
from web.api import api_bp
from web.routes import page_bp
from web.security import get_csrf_token


def create_app(config_overrides: Optional[dict] = None) -> Flask:
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Core Security and Application Configuration
    app.config["SECRET_KEY"] = os.environ.get(
        "PORTSENTINEL_SECRET_KEY", "portsentinel-insecure-lab-secret-key-change-in-prod"
    )
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB maximum payload
    app.config["OUTPUT_DIR"] = "output"
    app.config["DB_PATH"] = "data/portsentinel.db"
    app.config["MAX_CONCURRENT_SCANS"] = 2
    app.config["WTF_CSRF_ENABLED"] = True

    if config_overrides:
        app.config.update(config_overrides)

    # Initialize Logger
    setup_logger(verbose=app.config.get("DEBUG", False))

    # Initialize Scan Service & History Repository
    scan_service = ScanService(
        max_concurrent_scans=app.config["MAX_CONCURRENT_SCANS"],
        output_dir=app.config["OUTPUT_DIR"],
        db_path=app.config["DB_PATH"],
    )
    app.config["SCAN_SERVICE"] = scan_service

    # Expose CSRF token generator to Jinja2 templates
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=get_csrf_token)

    # Register Blueprints
    app.register_blueprint(page_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    # Security Response Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        msg = getattr(error, "description", "Bad Request")
        if request.path.startswith("/api/"):
            return jsonify({"error": msg}), 400
        return render_template("error.html", error_code=400, title="Bad Request", message=msg), 400

    @app.errorhandler(403)
    def forbidden(error):
        msg = getattr(error, "description", "Forbidden")
        if request.path.startswith("/api/"):
            return jsonify({"error": msg}), 403
        return render_template("error.html", error_code=403, title="Forbidden", message=msg), 403

    @app.errorhandler(404)
    def not_found(error):
        msg = getattr(error, "description", "Resource not found.")
        if request.path.startswith("/api/"):
            return jsonify({"error": msg}), 404
        return render_template("error.html", error_code=404, title="Page Not Found", message=msg), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        msg = getattr(error, "description", "Method Not Allowed")
        if request.path.startswith("/api/"):
            return jsonify({"error": msg}), 405
        return render_template("error.html", error_code=405, title="Method Not Allowed", message=msg), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        msg = getattr(error, "description", "Too Many Requests")
        if request.path.startswith("/api/"):
            return jsonify({"error": msg}), 429
        return render_template("error.html", error_code=429, title="Rate Limited", message=msg), 429

    @app.errorhandler(500)
    def server_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "An internal server error occurred."}), 500
        return (
            render_template(
                "error.html",
                error_code=500,
                title="Internal Server Error",
                message="An unexpected server error occurred during request processing.",
            ),
            500,
        )

    return app


APP_BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                    PORTSENTINEL DASHBOARD v1.0                   ║
║         Network Reconnaissance & Open-Port Analysis Engine       ║
║               Web Interface & Background Controller              ║
╚══════════════════════════════════════════════════════════════════╝
"""


def main():
    """Start the PortSentinel Flask application."""
    print(APP_BANNER)
    host = os.environ.get("PORTSENTINEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PORTSENTINEL_PORT", 5005))
    debug = os.environ.get("PORTSENTINEL_DEBUG", "0").lower() in ("1", "true", "yes")

    app = create_app()

    print(f"[*] PortSentinel Web Dashboard Initializing...")
    print(f"[*] Binding to address : http://{host}:{port}")
    print(f"[*] Environment        : {'Development (Debug ON)' if debug else 'Production (Debug OFF)'}")
    print(f"[*] Open Dashboard URL : http://{host}:{port}\n")

    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\n[!] PortSentinel dashboard server stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
