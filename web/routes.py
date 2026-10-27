"""Page routes and safe report download endpoints for PortSentinel."""

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

page_bp = Blueprint("pages", __name__)


def get_scan_service():
    """Retrieve scan service instance from Flask app."""
    return current_app.config["SCAN_SERVICE"]


@page_bp.route("/")
def index():
    """Redirect root to dashboard."""
    return redirect(url_for("pages.dashboard"))


@page_bp.route("/dashboard")
def dashboard():
    """Render main reconnaissance dashboard."""
    service = get_scan_service()
    metrics = service.get_metrics()
    recent_scans = service.get_recent_scans(limit=6)
    recent_reports = service.list_reports(limit=6)
    active_count = service.get_active_scans_count()

    # Engine status check
    nmap_avail = service.nmap_mgr.is_available()
    _, nmap_ver = service.nmap_mgr.get_version() if nmap_avail else (False, "Unavailable")

    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent_scans=recent_scans,
        recent_reports=recent_reports,
        active_count=active_count,
        nmap_available=nmap_avail,
        nmap_version=nmap_ver,
    )


@page_bp.route("/scans/<scan_id>")
def scan_details(scan_id: str):
    """Render detailed results and exposure page for a scan."""
    service = get_scan_service()
    scan = service.get_scan(scan_id)
    if not scan:
        abort(404, description=f"Scan ID '{scan_id}' not found.")

    return render_template("scan_details.html", scan=scan)


@page_bp.route("/history")
def history():
    """Render historical scan catalog."""
    service = get_scan_service()
    scans = service.list_all_scans(limit=100)
    metrics = service.get_metrics()
    return render_template("history.html", scans=scans, metrics=metrics)


@page_bp.route("/reports")
def reports_page():
    """Render reports list."""
    service = get_scan_service()
    reports = service.list_reports(limit=50)
    return render_template("history.html", scans=service.list_all_scans(limit=100), metrics=service.get_metrics(), active_tab="reports")


@page_bp.route("/reports/<scan_id>/download")
def download_report(scan_id: str):
    """Safely stream text or JSON scan report to user."""
    format_type = request.args.get("format", "txt").lower().strip()
    if format_type not in ("txt", "json"):
        abort(400, description="Invalid report format requested. Supported formats: 'txt', 'json'.")

    service = get_scan_service()
    report_path = service.get_report_path(scan_id, format_type)
    if not report_path or not report_path.is_file():
        abort(404, description=f"Report file for scan '{scan_id}' ({format_type.upper()}) was not found or is not registered.")

    mimetype = "text/plain; charset=utf-8" if format_type == "txt" else "application/json; charset=utf-8"
    return send_file(
        report_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=report_path.name,
    )
