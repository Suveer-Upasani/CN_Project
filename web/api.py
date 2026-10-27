"""RESTful JSON API endpoints for PortSentinel reconnaissance engine."""

from flask import Blueprint, current_app, jsonify, request
from web.security import validate_csrf

api_bp = Blueprint("api", __name__)


def get_scan_service():
    """Retrieve scan service instance from Flask app."""
    return current_app.config["SCAN_SERVICE"]


@api_bp.route("/health", methods=["GET"])
def health_check():
    """System and engine health status endpoint."""
    service = get_scan_service()
    nmap_avail = service.nmap_mgr.is_available()
    _, nmap_ver = service.nmap_mgr.get_version() if nmap_avail else (False, "Nmap not found")

    return jsonify(
        {
            "status": "ok",
            "nmap_available": nmap_avail,
            "nmap_version": nmap_ver,
            "active_scans": service.get_active_scans_count(),
            "max_concurrent_scans": service.max_concurrent_scans,
        }
    )


@api_bp.route("/scans", methods=["POST"])
def submit_scan():
    """Initiate a new individual IP or hostname scan."""
    # CSRF validation
    if not validate_csrf():
        return jsonify({"error": "Security validation failed (CSRF token missing or invalid)."}), 403

    payload = request.get_json(silent=True) or request.form.to_dict()

    target = payload.get("target", "").strip()
    authorized = payload.get("authorized", False)
    # Handle boolean or string checkboxes
    if isinstance(authorized, str):
        authorized = authorized.lower() in ("true", "1", "on", "yes")

    ports = payload.get("ports", None)
    if isinstance(ports, str) and not ports.strip():
        ports = None

    service = get_scan_service()
    success, result, status_code = service.submit_scan(
        target_input=target,
        authorized=bool(authorized),
        port_range=ports,
    )

    return jsonify(result), status_code


@api_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Retrieve full details for a scan."""
    service = get_scan_service()
    scan = service.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan ID '{scan_id}' not found."}), 404
    return jsonify(scan)


@api_bp.route("/scans/<scan_id>/status", methods=["GET"])
def get_scan_status(scan_id: str):
    """Retrieve lightweight status for frontend live polling."""
    service = get_scan_service()
    status_data = service.get_scan_status(scan_id)
    if not status_data:
        return jsonify({"error": f"Scan ID '{scan_id}' not found."}), 404
    return jsonify(status_data)


@api_bp.route("/scans/<scan_id>/results", methods=["GET"])
def get_scan_results(scan_id: str):
    """Retrieve structured scan findings once completed."""
    service = get_scan_service()
    scan = service.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan ID '{scan_id}' not found."}), 404

    if scan.get("status") not in ("completed", "failed"):
        return jsonify(
            {
                "scan_id": scan_id,
                "status": scan.get("status"),
                "message": "Scan is still in progress.",
            }
        ), 202

    return jsonify(
        {
            "scan_id": scan_id,
            "target": scan.get("target"),
            "resolved_ip": scan.get("resolved_ip"),
            "status": scan.get("status"),
            "host_status": scan.get("host_status"),
            "duration": scan.get("duration"),
            "open_ports_count": scan.get("open_ports_count", 0),
            "services_count": scan.get("services_count", 0),
            "nmap_version": scan.get("nmap_version"),
            "result_data": scan.get("result_data"),
            "reports": {
                "txt": scan.get("txt_report_url"),
                "json": scan.get("json_report_url"),
            },
            "error_message": scan.get("error_message"),
        }
    )


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    """List recent scans."""
    service = get_scan_service()
    limit = request.args.get("limit", 20, type=int)
    offset = request.args.get("offset", 0, type=int)
    scans = service.list_all_scans(limit=min(limit, 100), offset=offset)
    return jsonify({"scans": scans})


@api_bp.route("/metrics", methods=["GET"])
def get_metrics():
    """Get aggregated dashboard metrics."""
    service = get_scan_service()
    return jsonify(service.get_metrics())
