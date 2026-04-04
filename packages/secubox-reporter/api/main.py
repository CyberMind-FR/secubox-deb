"""
SecuBox-Deb :: Reporter
CyberMind — https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

System reporting module - generates PDF/HTML reports.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
from typing import Optional
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import asyncio
import json
import subprocess
import uuid
import psutil

app = FastAPI(title="secubox-reporter", version="1.0.0", root_path="/api/v1/reporter")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("reporter")

# Configuration
REPORTS_DIR = Path("/var/lib/secubox/reports")
TEMPLATES_DIR = Path("/usr/share/secubox/reporter/templates")
SCHEDULE_FILE = Path("/etc/secubox/reporter-schedule.json")
CACHE_FILE = Path("/var/cache/secubox/reporter/stats.json")

# Ensure directories exist
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)


class ReportType(str, Enum):
    daily = "daily"
    weekly = "weekly"
    security = "security"
    network = "network"


class ReportFormat(str, Enum):
    pdf = "pdf"
    html = "html"


class ReportStatus(str, Enum):
    pending = "pending"
    generating = "generating"
    completed = "completed"
    failed = "failed"


class GenerateReportRequest(BaseModel):
    report_type: ReportType
    format: ReportFormat = ReportFormat.pdf
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    sections: Optional[list[str]] = None
    title: Optional[str] = None


class ScheduleRequest(BaseModel):
    cron: str
    report_type: ReportType
    format: ReportFormat = ReportFormat.pdf
    enabled: bool = True


class Report(BaseModel):
    id: str
    report_type: ReportType
    format: ReportFormat
    status: ReportStatus
    created_at: str
    completed_at: Optional[str] = None
    title: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    error: Optional[str] = None


# In-memory report tracking (would be persisted in production)
_reports: dict[str, Report] = {}
_cache: dict = {}


def _load_reports_index() -> dict:
    """Load reports index from disk."""
    index_file = REPORTS_DIR / "index.json"
    if index_file.exists():
        try:
            data = json.loads(index_file.read_text())
            return {r["id"]: Report(**r) for r in data}
        except Exception as e:
            log.error(f"Failed to load reports index: {e}")
    return {}


def _save_reports_index():
    """Save reports index to disk."""
    index_file = REPORTS_DIR / "index.json"
    try:
        data = [r.model_dump() for r in _reports.values()]
        index_file.write_text(json.dumps(data, indent=2, default=str))
    except Exception as e:
        log.error(f"Failed to save reports index: {e}")


# Load reports on startup
_reports = _load_reports_index()


def _get_default_sections(report_type: ReportType) -> list[str]:
    """Get default sections for a report type."""
    sections_map = {
        ReportType.daily: ["system_health", "services_status", "alerts_summary", "network_stats"],
        ReportType.weekly: ["system_health", "services_status", "alerts_summary", "network_stats",
                           "security_events", "bandwidth_usage", "top_clients"],
        ReportType.security: ["security_events", "crowdsec_decisions", "blocked_ips",
                             "auth_failures", "waf_alerts", "vulnerability_scan"],
        ReportType.network: ["interface_stats", "bandwidth_usage", "top_protocols",
                            "top_clients", "dns_queries", "connection_summary"],
    }
    return sections_map.get(report_type, ["system_health"])


def _collect_system_stats() -> dict:
    """Collect current system statistics for reports."""
    import psutil

    # CPU info
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_count = psutil.cpu_count()
    load_avg = list(psutil.getloadavg())

    # Memory info
    mem = psutil.virtual_memory()

    # Disk info
    disk = psutil.disk_usage("/")

    # Network info
    net_io = psutil.net_io_counters()

    # Uptime
    uptime_seconds = int(float(Path("/proc/uptime").read_text().split()[0]))

    return {
        "timestamp": datetime.now().isoformat(),
        "cpu": {
            "percent": cpu_percent,
            "count": cpu_count,
            "load_avg": load_avg,
        },
        "memory": {
            "total_mb": mem.total // 1024 // 1024,
            "used_mb": mem.used // 1024 // 1024,
            "available_mb": mem.available // 1024 // 1024,
            "percent": mem.percent,
        },
        "disk": {
            "total_gb": disk.total // 1024**3,
            "used_gb": disk.used // 1024**3,
            "free_gb": disk.free // 1024**3,
            "percent": disk.percent,
        },
        "network": {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
        },
        "uptime_seconds": uptime_seconds,
    }


def _get_services_status() -> list[dict]:
    """Get status of SecuBox services."""
    services = []
    service_names = [
        "secubox-hub", "secubox-crowdsec", "secubox-wireguard",
        "secubox-dpi", "secubox-nac", "secubox-qos", "secubox-system",
    ]

    for svc in service_names:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            services.append({
                "name": svc,
                "active": status == "active",
                "status": status,
            })
        except Exception:
            services.append({"name": svc, "active": False, "status": "unknown"})

    return services


def _generate_html_report(report: Report, stats: dict, services: list) -> str:
    """Generate HTML report content."""
    sections_html = ""

    # System Health section
    sections_html += f"""
    <section class="report-section">
        <h2>System Health</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['cpu']['percent']:.1f}%</div>
                <div class="stat-label">CPU Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['memory']['percent']:.1f}%</div>
                <div class="stat-label">Memory Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['disk']['percent']:.1f}%</div>
                <div class="stat-label">Disk Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['uptime_seconds'] // 86400}d</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>
    </section>
    """

    # Services Status section
    services_rows = "".join([
        f"<tr><td>{s['name']}</td><td class=\"{'status-active' if s['active'] else 'status-inactive'}\">{s['status']}</td></tr>"
        for s in services
    ])
    sections_html += f"""
    <section class="report-section">
        <h2>Services Status</h2>
        <table class="data-table">
            <thead><tr><th>Service</th><th>Status</th></tr></thead>
            <tbody>{services_rows}</tbody>
        </table>
    </section>
    """

    # Network Stats section
    sections_html += f"""
    <section class="report-section">
        <h2>Network Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{_format_bytes(stats['network']['bytes_recv'])}</div>
                <div class="stat-label">Data Received</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{_format_bytes(stats['network']['bytes_sent'])}</div>
                <div class="stat-label">Data Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['network']['packets_recv']:,}</div>
                <div class="stat-label">Packets Received</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['network']['packets_sent']:,}</div>
                <div class="stat-label">Packets Sent</div>
            </div>
        </div>
    </section>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>
        :root {{
            --p31-peak: #00dd44;
            --p31-hot: #00ff55;
            --p31-mid: #009933;
            --p31-dim: #006622;
            --p31-ghost: #003311;
            --p31-decay: #ffb347;
            --tube-light: #e8f5e9;
            --tube-pale: #c8e6c9;
            --tube-soft: #a5d6a7;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Courier Prime', 'Courier New', monospace;
            background: var(--tube-light);
            color: #1a1a2e;
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }}
        .report-header {{
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--p31-peak);
        }}
        .report-header h1 {{
            color: var(--p31-mid);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        .report-meta {{
            color: var(--p31-dim);
            font-size: 0.9rem;
        }}
        .report-section {{
            background: var(--tube-pale);
            border: 1px solid var(--tube-soft);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .report-section h2 {{
            color: var(--p31-decay);
            font-size: 1.2rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--tube-soft);
            padding-bottom: 0.5rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }}
        .stat-card {{
            background: var(--tube-light);
            border: 1px solid var(--tube-soft);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .stat-value {{
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--p31-peak);
        }}
        .stat-label {{
            font-size: 0.75rem;
            color: var(--p31-dim);
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .data-table th, .data-table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--tube-soft);
        }}
        .data-table th {{
            color: var(--p31-dim);
            font-size: 0.8rem;
            text-transform: uppercase;
        }}
        .status-active {{ color: var(--p31-peak); font-weight: bold; }}
        .status-inactive {{ color: #ff4466; }}
        .report-footer {{
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--tube-soft);
            color: var(--p31-dim);
            font-size: 0.8rem;
        }}
        @media print {{
            body {{ padding: 1rem; }}
            .report-section {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <header class="report-header">
        <h1>{report.title}</h1>
        <div class="report-meta">
            <p>Report Type: {report.report_type.value.title()} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>SecuBox System Report</p>
        </div>
    </header>

    {sections_html}

    <footer class="report-footer">
        <p>SecuBox Reporter - CyberMind</p>
        <p>Generated at {datetime.now().isoformat()}</p>
    </footer>
</body>
</html>"""

    return html


def _format_bytes(b: int) -> str:
    """Format bytes to human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    elif b < 1024**3:
        return f"{b/1024**2:.1f} MB"
    else:
        return f"{b/1024**3:.2f} GB"


async def _generate_report_task(report_id: str):
    """Background task to generate a report."""
    if report_id not in _reports:
        return

    report = _reports[report_id]
    report.status = ReportStatus.generating
    _save_reports_index()

    try:
        # Collect data
        stats = _collect_system_stats()
        services = _get_services_status()

        # Generate HTML content
        html_content = _generate_html_report(report, stats, services)

        # Save HTML file
        html_path = REPORTS_DIR / f"{report_id}.html"
        html_path.write_text(html_content)

        if report.format == ReportFormat.pdf:
            # Convert HTML to PDF using weasyprint or wkhtmltopdf
            pdf_path = REPORTS_DIR / f"{report_id}.pdf"

            # Try weasyprint first
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(str(pdf_path))
                report.file_path = str(pdf_path)
            except ImportError:
                # Fallback to wkhtmltopdf
                result = subprocess.run(
                    ["wkhtmltopdf", "--quiet", str(html_path), str(pdf_path)],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0:
                    report.file_path = str(pdf_path)
                else:
                    # If PDF generation fails, keep HTML
                    report.file_path = str(html_path)
                    report.format = ReportFormat.html
                    log.warning(f"PDF generation failed, using HTML: {result.stderr}")
        else:
            report.file_path = str(html_path)

        # Update report status
        report.status = ReportStatus.completed
        report.completed_at = datetime.now().isoformat()

        if report.file_path and Path(report.file_path).exists():
            report.file_size = Path(report.file_path).stat().st_size

        log.info(f"Report generated: {report_id} ({report.format.value})")

    except Exception as e:
        log.error(f"Report generation failed: {report_id} - {e}")
        report.status = ReportStatus.failed
        report.error = str(e)

    _save_reports_index()


# ═══════════════════════════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════════════════════════

@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get module status."""
    total_reports = len(_reports)
    completed = sum(1 for r in _reports.values() if r.status == ReportStatus.completed)
    pending = sum(1 for r in _reports.values() if r.status in (ReportStatus.pending, ReportStatus.generating))

    # Get disk usage for reports
    reports_size = sum(
        Path(r.file_path).stat().st_size
        for r in _reports.values()
        if r.file_path and Path(r.file_path).exists()
    )

    return {
        "module": "reporter",
        "version": "1.0.0",
        "status": "running",
        "total_reports": total_reports,
        "completed_reports": completed,
        "pending_reports": pending,
        "reports_size_bytes": reports_size,
        "reports_dir": str(REPORTS_DIR),
    }


@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    return {"status": "ok", "module": "reporter", "version": "1.0.0"}


@router.get("/reports")
async def list_reports(
    limit: int = 50,
    offset: int = 0,
    report_type: Optional[ReportType] = None,
    user=Depends(require_jwt)
):
    """List generated reports."""
    reports = list(_reports.values())

    # Filter by type if specified
    if report_type:
        reports = [r for r in reports if r.report_type == report_type]

    # Sort by creation date (newest first)
    reports.sort(key=lambda r: r.created_at, reverse=True)

    # Paginate
    total = len(reports)
    reports = reports[offset:offset + limit]

    return {
        "reports": [r.model_dump() for r in reports],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/reports/generate")
async def generate_report(
    req: GenerateReportRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_jwt)
):
    """Generate a new report."""
    report_id = str(uuid.uuid4())[:8]

    # Default title based on type
    if not req.title:
        now = datetime.now()
        title_map = {
            ReportType.daily: f"Daily Report - {now.strftime('%Y-%m-%d')}",
            ReportType.weekly: f"Weekly Report - Week {now.isocalendar()[1]}, {now.year}",
            ReportType.security: f"Security Report - {now.strftime('%Y-%m-%d %H:%M')}",
            ReportType.network: f"Network Report - {now.strftime('%Y-%m-%d %H:%M')}",
        }
        title = title_map.get(req.report_type, f"Report {report_id}")
    else:
        title = req.title

    report = Report(
        id=report_id,
        report_type=req.report_type,
        format=req.format,
        status=ReportStatus.pending,
        created_at=datetime.now().isoformat(),
        title=title,
    )

    _reports[report_id] = report
    _save_reports_index()

    # Start background generation
    background_tasks.add_task(_generate_report_task, report_id)

    log.info(f"Report generation started: {report_id} ({req.report_type.value})")

    return {
        "success": True,
        "report_id": report_id,
        "message": f"Report generation started",
    }


@router.get("/reports/{report_id}")
async def get_report(report_id: str, user=Depends(require_jwt)):
    """Get report details or download report file."""
    if report_id not in _reports:
        raise HTTPException(404, "Report not found")

    report = _reports[report_id]

    # If report is ready and has a file, return file info
    if report.status == ReportStatus.completed and report.file_path:
        file_path = Path(report.file_path)
        if file_path.exists():
            return {
                "report": report.model_dump(),
                "download_url": f"/api/v1/reporter/reports/{report_id}/download",
            }

    return {"report": report.model_dump()}


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str, user=Depends(require_jwt)):
    """Download a report file."""
    if report_id not in _reports:
        raise HTTPException(404, "Report not found")

    report = _reports[report_id]

    if report.status != ReportStatus.completed:
        raise HTTPException(400, f"Report is not ready (status: {report.status.value})")

    if not report.file_path or not Path(report.file_path).exists():
        raise HTTPException(404, "Report file not found")

    media_type = "application/pdf" if report.format == ReportFormat.pdf else "text/html"
    filename = f"{report.title.replace(' ', '_')}.{report.format.value}"

    return FileResponse(
        report.file_path,
        media_type=media_type,
        filename=filename,
    )


@router.delete("/reports/{report_id}")
async def delete_report(report_id: str, user=Depends(require_jwt)):
    """Delete a report."""
    if report_id not in _reports:
        raise HTTPException(404, "Report not found")

    report = _reports[report_id]

    # Delete file if exists
    if report.file_path and Path(report.file_path).exists():
        Path(report.file_path).unlink()

    # Also delete HTML version if PDF was generated
    html_path = REPORTS_DIR / f"{report_id}.html"
    if html_path.exists():
        html_path.unlink()

    del _reports[report_id]
    _save_reports_index()

    log.info(f"Report deleted: {report_id}")

    return {"success": True, "message": "Report deleted"}


@router.get("/templates")
async def list_templates(user=Depends(require_jwt)):
    """List available report templates."""
    templates = [
        {
            "id": "daily",
            "name": "Daily Report",
            "description": "Daily system health and activity summary",
            "sections": _get_default_sections(ReportType.daily),
        },
        {
            "id": "weekly",
            "name": "Weekly Report",
            "description": "Comprehensive weekly analysis with trends",
            "sections": _get_default_sections(ReportType.weekly),
        },
        {
            "id": "security",
            "name": "Security Report",
            "description": "Security events, threats, and incidents",
            "sections": _get_default_sections(ReportType.security),
        },
        {
            "id": "network",
            "name": "Network Report",
            "description": "Network traffic analysis and statistics",
            "sections": _get_default_sections(ReportType.network),
        },
    ]

    return {"templates": templates}


@router.get("/schedule")
async def get_schedule(user=Depends(require_jwt)):
    """Get report generation schedule."""
    if SCHEDULE_FILE.exists():
        try:
            return json.loads(SCHEDULE_FILE.read_text())
        except Exception:
            pass

    # Default schedule
    return {
        "enabled": False,
        "schedules": [
            {
                "id": "daily",
                "cron": "0 6 * * *",
                "report_type": "daily",
                "format": "pdf",
                "enabled": False,
                "description": "Daily report at 6:00 AM",
            },
            {
                "id": "weekly",
                "cron": "0 7 * * 1",
                "report_type": "weekly",
                "format": "pdf",
                "enabled": False,
                "description": "Weekly report on Monday at 7:00 AM",
            },
        ],
    }


@router.post("/schedule")
async def update_schedule(req: ScheduleRequest, user=Depends(require_jwt)):
    """Update report schedule."""
    schedule = await get_schedule(user)

    # Update or add schedule entry
    updated = False
    for s in schedule["schedules"]:
        if s["report_type"] == req.report_type.value:
            s["cron"] = req.cron
            s["format"] = req.format.value
            s["enabled"] = req.enabled
            updated = True
            break

    if not updated:
        schedule["schedules"].append({
            "id": req.report_type.value,
            "cron": req.cron,
            "report_type": req.report_type.value,
            "format": req.format.value,
            "enabled": req.enabled,
        })

    # Check if any schedule is enabled
    schedule["enabled"] = any(s["enabled"] for s in schedule["schedules"])

    # Save schedule
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCHEDULE_FILE.write_text(json.dumps(schedule, indent=2))

    log.info(f"Schedule updated: {req.report_type.value} = {req.cron} (enabled: {req.enabled})")

    return {"success": True, "schedule": schedule}


@router.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get current system stats for reports."""
    stats = _collect_system_stats()
    services = _get_services_status()

    # Count active services
    active_services = sum(1 for s in services if s["active"])
    total_services = len(services)

    return {
        "system": stats,
        "services": {
            "list": services,
            "active": active_services,
            "total": total_services,
        },
        "reports_summary": {
            "total": len(_reports),
            "completed": sum(1 for r in _reports.values() if r.status == ReportStatus.completed),
            "pending": sum(1 for r in _reports.values() if r.status == ReportStatus.pending),
            "failed": sum(1 for r in _reports.values() if r.status == ReportStatus.failed),
        },
    }


# Background cache refresh task
async def refresh_cache():
    """Background task to update stats cache."""
    global _cache
    while True:
        try:
            _cache = {
                "stats": _collect_system_stats(),
                "services": _get_services_status(),
                "updated_at": datetime.now().isoformat(),
            }
            CACHE_FILE.write_text(json.dumps(_cache, indent=2))
        except Exception as e:
            log.error(f"Cache refresh failed: {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Startup tasks."""
    asyncio.create_task(refresh_cache())
    log.info("SecuBox Reporter started")


app.include_router(router)
