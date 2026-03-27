"""SecuBox Config Advisor - Security Configuration Auditing
Checks system configuration against ANSSI CSPN guidelines and security best practices.

Features:
- ANSSI CSPN compliance checks
- CIS benchmark validation
- SSH/firewall/service hardening checks
- Real-time configuration monitoring
- Remediation recommendations
- Compliance scoring
"""
import os
import re
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/config-advisor.toml")
DATA_DIR = Path("/var/lib/secubox/config-advisor")
RESULTS_FILE = DATA_DIR / "results.json"
HISTORY_FILE = DATA_DIR / "history.jsonl"

app = FastAPI(title="SecuBox Config Advisor", version="1.0.0")
logger = logging.getLogger("secubox.config-advisor")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"
    ERROR = "error"


class Category(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    SERVICES = "services"
    FILESYSTEM = "filesystem"
    KERNEL = "kernel"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    ACCESS_CONTROL = "access_control"


class CheckResult(BaseModel):
    check_id: str
    name: str
    category: Category
    severity: Severity
    status: CheckStatus
    description: str
    finding: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None  # ANSSI/CIS reference


class AuditReport(BaseModel):
    id: str
    timestamp: str
    duration_ms: int
    total_checks: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    score: float  # 0-100
    results: List[CheckResult]


class ConfigAdvisor:
    """Security configuration auditor."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.results_file = data_dir / "results.json"
        self.history_file = data_dir / "history.jsonl"
        self._ensure_dirs()
        self._last_report: Optional[AuditReport] = None
        self._load_last_report()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_last_report(self):
        if self.results_file.exists():
            try:
                data = json.loads(self.results_file.read_text())
                self._last_report = AuditReport(**data)
            except Exception:
                pass

    def _save_report(self, report: AuditReport):
        self.results_file.write_text(json.dumps(report.model_dump(), indent=2))
        with open(self.history_file, "a") as f:
            f.write(json.dumps({
                "id": report.id,
                "timestamp": report.timestamp,
                "score": report.score,
                "passed": report.passed,
                "failed": report.failed
            }) + "\n")
        self._last_report = report

    def _run_cmd(self, cmd: List[str], timeout: int = 10) -> tuple[int, str]:
        """Run a command and return exit code and output."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout + result.stderr
        except Exception as e:
            return -1, str(e)

    def _file_exists(self, path: str) -> bool:
        return Path(path).exists()

    def _file_contains(self, path: str, pattern: str) -> bool:
        try:
            content = Path(path).read_text()
            return bool(re.search(pattern, content))
        except Exception:
            return False

    def _get_file_perms(self, path: str) -> Optional[int]:
        try:
            return Path(path).stat().st_mode & 0o777
        except Exception:
            return None

    # ========================================================================
    # ANSSI CSPN Checks
    # ========================================================================

    def check_ssh_root_login(self) -> CheckResult:
        """ANSSI R28: Disable SSH root login."""
        sshd_config = "/etc/ssh/sshd_config"

        if not self._file_exists(sshd_config):
            return CheckResult(
                check_id="ANSSI-R28",
                name="SSH root login disabled",
                category=Category.AUTHENTICATION,
                severity=Severity.CRITICAL,
                status=CheckStatus.SKIP,
                description="SSH configuration not found",
                reference="ANSSI-BP-028"
            )

        if self._file_contains(sshd_config, r"^PermitRootLogin\s+(no|prohibit-password)"):
            return CheckResult(
                check_id="ANSSI-R28",
                name="SSH root login disabled",
                category=Category.AUTHENTICATION,
                severity=Severity.CRITICAL,
                status=CheckStatus.PASS,
                description="Root login via SSH is properly disabled",
                reference="ANSSI-BP-028"
            )
        else:
            return CheckResult(
                check_id="ANSSI-R28",
                name="SSH root login disabled",
                category=Category.AUTHENTICATION,
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                description="Root login via SSH should be disabled",
                finding="PermitRootLogin is not set to 'no' or 'prohibit-password'",
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                reference="ANSSI-BP-028"
            )

    def check_ssh_password_auth(self) -> CheckResult:
        """ANSSI R29: Use SSH key authentication."""
        sshd_config = "/etc/ssh/sshd_config"

        if self._file_contains(sshd_config, r"^PasswordAuthentication\s+no"):
            return CheckResult(
                check_id="ANSSI-R29",
                name="SSH password authentication disabled",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                description="Password authentication is disabled, key-based auth enforced",
                reference="ANSSI-BP-028"
            )
        else:
            return CheckResult(
                check_id="ANSSI-R29",
                name="SSH password authentication disabled",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="SSH password authentication should be disabled",
                finding="PasswordAuthentication is not set to 'no'",
                remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
                reference="ANSSI-BP-028"
            )

    def check_ssh_protocol(self) -> CheckResult:
        """SSH Protocol 2 only."""
        sshd_config = "/etc/ssh/sshd_config"

        # SSH2 is default in modern OpenSSH, check for explicit Protocol 1
        if self._file_contains(sshd_config, r"^Protocol\s+1"):
            return CheckResult(
                check_id="SSH-01",
                name="SSH Protocol 2 only",
                category=Category.AUTHENTICATION,
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                description="SSH Protocol 1 is insecure",
                finding="Protocol 1 is explicitly enabled",
                remediation="Remove 'Protocol 1' or set 'Protocol 2'",
                reference="CIS 5.2.4"
            )
        else:
            return CheckResult(
                check_id="SSH-01",
                name="SSH Protocol 2 only",
                category=Category.AUTHENTICATION,
                severity=Severity.CRITICAL,
                status=CheckStatus.PASS,
                description="SSH is using Protocol 2 (default)",
                reference="CIS 5.2.4"
            )

    def check_firewall_enabled(self) -> CheckResult:
        """ANSSI R7: Firewall enabled."""
        # Check for nftables or iptables
        code, output = self._run_cmd(["nft", "list", "ruleset"])
        if code == 0 and len(output.strip()) > 50:
            return CheckResult(
                check_id="ANSSI-R7",
                name="Firewall enabled",
                category=Category.NETWORK,
                severity=Severity.CRITICAL,
                status=CheckStatus.PASS,
                description="nftables firewall is configured",
                reference="ANSSI-BP-028"
            )

        code, output = self._run_cmd(["iptables", "-L", "-n"])
        if code == 0 and "Chain" in output:
            # Check if there are actual rules beyond default
            if "DROP" in output or "REJECT" in output:
                return CheckResult(
                    check_id="ANSSI-R7",
                    name="Firewall enabled",
                    category=Category.NETWORK,
                    severity=Severity.CRITICAL,
                    status=CheckStatus.PASS,
                    description="iptables firewall has active rules",
                    reference="ANSSI-BP-028"
                )

        return CheckResult(
            check_id="ANSSI-R7",
            name="Firewall enabled",
            category=Category.NETWORK,
            severity=Severity.CRITICAL,
            status=CheckStatus.FAIL,
            description="No active firewall detected",
            finding="Neither nftables nor iptables has active filtering rules",
            remediation="Configure nftables or iptables with appropriate rules",
            reference="ANSSI-BP-028"
        )

    def check_password_policy(self) -> CheckResult:
        """ANSSI R30: Strong password policy."""
        pam_pwquality = "/etc/security/pwquality.conf"

        checks = []
        if self._file_exists(pam_pwquality):
            if self._file_contains(pam_pwquality, r"minlen\s*=\s*(\d+)"):
                match = re.search(r"minlen\s*=\s*(\d+)", Path(pam_pwquality).read_text())
                if match and int(match.group(1)) >= 12:
                    checks.append(True)

        if checks and all(checks):
            return CheckResult(
                check_id="ANSSI-R30",
                name="Strong password policy",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                description="Password policy meets minimum requirements",
                reference="ANSSI-BP-028"
            )
        else:
            return CheckResult(
                check_id="ANSSI-R30",
                name="Strong password policy",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                status=CheckStatus.WARNING,
                description="Password policy should be strengthened",
                finding="Password complexity requirements may not be sufficient",
                remediation="Configure /etc/security/pwquality.conf with minlen=12",
                reference="ANSSI-BP-028"
            )

    def check_tmp_noexec(self) -> CheckResult:
        """ANSSI R12: /tmp mounted with noexec."""
        code, output = self._run_cmd(["mount"])

        if "/tmp" in output:
            if "noexec" in output.split("/tmp")[1].split("\n")[0]:
                return CheckResult(
                    check_id="ANSSI-R12",
                    name="/tmp mounted noexec",
                    category=Category.FILESYSTEM,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.PASS,
                    description="/tmp is mounted with noexec option",
                    reference="ANSSI-BP-028"
                )

        return CheckResult(
            check_id="ANSSI-R12",
            name="/tmp mounted noexec",
            category=Category.FILESYSTEM,
            severity=Severity.MEDIUM,
            status=CheckStatus.WARNING,
            description="/tmp should be mounted with noexec",
            finding="/tmp is not mounted with noexec option",
            remediation="Add 'noexec' to /tmp mount options in /etc/fstab",
            reference="ANSSI-BP-028"
        )

    def check_kernel_aslr(self) -> CheckResult:
        """ANSSI R18: ASLR enabled."""
        try:
            aslr = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
            if aslr == "2":
                return CheckResult(
                    check_id="ANSSI-R18",
                    name="Kernel ASLR enabled",
                    category=Category.KERNEL,
                    severity=Severity.HIGH,
                    status=CheckStatus.PASS,
                    description="ASLR is fully enabled (randomize_va_space=2)",
                    reference="ANSSI-BP-028"
                )
            else:
                return CheckResult(
                    check_id="ANSSI-R18",
                    name="Kernel ASLR enabled",
                    category=Category.KERNEL,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description="ASLR should be fully enabled",
                    finding=f"randomize_va_space={aslr}",
                    remediation="echo 2 > /proc/sys/kernel/randomize_va_space",
                    reference="ANSSI-BP-028"
                )
        except Exception:
            return CheckResult(
                check_id="ANSSI-R18",
                name="Kernel ASLR enabled",
                category=Category.KERNEL,
                severity=Severity.HIGH,
                status=CheckStatus.ERROR,
                description="Could not check ASLR status",
                reference="ANSSI-BP-028"
            )

    def check_audit_logging(self) -> CheckResult:
        """ANSSI R67: Audit logging enabled."""
        code, output = self._run_cmd(["systemctl", "is-active", "auditd"])

        if "active" in output:
            return CheckResult(
                check_id="ANSSI-R67",
                name="Audit logging enabled",
                category=Category.LOGGING,
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                description="auditd service is running",
                reference="ANSSI-BP-028"
            )
        else:
            return CheckResult(
                check_id="ANSSI-R67",
                name="Audit logging enabled",
                category=Category.LOGGING,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="Audit daemon should be running",
                finding="auditd is not active",
                remediation="apt install auditd && systemctl enable auditd",
                reference="ANSSI-BP-028"
            )

    def check_unnecessary_services(self) -> CheckResult:
        """Check for unnecessary services running."""
        dangerous_services = ["telnet", "rsh", "rlogin", "rexec", "xinetd", "vsftpd"]
        running = []

        for svc in dangerous_services:
            code, output = self._run_cmd(["systemctl", "is-active", svc])
            if "active" in output:
                running.append(svc)

        if running:
            return CheckResult(
                check_id="SVC-01",
                name="No unnecessary services",
                category=Category.SERVICES,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="Dangerous legacy services are running",
                finding=f"Active services: {', '.join(running)}",
                remediation=f"Disable services: systemctl disable --now {' '.join(running)}",
                reference="CIS 2.2"
            )
        else:
            return CheckResult(
                check_id="SVC-01",
                name="No unnecessary services",
                category=Category.SERVICES,
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                description="No dangerous legacy services detected",
                reference="CIS 2.2"
            )

    def check_permissions_shadow(self) -> CheckResult:
        """Check /etc/shadow permissions."""
        perms = self._get_file_perms("/etc/shadow")

        if perms is not None and perms <= 0o640:
            return CheckResult(
                check_id="FS-01",
                name="/etc/shadow permissions",
                category=Category.FILESYSTEM,
                severity=Severity.CRITICAL,
                status=CheckStatus.PASS,
                description="/etc/shadow has correct permissions",
                reference="CIS 6.1.3"
            )
        else:
            return CheckResult(
                check_id="FS-01",
                name="/etc/shadow permissions",
                category=Category.FILESYSTEM,
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                description="/etc/shadow should have restrictive permissions",
                finding=f"Permissions: {oct(perms) if perms else 'unknown'}",
                remediation="chmod 640 /etc/shadow",
                reference="CIS 6.1.3"
            )

    def check_cron_permissions(self) -> CheckResult:
        """Check cron directory permissions."""
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
        issues = []

        for cron_dir in cron_dirs:
            perms = self._get_file_perms(cron_dir)
            if perms is not None and perms > 0o700:
                issues.append(f"{cron_dir}: {oct(perms)}")

        if issues:
            return CheckResult(
                check_id="FS-02",
                name="Cron directory permissions",
                category=Category.FILESYSTEM,
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                description="Cron directories should be restricted",
                finding="; ".join(issues),
                remediation="chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly",
                reference="CIS 5.1.3"
            )
        else:
            return CheckResult(
                check_id="FS-02",
                name="Cron directory permissions",
                category=Category.FILESYSTEM,
                severity=Severity.MEDIUM,
                status=CheckStatus.PASS,
                description="Cron directories have correct permissions",
                reference="CIS 5.1.3"
            )

    def check_sudo_nopasswd(self) -> CheckResult:
        """Check for NOPASSWD in sudoers."""
        code, output = self._run_cmd(["grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/"])

        if code == 0 and output.strip():
            return CheckResult(
                check_id="SUDO-01",
                name="No NOPASSWD in sudoers",
                category=Category.ACCESS_CONTROL,
                severity=Severity.HIGH,
                status=CheckStatus.WARNING,
                description="NOPASSWD entries found in sudoers",
                finding=output.strip()[:200],
                remediation="Remove NOPASSWD entries from sudoers files",
                reference="CIS 5.3"
            )
        else:
            return CheckResult(
                check_id="SUDO-01",
                name="No NOPASSWD in sudoers",
                category=Category.ACCESS_CONTROL,
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                description="No NOPASSWD entries in sudoers",
                reference="CIS 5.3"
            )

    def check_world_writable_files(self) -> CheckResult:
        """Check for world-writable files in critical directories."""
        code, output = self._run_cmd([
            "find", "/etc", "-type", "f", "-perm", "-002",
            "-not", "-path", "/etc/mtab", "-print"
        ], timeout=30)

        files = [f for f in output.strip().split("\n") if f]

        if files:
            return CheckResult(
                check_id="FS-03",
                name="No world-writable config files",
                category=Category.FILESYSTEM,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="World-writable files found in /etc",
                finding=f"Found {len(files)} files: {', '.join(files[:5])}",
                remediation="chmod o-w <files>",
                reference="CIS 6.1.10"
            )
        else:
            return CheckResult(
                check_id="FS-03",
                name="No world-writable config files",
                category=Category.FILESYSTEM,
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                description="No world-writable files in /etc",
                reference="CIS 6.1.10"
            )

    def check_sysctl_hardening(self) -> CheckResult:
        """Check kernel hardening sysctls."""
        checks_passed = 0
        checks_failed = []

        sysctl_checks = {
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.all.accept_source_route": "0",
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "kernel.randomize_va_space": "2",
        }

        for key, expected in sysctl_checks.items():
            try:
                path = f"/proc/sys/{key.replace('.', '/')}"
                actual = Path(path).read_text().strip()
                if actual == expected:
                    checks_passed += 1
                else:
                    checks_failed.append(f"{key}={actual} (expected {expected})")
            except Exception:
                checks_failed.append(f"{key}=unknown")

        if checks_failed:
            return CheckResult(
                check_id="KERNEL-01",
                name="Kernel hardening sysctls",
                category=Category.KERNEL,
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING if len(checks_failed) < 3 else CheckStatus.FAIL,
                description="Some kernel hardening sysctls not configured",
                finding="; ".join(checks_failed),
                remediation="Add recommended values to /etc/sysctl.conf",
                reference="CIS 3.2"
            )
        else:
            return CheckResult(
                check_id="KERNEL-01",
                name="Kernel hardening sysctls",
                category=Category.KERNEL,
                severity=Severity.MEDIUM,
                status=CheckStatus.PASS,
                description="Kernel hardening sysctls are properly configured",
                reference="CIS 3.2"
            )

    # Auto-remediation methods
    def apply_fix(self, check_id: str) -> Dict[str, Any]:
        """Apply automatic fix for a check."""
        fixes = {
            "ANSSI-R28": self._fix_ssh_root_login,
            "ANSSI-R29": self._fix_ssh_password_auth,
            "ANSSI-R18": self._fix_kernel_aslr,
            "FS-01": self._fix_shadow_permissions,
            "FS-02": self._fix_cron_permissions,
            "KERNEL-01": self._fix_sysctl_hardening,
        }

        if check_id not in fixes:
            return {"success": False, "error": f"No auto-fix available for {check_id}"}

        try:
            result = fixes[check_id]()
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _fix_ssh_root_login(self) -> Dict[str, Any]:
        """Fix SSH root login setting."""
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return {"success": False, "error": "sshd_config not found"}

        content = sshd_config.read_text()
        if re.search(r'^PermitRootLogin', content, re.MULTILINE):
            content = re.sub(r'^PermitRootLogin\s+.*$', 'PermitRootLogin no', content, flags=re.MULTILINE)
        else:
            content += "\nPermitRootLogin no\n"

        sshd_config.write_text(content)
        self._run_cmd(["systemctl", "reload", "sshd"])
        return {"success": True, "action": "Set PermitRootLogin no"}

    def _fix_ssh_password_auth(self) -> Dict[str, Any]:
        """Fix SSH password auth setting."""
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return {"success": False, "error": "sshd_config not found"}

        content = sshd_config.read_text()
        if re.search(r'^PasswordAuthentication', content, re.MULTILINE):
            content = re.sub(r'^PasswordAuthentication\s+.*$', 'PasswordAuthentication no', content, flags=re.MULTILINE)
        else:
            content += "\nPasswordAuthentication no\n"

        sshd_config.write_text(content)
        self._run_cmd(["systemctl", "reload", "sshd"])
        return {"success": True, "action": "Set PasswordAuthentication no"}

    def _fix_kernel_aslr(self) -> Dict[str, Any]:
        """Enable ASLR."""
        Path("/proc/sys/kernel/randomize_va_space").write_text("2")

        # Make persistent
        sysctl_conf = Path("/etc/sysctl.d/99-secubox-aslr.conf")
        sysctl_conf.write_text("kernel.randomize_va_space = 2\n")

        return {"success": True, "action": "Enabled ASLR (persistent)"}

    def _fix_shadow_permissions(self) -> Dict[str, Any]:
        """Fix /etc/shadow permissions."""
        self._run_cmd(["chmod", "640", "/etc/shadow"])
        self._run_cmd(["chown", "root:shadow", "/etc/shadow"])
        return {"success": True, "action": "Set /etc/shadow to 640"}

    def _fix_cron_permissions(self) -> Dict[str, Any]:
        """Fix cron directory permissions."""
        for d in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]:
            if Path(d).exists():
                self._run_cmd(["chmod", "700", d])
        return {"success": True, "action": "Set cron directories to 700"}

    def _fix_sysctl_hardening(self) -> Dict[str, Any]:
        """Apply kernel hardening sysctls."""
        sysctl_conf = Path("/etc/sysctl.d/99-secubox-hardening.conf")
        content = """# SecuBox kernel hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.randomize_va_space = 2
"""
        sysctl_conf.write_text(content)
        self._run_cmd(["sysctl", "-p", str(sysctl_conf)])
        return {"success": True, "action": "Applied kernel hardening sysctls"}

    def run_audit(self) -> AuditReport:
        """Run full security audit."""
        import time
        start = time.time()

        checks = [
            self.check_ssh_root_login,
            self.check_ssh_password_auth,
            self.check_ssh_protocol,
            self.check_firewall_enabled,
            self.check_password_policy,
            self.check_tmp_noexec,
            self.check_kernel_aslr,
            self.check_audit_logging,
            self.check_unnecessary_services,
            self.check_permissions_shadow,
            self.check_cron_permissions,
            self.check_sudo_nopasswd,
            self.check_world_writable_files,
            self.check_sysctl_hardening,
        ]

        results = []
        for check_fn in checks:
            try:
                result = check_fn()
                results.append(result)
            except Exception as e:
                logger.warning(f"Check {check_fn.__name__} failed: {e}")

        duration = int((time.time() - start) * 1000)

        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        warnings = sum(1 for r in results if r.status == CheckStatus.WARNING)
        skipped = sum(1 for r in results if r.status in [CheckStatus.SKIP, CheckStatus.ERROR])

        # Calculate score (passed / total non-skipped * 100)
        total_scored = passed + failed + warnings
        score = (passed / total_scored * 100) if total_scored > 0 else 0

        report = AuditReport(
            id=f"audit-{int(time.time())}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            duration_ms=duration,
            total_checks=len(results),
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            score=round(score, 1),
            results=results
        )

        self._save_report(report)
        return report

    def get_stats(self) -> Dict[str, Any]:
        """Get advisor statistics."""
        if not self._last_report:
            return {
                "last_audit": None,
                "score": 0,
                "total_checks": 0,
                "failed": 0
            }

        return {
            "last_audit": self._last_report.timestamp,
            "score": self._last_report.score,
            "total_checks": self._last_report.total_checks,
            "passed": self._last_report.passed,
            "failed": self._last_report.failed,
            "warnings": self._last_report.warnings
        }


# Global instance
advisor = ConfigAdvisor(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = advisor.get_stats()
    return {
        "module": "config-advisor",
        "status": "ok",
        "version": "1.0.0",
        "score": stats.get("score", 0),
        "failed_checks": stats.get("failed", 0)
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get advisor statistics."""
    return advisor.get_stats()


@app.post("/audit", dependencies=[Depends(require_jwt)])
async def run_audit():
    """Run security audit."""
    report = advisor.run_audit()
    return report


@app.get("/report", dependencies=[Depends(require_jwt)])
async def get_report():
    """Get last audit report."""
    if not advisor._last_report:
        raise HTTPException(status_code=404, detail="No audit report available")
    return advisor._last_report


@app.get("/report/summary", dependencies=[Depends(require_jwt)])
async def get_summary():
    """Get audit summary without full results."""
    if not advisor._last_report:
        raise HTTPException(status_code=404, detail="No audit report available")

    report = advisor._last_report
    return {
        "id": report.id,
        "timestamp": report.timestamp,
        "score": report.score,
        "passed": report.passed,
        "failed": report.failed,
        "warnings": report.warnings,
        "critical_issues": [
            r for r in report.results
            if r.status == CheckStatus.FAIL and r.severity == Severity.CRITICAL
        ]
    }


@app.get("/checks/{check_id}", dependencies=[Depends(require_jwt)])
async def get_check(check_id: str):
    """Get specific check result."""
    if not advisor._last_report:
        raise HTTPException(status_code=404, detail="No audit report available")

    for result in advisor._last_report.results:
        if result.check_id == check_id:
            return result

    raise HTTPException(status_code=404, detail="Check not found")


@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_history(limit: int = 10):
    """Get audit history."""
    history = []
    if advisor.history_file.exists():
        lines = advisor.history_file.read_text().strip().split("\n")
        for line in lines[-limit:]:
            try:
                history.append(json.loads(line))
            except Exception:
                continue
    return {"history": list(reversed(history))}


@app.post("/fix/{check_id}", dependencies=[Depends(require_jwt)])
async def apply_fix(check_id: str):
    """Apply automatic fix for a failed check."""
    result = advisor.apply_fix(check_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Fix failed"))
    return result


@app.get("/fixable", dependencies=[Depends(require_jwt)])
async def list_fixable():
    """List checks that have auto-fix available."""
    fixable_checks = ["ANSSI-R28", "ANSSI-R29", "ANSSI-R18", "FS-01", "FS-02", "KERNEL-01"]

    if not advisor._last_report:
        return {"fixable": []}

    failed_fixable = [
        r for r in advisor._last_report.results
        if r.check_id in fixable_checks and r.status == CheckStatus.FAIL
    ]

    return {"fixable": failed_fixable}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Config Advisor started")
