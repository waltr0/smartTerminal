from __future__ import annotations

from cybershell.models import RiskFinding


def safe_alternatives(command: str, findings: list[RiskFinding]) -> list[str]:
    categories = {finding.category for finding in findings}
    suggestions: list[str] = []

    if "destructive_filesystem" in categories:
        suggestions.extend(
            [
                "ls -la <target>",
                "find <target> -maxdepth 1 -print",
                "trash-put <target>  # if trash-cli is installed",
            ]
        )
    if "disk_destruction" in categories:
        suggestions.extend(["lsblk -f", "sudo fdisk -l", "mount | column -t"])
    if "privilege_escalation" in categories:
        suggestions.extend(["sudo -l", "id", "groups"])
    if "secrets_access" in categories:
        suggestions.extend(
            [
                "ls -l <secret-file>",
                "stat <secret-file>",
                "grep -R \"REDACTED\" <path>  # avoid printing secrets",
            ]
        )
    if "network_exfiltration" in categories:
        suggestions.extend(
            [
                "ss -tulpn",
                "ip route",
                "sudo tcpdump -i any -c 25 -nn",
            ]
        )
    if "firewall_tampering" in categories:
        suggestions.extend(["sudo iptables -S", "sudo ufw status verbose"])
    if "persistence" in categories:
        suggestions.extend(
            [
                "crontab -l",
                "systemctl list-timers --all",
                "systemctl list-unit-files --type=service",
            ]
        )
    if "container_escape_risk" in categories:
        suggestions.extend(["docker ps --format 'table {{.ID}}\\t{{.Image}}\\t{{.Status}}'", "docker inspect <container>"])
    if not suggestions:
        suggestions.append("Run a read-only inspection command before making changes.")

    seen: set[str] = set()
    unique: list[str] = []
    for item in suggestions:
        if item not in seen and item.lower() != command.lower():
            seen.add(item)
            unique.append(item)
    return unique[:5]

