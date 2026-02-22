import re

RISKY_COMMANDS = {
    # privilege escalation
    "sudo": 3, "su": 3, "passwd": 3, "pkexec": 3,
    # file permissions
    "chmod": 2, "chown": 2, "chattr": 2,
    # network tools
    "wget": 2, "curl": 2, "scp": 2,
    "nc": 3, "netcat": 3, "nmap": 3,
    "tcpdump": 3, "wireshark": 2,
    # user management
    "useradd": 3, "userdel": 3, "usermod": 2,
    "groupadd": 2, "groupdel": 2,
    # destructive commands
    "dd": 2, "shred": 2, "mkfs": 3,
    "rm": 2, "kill": 2, "pkill": 2,
    # persistence / scheduling
    "crontab": 2, "at": 1, "systemctl": 2,
    # remote access
    "ssh": 1, "ssh-keygen": 2, "ssh-copy-id": 2,
    # scripting / execution
    "python": 1, "python3": 1, "perl": 1,
    "ruby": 1, "bash": 1, "sh": 1,
    "eval": 3, "exec": 2, "base64": 2,
    # firewall
    "iptables": 3, "ufw": 2,
    # recon
    "ps": 1, "top": 1, "who": 1,
    "netstat": 2, "ss": 1, "lsof": 2,
    # file reading
    "cat": 1, "less": 1, "more": 1,
    "head": 1, "tail": 1,
    # editors (used to modify system files)
    "nano": 1, "vim": 1, "vi": 1,
}

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/hosts", "/etc/crontab", "/etc/ssh",
    "/root/", "/proc/", "/sys/",
    ".ssh/", ".bashrc", ".bash_profile", ".bash_history",
    "/var/log/", "/tmp/", "/dev/",
    "/boot/", "/etc/init.d/",
]


def clean_commands(raw_lines):
    cleaned = []
    for line in raw_lines:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # skip bash timestamp lines
        if re.match(r"^#\d+$", line):
            continue

        cmd = line.lower()

        # normalize large numbers only
        cmd = re.sub(r"\b\d{5,}\b", "NUM", cmd)

        # ✅ tag sensitive paths BEFORE replacing anything
        for sp in SENSITIVE_PATHS:
            if sp in cmd:
                tag = "SENSITIVE_" + sp.strip("/").replace("/", "_").replace(".", "_").upper()
                cmd = cmd.replace(sp, tag)

        # replace remaining generic paths
        cmd = re.sub(r"/(?:[a-zA-Z0-9_\-\.]+/)+[a-zA-Z0-9_\-\.]*", "PATH", cmd)

        # normalize IPs
        cmd = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP_ADDR", cmd)

        cleaned.append(cmd)
    return cleaned


def get_risky_commands_in(text):
    """Return list of risky commands found in a sequence string."""
    found = []
    for cmd in RISKY_COMMANDS:
        if re.search(r"\b" + re.escape(cmd) + r"\b", text):
            found.append(cmd)
    return found


def get_risk_score(sequence):
    """
    Calculate risk score 0.0 - 10.0 for a sequence string.
    Higher = more suspicious.
    """
    import re as _re
    score = 0
    parts = sequence.split(" | ")

    for part in parts:
        base_cmd = part.split()[0] if part.split() else ""

        # command weight
        score += RISKY_COMMANDS.get(base_cmd, 0)

        # sensitive path access
        if "SENSITIVE_" in part:
            score += 3

        # piped commands (chaining is suspicious)
        if "|" in part:
            score += 1

        # output redirected somewhere sensitive
        if _re.search(r">\s*SENSITIVE_", part):
            score += 2

        # encoded payloads
        if "base64" in part or "xxd" in part:
            score += 2

        # background execution
        if part.strip().endswith("&"):
            score += 1

        # downloading and executing
        if base_cmd in ("wget", "curl") and ("|" in part or "bash" in part):
            score += 3

    max_possible = len(parts) * 9
    if max_possible == 0:
        return 0.0
    return round(min((score / max_possible) * 10, 10.0), 2)