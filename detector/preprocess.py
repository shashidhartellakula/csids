import re

# Commands and their risk weights — used later for scoring
RISKY_COMMANDS = {
    "sudo": 3, "su": 3, "passwd": 3,
    "chmod": 2, "chown": 2,
    "wget": 2, "curl": 2, "scp": 2,
    "nc": 3, "netcat": 3, "nmap": 3,
    "dd": 2, "shred": 2,
    "crontab": 2, "useradd": 3,
    "userdel": 3, "usermod": 2,
    "ssh": 1, "ssh-keygen": 2,
    "base64": 2, "eval": 3,
    "python": 1, "python3": 1,
    "perl": 1, "bash": 1, "sh": 1,
    "rm": 2, "kill": 2, "pkill": 2,
    "systemctl": 2, "iptables": 3,
}

# Sensitive paths — preserve these, don't erase them
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/hosts", "/etc/crontab",
    "/root/", "/proc/", "/sys/",
    ".ssh/", ".bashrc", ".bash_profile",
    "/var/log/", "/tmp/", "/dev/",
]

def clean_commands(raw_lines):
    cleaned = []
    for line in raw_lines:
        line = line.strip()

        # skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # skip bash timestamp lines like #1234567890
        if re.match(r"^#\d+$", line):
            continue

        cmd = line.lower()

        # normalize large numbers only (keep small ones like port 22)
        cmd = re.sub(r"\b\d{5,}\b", "NUM", cmd)

        # tag sensitive paths BEFORE replacing anything
        # this preserves them as meaningful features
        for sp in SENSITIVE_PATHS:
            if sp in cmd:
                cmd = cmd.replace(sp, f"SENSITIVE_{sp.strip('/').replace('/', '_').upper()}")

        # ✅ FIXED — only replace non-sensitive generic paths
        # old code replaced ALL paths including /etc/passwd
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
