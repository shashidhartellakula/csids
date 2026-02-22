import re

def clean_commands(commands):
    cleaned = []
    for cmd in commands:
        cmd = cmd.strip().lower()
        if not cmd:
            continue
        cmd = re.sub(r'\d+', 'NUM', cmd)
        cmd = re.sub(r'/\S+', 'PATH', cmd)
        cleaned.append(cmd)
    return cleaned
