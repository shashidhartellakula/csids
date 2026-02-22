def build_sequences(commands, window=3):
    """
    Build sliding window sequences from a list of cleaned commands.

    Example with window=3:
        ['ls', 'pwd', 'whoami', 'cd'] 
        → ['ls | pwd | whoami', 'pwd | whoami | cd']

    ✅ FIXED — handles histories shorter than the window size
    """
    if not commands:
        return []

    # ✅ if fewer commands than window, return what we have as one sequence
    if len(commands) < window:
        return [" | ".join(commands)]

    sequences = []
    for i in range(len(commands) - window + 1):
        seq = " | ".join(commands[i:i + window])
        sequences.append(seq)
    return sequences


def build_bigrams(commands):
    """Build 2-command pairs — useful for fine-grained analysis."""
    return build_sequences(commands, window=2)