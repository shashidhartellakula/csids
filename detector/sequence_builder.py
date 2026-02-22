def build_sequences(commands, window=3):
    sequences = []
    for i in range(len(commands) - window + 1):
        sequences.append(" | ".join(commands[i:i+window]))
    return sequences
