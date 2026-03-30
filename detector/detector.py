import sqlite3
import os
import math

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ids.db")

RISKY_COMMANDS = [
    'nc', 'ncat', 'netcat', 'hydra', 'john', 'hashcat',
    'sqlmap', 'metasploit', 'msfconsole', 'tcpdump',
    'mkfs', 'fdisk', 'useradd', 'userdel', 'usermod',
    'visudo', 'iptables', 'ufw', 'sudo', 'su', 'chmod',
    'chown', 'wget', 'curl', 'scp', 'crontab', 'at',
    'systemctl', 'mount', 'passwd', 'ssh', 'telnet',
    'rm', 'cat', 'grep', 'find', 'python', 'perl',
    'bash', 'sh', 'eval', 'exec', 'base64', 'dd',
]

DANGEROUS_PATTERNS = [
    ('/etc/passwd',   3.0, 'accessing password file'),
    ('/etc/shadow',   5.0, 'accessing shadow password file'),
    ('/etc/sudoers',  5.0, 'accessing sudoers file'),
    ('rm -rf',        4.0, 'recursive force delete'),
    ('| bash',        5.0, 'piping to bash'),
    ('| sh',          5.0, 'piping to shell'),
    ('chmod 777',     4.0, 'world writable permission'),
    ('wget.*|',       4.0, 'download and execute'),
    ('curl.*|',       4.0, 'download and execute'),
    ('base64 -d',     3.0, 'possible obfuscation'),
    ('eval',          4.0, 'code evaluation'),
    ('4444',          3.0, 'common backdoor port'),
    ('0.0.0.0',       2.0, 'binding all interfaces'),
    ('> /etc',        4.0, 'writing to system files'),
    ('chmod 666',     3.0, 'world readable permission'),
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_trained_sequences(user):
    """Get all trained sequences and their frequencies."""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT sequence, frequency FROM user_sequences WHERE user=?",
        (user,)
    )
    rows = cur.fetchall()
    conn.close()
    return {r['sequence']: r['frequency'] for r in rows}


def build_tfidf_profile(trained_sequences):
    """
    Build TF-IDF profile from trained sequences.

    TF  = frequency of sequence / total sequences
    IDF = log(total / sequences containing this term)
    """
    total = sum(trained_sequences.values())
    if total == 0:
        return {}

    tfidf = {}
    for seq, freq in trained_sequences.items():
        tf          = freq / total
        idf         = math.log((total + 1) / (freq + 1)) + 1
        tfidf[seq]  = tf * idf

    return tfidf


def cosine_similarity(vec1, vec2):
    """
    Calculate cosine similarity between two vectors.
    Returns value between 0 and 1.
    1 = identical behavior
    0 = completely different behavior
    """
    # get all keys
    all_keys = set(vec1.keys()) | set(vec2.keys())

    dot_product = sum(vec1.get(k, 0) * vec2.get(k, 0) for k in all_keys)
    mag1        = math.sqrt(sum(v**2 for v in vec1.values()))
    mag2        = math.sqrt(sum(v**2 for v in vec2.values()))

    if mag1 == 0 or mag2 == 0:
        return 0.0

    return dot_product / (mag1 * mag2)


def get_pattern_score(sequence):
    """Check for dangerous patterns in sequence."""
    score   = 0.0
    reasons = []
    seq_lower = sequence.lower()

    for pattern, pscore, pdesc in DANGEROUS_PATTERNS:
        if pattern.lower() in seq_lower:
            score += pscore
            reasons.append(pdesc)

    return score, reasons


def get_risky_cmds(sequence):
    """Extract risky commands from sequence."""
    return [r for r in RISKY_COMMANDS if r in sequence.lower()]


def detect(user, new_sequences):
    """
    Detect intrusion using TF-IDF + Cosine Similarity.

    How it works:
    1. Build TF-IDF profile of trained (normal) behavior
    2. Build TF-IDF vector of new sequences
    3. Calculate cosine similarity between them
    4. Low similarity = unusual behavior = potential intrusion
    5. Also check dangerous patterns for extra scoring
    """
    trained = get_trained_sequences(user)

    if not trained:
        return [], f"No profile found for '{user}'. Please train first."

    if not new_sequences:
        return [], None

    # build TF-IDF profile of normal behavior
    normal_tfidf = build_tfidf_profile(trained)

    # build frequency dict of new sequences
    new_freq = {}
    for seq in new_sequences:
        new_freq[seq] = new_freq.get(seq, 0) + 1

    # build TF-IDF of new sequences
    new_tfidf = build_tfidf_profile(new_freq)

    # calculate overall similarity score
    similarity = cosine_similarity(normal_tfidf, new_tfidf)

    # anomaly score = how different from normal
    # 0 = identical to normal (no anomaly)
    # 1 = completely different from normal (high anomaly)
    overall_anomaly = 1.0 - similarity

    alerts = []

    for seq in new_sequences:
        seq_anomaly = 0.0
        reasons     = []

        # Factor 1: Is this sequence in trained profile?
        if seq not in trained:
            seq_anomaly += 3.0
            reasons.append("sequence never seen in normal behavior")
        else:
            # sequence is known — check how rare it is
            freq_ratio = trained[seq] / sum(trained.values())
            if freq_ratio < 0.01:
                seq_anomaly += 1.5
                reasons.append("very rare sequence in normal behavior")

        # Factor 2: Overall behavior similarity
        if overall_anomaly > 0.7:
            seq_anomaly += 2.0
            reasons.append(f"behavior pattern {overall_anomaly*100:.0f}% different from normal")
        elif overall_anomaly > 0.4:
            seq_anomaly += 1.0
            reasons.append(f"behavior pattern {overall_anomaly*100:.0f}% different from normal")

        # Factor 3: Dangerous patterns
        pattern_score, pattern_reasons = get_pattern_score(seq)
        seq_anomaly += pattern_score
        reasons.extend(pattern_reasons)

        # cap at 10
        seq_anomaly = min(seq_anomaly, 10.0)

        # only alert if anomaly score is significant
        if seq_anomaly >= 6.0 and reasons:
            risky = get_risky_cmds(seq)
            alerts.append({
                'sequence':   seq,
                'reason':     ' | '.join(reasons),
                'risk_score': round(seq_anomaly, 2),
                'risky':      risky,
            })

    return alerts, None