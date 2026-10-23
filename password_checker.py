#!/usr/bin/env python3
"""
Password Strength Checker - CLI version

Features:
- Entropy-based scoring (Shannon entropy estimate using charset size)
- Checks: length, lowercase, uppercase, digits, symbols
- Dictionary check against common_passwords.txt (and substrings)
- Detects repeats, sequences (like 'abcd', '1234'), keyboard adjacency (simple)
- Estimates time-to-crack under guesses/sec (offline brute force or online rate)
- Outputs human-friendly score and suggestions

Usage:
    python password_checker.py --password "YourPass123!"
    python password_checker.py     (interactive prompt)
"""

import math, argparse, os, sys, re

BASE_DIR = os.path.dirname(__file__)
COMMON_PATH = os.path.join(BASE_DIR, "common_passwords.txt")

# Load common passwords into a set (lowercase)
try:
    with open(COMMON_PATH, "r", encoding="utf-8") as f:
        COMMON = set(line.strip().lower() for line in f if line.strip())
except Exception:
    COMMON = set()

# Basic keyboard sequences (rows) for detection
KEY_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

def charset_size(password):
    s = set(password)
    size = 0
    if any(c.islower() for c in s): size += 26
    if any(c.isupper() for c in s): size += 26
    if any(c.isdigit() for c in s): size += 10
    # Count other printable symbols roughly
    if any(not c.isalnum() for c in s): size += 32
    return size

def shannon_entropy(password):
    if len(password) == 0: return 0.0
    size = charset_size(password)
    if size <= 1:
        return 0.0
    return len(password) * math.log2(size)

def detect_sequences(pw):
    pw_lower = pw.lower()
    seq_count = 0
    seq_positions = []
    for i in range(len(pw_lower)-2):
        a,b,c = pw_lower[i:i+3]
        if ord(b)==ord(a)+1 and ord(c)==ord(b)+1:
            seq_count += 1
            seq_positions.append((i,i+3))
    for row in KEY_ROWS:
        for i in range(len(row)-2):
            pattern = row[i:i+3]
            if pattern in pw_lower:
                seq_count += 1
    return seq_count, seq_positions

def detect_repeated_chars(pw):
    repeats = 0
    max_run = 1
    cur = 1
    for i in range(1,len(pw)):
        if pw[i]==pw[i-1]:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 1
    repeats = max_run
    return repeats

def dictionary_check(pw):
    low = pw.lower()
    if low in COMMON:
        return True, "exact_common_password"
    for i in range(len(low)-3):
        if low[i:i+4] in COMMON:
            return True, "common_substring"
    return False, None

def score_password(pw):
    length = len(pw)
    ent = shannon_entropy(pw)
    seq_count, seq_positions = detect_sequences(pw)
    repeats = detect_repeated_chars(pw)
    dict_flag, dict_type = dictionary_check(pw)

    base = max(0, min(60, (ent / 60.0) * 60))

    if length < 6:
        base -= 15
    elif length < 8:
        base -= 5
    elif length >= 12:
        base += 5

    variety = 0
    if any(c.islower() for c in pw): variety += 1
    if any(c.isupper() for c in pw): variety += 1
    if any(c.isdigit() for c in pw): variety += 1
    if any(not c.isalnum() for c in pw): variety += 1
    base += variety * 3

    base -= seq_count * 6

    if repeats >= 3:
        base -= (repeats - 2) * 3

    if dict_flag:
        base -= 40

    score = max(0, min(100, round(base)))

    suggestions = []
    if length < 8:
        suggestions.append("Use at least 8 characters (12+ recommended).")
    if variety < 3:
        suggestions.append("Include uppercase, lowercase, digits, and symbols.")
    if seq_count > 0:
        suggestions.append("Avoid sequential patterns like 'abcd' or '1234'.")
    if repeats >= 3:
        suggestions.append("Avoid repeated characters like 'aaa' or '111'.")
    if dict_flag:
        suggestions.append("Avoid common passwords or words. Use unrelated words or passphrases.")

    guesses_space = 2**ent if ent>0 else 1
    tt_offline = guesses_space / 1e10
    tt_online = guesses_space / 1e3
    def human_readable(seconds):
        if seconds < 60: return f"{int(seconds)} seconds"
        minutes = seconds/60
        if minutes < 60: return f"{int(minutes)} minutes"
        hours = minutes/60
        if hours < 24: return f"{int(hours)} hours"
        days = hours/24
        if days < 365: return f"{int(days)} days"
        years = days/365
        if years < 1000: return f"{int(years)} years"
        return f"{years:.2e} years"

    return {
        "password": pw,
        "length": length,
        "entropy_bits": round(ent,2),
        "score": score,
        "suggestions": suggestions,
        "tt_offline": human_readable(tt_offline),
        "tt_online": human_readable(tt_online),
        "seq_count": seq_count,
        "repeats": repeats,
        "dict_flag": dict_flag,
        "dict_type": dict_type
    }

def print_report(res):
    print("Password:", res['password'])
    print("Length:", res['length'], "Entropy (bits):", res['entropy_bits'])
    print("Score (0-100):", res['score'])
    print("Estimated time to crack (offline):", res['tt_offline'])
    print("Estimated time to crack (online):", res['tt_online'])
    if res['suggestions']:
        print("\nSuggestions:")
        for s in res['suggestions']:
            print(" -", s)
    if res['dict_flag']:
        print("\\nWarning: Password matches or contains a common password pattern (type:", res['dict_type'], ")")

def main():
    ap = argparse.ArgumentParser(description="Password Strength Checker")
    ap.add_argument("--password", "-p", type=str, help="Password to check")
    args = ap.parse_args()
    if args.password:
        pw = args.password.strip()
    else:
        pw = input("Enter password to analyze: ").strip()
    res = score_password(pw)
    print_report(res)

if __name__ == "__main__":
    main()
