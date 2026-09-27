"""
hash_cracker.py
A dictionary-based hash cracker for CTF challenges and lab exercises.

Given a target hash and a wordlist, this tries each candidate password,
hashes it with the chosen algorithm, and checks for a match.

Usage:
    python hash_cracker.py <hash> <wordlist_path> [--algo sha256]

Supported algorithms: md5, sha1, sha256, sha512
Intended for use against hashes YOU created or were given for a CTF/lab
exercise, not for attacking accounts or systems without authorization.
"""

import argparse
import hashlib
import sys

SUPPORTED_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def hash_candidate(candidate: str, algo: str) -> str:
    hasher = SUPPORTED_ALGOS[algo]()
    hasher.update(candidate.encode("utf-8"))
    return hasher.hexdigest()


def crack(target_hash: str, wordlist_path: str, algo: str):
    target_hash = target_hash.strip().lower()

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                candidate = line.strip("\n\r")
                if not candidate:
                    continue
                if hash_candidate(candidate, algo) == target_hash:
                    return candidate, line_num
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)

    return None, None


def main():
    parser = argparse.ArgumentParser(description="Dictionary-based hash cracker for CTF/lab use")
    parser.add_argument("hash", help="Target hash to crack")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--algo", choices=SUPPORTED_ALGOS.keys(), default="sha256",
                         help="Hash algorithm (default: sha256)")
    args = parser.parse_args()

    print(f"[*] Attempting to crack {args.algo.upper()} hash using {args.wordlist}")
    result, line_num = crack(args.hash, args.wordlist, args.algo)

    if result:
        print(f"[+] Match found on line {line_num}: {result}")
    else:
        print("[*] No match found in wordlist.")


if __name__ == "__main__":
    main()
