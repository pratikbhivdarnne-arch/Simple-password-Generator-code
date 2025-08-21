# Simple-password-Ge# password_generator.py
import argparse
import secrets
import string
from itertools import repeat

AMBIGUOUS = "Il1O0|`'\";:,.<>[](){}"
DEFAULT_SYMBOLS = "!@#$%^&*_-+=?/\\"

def build_pool(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous):
    pool = ""
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = DEFAULT_SYMBOLS

    if avoid_ambiguous:
        rm = set(AMBIGUOUS)
        lowers = "".join(c for c in lowers if c not in rm)
        uppers = "".join(c for c in uppers if c not in rm)
        digits = "".join(c for c in digits if c not in rm)

    if use_lower:  pool += lowers
    if use_upper:  pool += uppers
    if use_digits: pool += digits
    if use_symbols: pool += symbols

    groups = []
    if use_lower:  groups.append(lowers)
    if use_upper:  groups.append(uppers)
    if use_digits: groups.append(digits)
    if use_symbols: groups.append(symbols)

    return pool, groups

def generate_password(length=16, use_lower=True, use_upper=True,
                      use_digits=True, use_symbols=True, avoid_ambiguous=True):
    pool, groups = build_pool(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous)
    if not pool:
        raise ValueError("Character pool is empty. Enable at least one character set.")
    if length < len(groups):
        raise ValueError(f"Length must be at least {len(groups)} to include all selected sets.")

    # Guarantee at least one from each selected group
    pwd_chars = [secrets.choice(g) for g in groups]
    # Fill the rest from the full pool
    pwd_chars += [secrets.choice(pool) for _ in range(length - len(pwd_chars))]

    # Fisher–Yates shuffle with cryptographic randomness
    for i in range(len(pwd_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd_chars[i], pwd_chars[j] = pwd_chars[j], pwd_chars[i]

    return "".join(pwd_chars)

def main():
    p = argparse.ArgumentParser(description="Secure password generator")
    p.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")
    p.add_argument("-n", "--number", type=int, default=1, help="How many passwords (default: 1)")
    p.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    p.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    p.add_argument("--no-digits", action="store_true", help="Exclude digits")
    p.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    p.add_argument("--allow-ambiguous", action="store_true", help="Allow ambiguous characters (Il1O0| etc.)")
    args = p.parse_args()

    for _ in repeat(None, args.number):
        print(generate_password(
            length=args.length,
            use_lower=not args.no_lower,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            avoid_ambiguous=not args.allow_ambiguous
        ))

if __name__ == "__main__":
    main()
    #How to use........ # 1 password, length 16 (default)
python password_generator.py

# 5 passwords, length 20
python password_generator.py -n 5 -l 20

# Only letters + digits, allow ambiguous characters
python password_generator.py --no-symbols --allow-ambiguous

# Symbols only (not recommended, just an example)
python password_generator.py --no-lower --no-upper --no-digits -l 24
from password_generator import generate_password
print(generate_password(length=12))
