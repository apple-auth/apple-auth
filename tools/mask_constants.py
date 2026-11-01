"""Mask/unmask comma-separated C++ integer literals read from stdin.

Apply twice with the same seed and element width to restore the original values.
Only masked literals belong in source files; decoding happens at runtime.
Aggregate braces are preserved. Use --matrix for mixed-width MatrixCodec tables.
Example: python tools/mask_constants.py --seed 0x12345678 --bits 16 < values.txt
"""

import argparse
import re
import sys


def literal_value(value):
    value = value.rstrip("uUlL")
    base = 16 if value.lower().startswith("0x") else 8 if len(value) > 1 and value[0] == "0" else 10
    return int(value, base)


def width(index, bits, matrix=False):
    field = index % 89
    return 32 if matrix and field >= 9 and (field - 9) % 10 == 0 else bits


def mask(values, seed, bits, matrix=False):
    for index, value in enumerate(values):
        size = width(index, bits, matrix)
        limit = (1 << size) - 1
        if not 0 <= value <= limit:
            raise ValueError(f"Value {value} does not fit in {size} bits")
        seed ^= (seed << 13) & 0xFFFFFFFF
        seed ^= seed >> 17
        seed ^= (seed << 5) & 0xFFFFFFFF
        yield value ^ (seed & limit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--bits", type=int, choices=(8, 16, 32), default=8)
    parser.add_argument("--matrix", action="store_true", help="MatrixCodec aggregate layout")
    args = parser.parse_args()
    if not 0 < args.seed <= 0xFFFFFFFF:
        parser.error("seed must be a nonzero 32-bit unsigned integer")
    source = sys.stdin.read()
    literal = r"(?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*"
    if re.sub(literal + r"|[\s,{}]", "", source):
        parser.error("input must contain only integer literals, commas and braces")
    try:
        values = [literal_value(value) for value in re.findall(literal, source)]
        if args.matrix and (args.bits != 8 or len(values) % 89):
            parser.error("--matrix requires byte elements and complete 89-field MatrixCodec records")
        encoded = list(mask(values, args.seed, args.bits, args.matrix))
    except ValueError as error:
        parser.error(str(error))
    columns = 16 if args.bits == 8 else 8
    tokens = []
    for index, value in enumerate(encoded):
        size = width(index, args.bits, args.matrix)
        suffix = "U" if size == 32 else ""
        tokens.append(f"0x{value:0{size // 4}X}{suffix}")
    if "{" in source:
        replacements = iter(tokens)
        print(re.sub(literal, lambda _: next(replacements), source).rstrip())
        return
    for start in range(0, len(encoded), columns):
        print(", ".join(tokens[start:start + columns]) + ",")


if __name__ == "__main__":
    main()
