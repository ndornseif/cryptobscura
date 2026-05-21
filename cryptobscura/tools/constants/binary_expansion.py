#!/usr/bin/env python3
import sys
from math import ceil
from pathlib import Path

here = Path(__file__).parent

pi_file = here / "pi.txt"
e_file = here / "e.txt"
sqrt2_file = here / "sqrt2.txt"

file_ids = {
    "pi": pi_file,
    "e": e_file,
    "sqrt2": sqrt2_file,
}


def read_file_decimal_digits(filepath: Path, n_chars: int) -> str:
    with filepath.open() as fd:
        while True:
            ch = fd.read(1)
            if not ch:
                return ""  # Did not find decimal point
            if ch == ".":
                break
        return fd.read(n_chars)


def generate_bytes_from_constant(filepath: Path, bytes_req: int) -> list[int]:
    bits_req = bytes_req * 8
    # Note that log2(10) approx 3.322
    # We round down to 3.32.
    dec_digits_req = ceil(bits_req / 3.32)

    digit_str = read_file_decimal_digits(filepath, dec_digits_req)
    shifted = (int(digit_str) << bits_req) // (10**dec_digits_req)
    binary_expansion = f"{shifted:b}".zfill(bits_req)

    assert len(binary_expansion) == bits_req
    bit_chunks = [binary_expansion[i : i + 8] for i in range(0, bits_req, 8)]
    return [int(x, base=2) for x in bit_chunks]


def format_bytes_list(intl: list[int]) -> str:
    formated_list = []
    for si in intl:
        assert si < 256
        formated_list.append(f"0x{si:02x}")

    return str(formated_list).replace("'", "")


def main() -> int:
    this_file = Path(__file__).name
    helpstr = f"./{this_file} (pi | e | sqrt2) <num_bytes>"

    if len(sys.argv) != 3:
        print("Incorrect number of arguments.")
        print(f"Usage: {helpstr}")
        return 1

    if sys.argv[1].lower() not in file_ids:
        print("Invalid constant specified.")
        print(f"Usage: {helpstr}")
        return 1
    file_path = file_ids[sys.argv[1].lower()]

    try:
        num_bytes = int(sys.argv[2])
    except ValueError:
        print("Invalid number of bytes specified.")
        print(f"Usage: {helpstr}")
        return 1

    if num_bytes < 1:
        print("Invalid number of bytes specified.")
        print(f"Usage: {helpstr}")
        return 1

    print(format_bytes_list(generate_bytes_from_constant(file_path, num_bytes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
