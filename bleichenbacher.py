#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "coach+username+100.00"
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import sys


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    #
    # TODO: Forge a signature
    #

    # get the message hash
    message_digest = hashlib.sha256(message.encode()).digest()

    # use the ASN.1 bytes
    asn1_bytes = bytes.fromhex("3031300d060960864801650304020105000420")

    # necessary front padding
    padding = b'\x00\x01\xff\x00'

    # create 201 arbitrary bytes to add at the end
    arbitrary_bytes = b'\x00' * 201

    forged_signature_value = padding + asn1_bytes + message_digest + arbitrary_bytes

    # turn the bytes into a big integer
    forged_int = int.from_bytes(forged_signature_value, byteorder='big')

    # find the cube root
    forced_sig_cube, is_exact = integer_nthroot(forged_int, 3)
    # if the cube root is not exact, round to next whole number
    if not is_exact:
        forced_sig_cube += 1

    forged_signature = forced_sig_cube
    print(bytes_to_base64(integer_to_bytes(forged_signature, 256)))


if __name__ == '__main__':
    main()

