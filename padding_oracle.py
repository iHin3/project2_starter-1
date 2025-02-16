#!/usr/bin/python3

import json
import sys
import time
from typing import List, Dict
import requests

# Use session to speed up requests
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    """ Sends ciphertext to the oracle and checks padding validity. """
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e) + "\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError:
            sys.stderr.write("Possible server overload or incorrect URL. Retrying in 10 seconds...\n")
            time.sleep(10)
            continue


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)

    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)
        sys.exit(-1)

    #
    # Padding Oracle Attack
    #

    message = bytearray(message)  # Convert to mutable type
    block_size = 16
    num_blocks = len(message) // block_size

    plaintext = bytearray(len(message))  # Store decrypted bytes

    for block_num in range(num_blocks - 1, 0, -1):  # Start from last block, move backwards
        cipher_text_block = message[(block_num - 1) * block_size:block_num * block_size]
        target_block = message[block_num * block_size:(block_num + 1) * block_size]

        intermediate = bytearray(block_size)  # Store intermediate state

        for i in range(1, block_size + 1):  # Decrypt from last byte to first
            for guess in range(256):  # Try all possible values
                altered_block = bytearray(cipher_text_block)  # Copy original block
                altered_block[-i] ^= guess ^ i  # Modify byte

                if oracle(oracle_url, [altered_block + target_block])[0]["status"] == "valid":
                    intermediate[-i] = guess ^ i
                    plaintext[(block_num - 1) * block_size + (block_size - i)] = intermediate[-i] ^ cipher_text_block[-i]
                    break

    decrypted_text = plaintext.rstrip(plaintext[-1:]).decode(errors="ignore")
    print(decrypted_text)


if __name__ == '__main__':
    main()

