#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "http://cpsc4200.mpese.com/username/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Union, Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """ XOR two byte sequences """
    return bytes(x ^ y for x, y in zip(a, b))



def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)

    #
    # TODO: Decrypt the message
    #

    altered_message = message.copy()
    plaintext = message.copy()
    # eventually add a loop here to decrypt all blocks
    block_size = 16
    padding = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
    
    # change variables and numbers to account for new loop
    for block_num in range(1, block_size):     # loop through all blocks
        # get the second to last 16 byte block
        cipher_text_block = message[-(2 * block_size):-block_size]
        current_byte = cipher_text_block[-1]        # change 1 to the loop variable later
        current_byte_index = message[-block_size - 1]

        # check different values in 256 bit range until correct one is found
        for i in range(256):
            altered_message[current_byte_index] = i
            response = oracle(oracle_url, altered_message)
            if response == "invalid_mac":       # if mac error, padding is correct so break
                break
            else
                continue

        int_state = altered_message[current_byte_index] ^ padding[block_num + 1]   
        plaintext_byte = message[current_byte_index] ^ int_state
        plaintext[current_byte_index] = plaintext_byte

    decrypted = "TODO"
    print(decrypted)


if __name__ == '__main__':
    main()

