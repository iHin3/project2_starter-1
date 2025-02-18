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

    message = bytearray(message) 
    block_size = 16
    num_blocks = len(message) // block_size

    #Begin with storing decrypted bytes then in loop start from last block

    plaintext = bytearray(len(message)) 

    for block_num in range(num_blocks - 1, 0, -1): 
        cipher_text_block = message[(block_num - 1) * block_size:block_num * block_size]
        target_block = message[block_num * block_size:(block_num + 1) * block_size]

        intermediate = bytearray(block_size) 
        
        #Helps with decrypting bytes from last to first then begin modifying the byte

        for i in range(1, block_size + 1): 
            for guess in range(256): 
                altered_block = bytearray(cipher_text_block)
                altered_block[-i] ^= guess ^ i 

                if oracle(oracle_url, [altered_block + target_block])[0]["status"] == "valid":
                    intermediate[-i] = guess ^ i
                    plaintext[(block_num - 1) * block_size + (block_size - i)] = intermediate[-i] ^ cipher_text_block[-i]
                    break
    
    # Changed original a bit to help remove padding and decode into a readable string
    decrypted = plaintext.rstrip(plaintext[-1:]).decode(errors="ignore")
    print(decrypted)


if __name__ == '__main__':
    main()

